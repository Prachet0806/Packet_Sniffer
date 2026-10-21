"""Run only against an explicitly supplied disposable test database."""
import json,os,pathlib,subprocess,sys,tempfile,re,shutil,uuid
# Preserve psql's invoked basename. Debian/Ubuntu's /usr/bin/psql is a symlink to
# pg_wrapper, which dispatches on argv[0]; resolving it makes SQL calls no-ops.
sniffer,stress=map(lambda p:str(pathlib.Path(p).resolve()),sys.argv[1:3])
psql=os.path.abspath(sys.argv[3]);conninfo=sys.argv[4]
root=pathlib.Path(sys.argv[5]).resolve();env={k:v for k,v in os.environ.items() if not k.startswith(('SNIFFER_','STATS_','AWS_RDS_')) and k not in ('DATABASE_URL','POSTGRES_CONNINFO','PGHOST','PGPASSWORD')}
checks=0
run_id=uuid.uuid4().hex[:12]
sensor='integration-'+run_id
with tempfile.TemporaryDirectory(prefix='sniffer-pg-') as tmp:
    tmp=pathlib.Path(tmp)
    def sql(query):
        p=subprocess.run([psql,'-X','-v','ON_ERROR_STOP=1','-At','-d',conninfo,'-c',query.replace('integration-current',sensor)],capture_output=True,text=True,timeout=10)
        assert p.returncode==0,p.stderr
        return p.stdout.strip()
    # This database is disposable; validate that the legacy schema remains intact.
    sql("CREATE TABLE IF NOT EXISTS protocol_stats(id SERIAL PRIMARY KEY,timestamp TIMESTAMP,total_packets BIGINT); INSERT INTO protocol_stats(timestamp,total_packets) VALUES(NOW(),987);")
    def run(args,d,more=None):
        e=env.copy();e.update(DATABASE_URL=conninfo,PACKET_TEST_CONNINFO=conninfo,SNIFFER_STATE_DIR=str(d),SNIFFER_SENSOR_ID=sensor,STATS_FLUSH_MS='1000');e.update(more or {})
        p=subprocess.run(args,cwd=d,env=e,capture_output=True,text=True,timeout=25)
        assert p.returncode==0,(p.stdout,p.stderr);return p
    def expect_total(expected,d):
        observed=sql("SELECT SUM(total_packets) FROM protocol_stats_v2 WHERE sensor_id='integration-current'")
        if observed!=str(expected):
            rows=sql("SELECT event_id,total_packets,session_id FROM protocol_stats_v2 WHERE sensor_id='integration-current' ORDER BY interval_start")
            snapshot=(d/'stats.json').read_text() if (d/'stats.json').exists() else '<missing>'
            raise AssertionError(f'expected {expected} packets for {sensor}, got {observed!r}; rows={rows!r}; state={snapshot}')
    d=tmp/'replay';d.mkdir();run([sniffer,'--no-env','--quiet','--db-required','--read',str(root/'tests/pcaps/eth-tcp-http.pcap')],d)
    expect_total(1,d)
    assert sql('SELECT total_packets FROM protocol_stats ORDER BY id DESC LIMIT 1')=='987';checks+=2
    # Pre-migrated applications need no DDL privileges. Reject incomplete v2 schemas at startup.
    role='sniffer_test_'+run_id;schema='sniffer_broken_'+run_id
    sql(f'CREATE ROLE {role}; GRANT USAGE ON SCHEMA public TO {role}; GRANT SELECT ON sniffer_schema,protocol_stats_v2,alerts_v2 TO {role}; GRANT INSERT ON protocol_stats_v2,alerts_v2 TO {role};')
    try:
        d=tmp/'restricted';d.mkdir()
        run([sniffer,'--no-env','--quiet','--db-required','--read',str(root/'tests/pcaps/empty.pcap')],d,{'DATABASE_URL':conninfo+f" options='-c role={role}'"});checks+=1
    finally:
        sql(f'DROP OWNED BY {role}; DROP ROLE {role};')
    sql(f'CREATE SCHEMA {schema}; CREATE TABLE {schema}.protocol_stats_v2 (LIKE public.protocol_stats_v2 INCLUDING ALL); ALTER TABLE {schema}.protocol_stats_v2 DROP COLUMN dhcp_bytes; CREATE TABLE {schema}.alerts_v2 (LIKE public.alerts_v2 INCLUDING ALL); CREATE TABLE {schema}.sniffer_schema (LIKE public.sniffer_schema INCLUDING ALL); INSERT INTO {schema}.sniffer_schema(version) VALUES(2);')
    try:
        d=tmp/'broken-schema';d.mkdir();e=env.copy();e.update(SNIFFER_STATE_DIR=str(d),SNIFFER_SENSOR_ID=sensor,DATABASE_URL=conninfo+f" options='-c search_path={schema}'")
        p=subprocess.run([sniffer,'--no-env','--quiet','--db-required','--read',str(root/'tests/pcaps/empty.pcap')],cwd=d,env=e,capture_output=True,text=True,timeout=15)
        assert p.returncode!=0,(p.stdout,p.stderr);checks+=1
    finally:
        sql(f'DROP SCHEMA {schema} CASCADE;')
    sql("CREATE OR REPLACE FUNCTION slow_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.15); RETURN NEW; END $$; DROP TRIGGER IF EXISTS delay_insert ON protocol_stats_v2; CREATE TRIGGER delay_insert BEFORE INSERT ON protocol_stats_v2 FOR EACH ROW EXECUTE FUNCTION slow_insert();")
    d=tmp/'stress';d.mkdir();run([stress],d)
    expect_total(250001,d);checks+=1
    state=json.loads((d/'stats.json').read_text());assert state['total_packets']==250000 and state['ack_total_packets']==250000
    assert not (d/'pending-stats.json').exists();assert sql("SELECT COUNT(*) FROM alerts_v2 WHERE type='integration' AND sensor_id='integration-current'")=='1';checks+=3
    run([stress],d);expect_total(500001,d);checks+=1
    sql('DROP TRIGGER delay_insert ON protocol_stats_v2; DROP FUNCTION slow_insert();')
    # Failed delivery must leave a journal. Recovery must deliver it once under its stable event ID.
    d=tmp/'outage';d.mkdir();bad=re.sub(r'port=(\d+)',lambda m:'port='+str(int(m[1])+1),conninfo);run([stress],d,{'PACKET_TEST_CONNINFO':bad})
    assert (d/'pending-stats.json').exists();checks+=1
    original=json.loads((d/'pending-stats.json').read_text())
    for key,value in [('schema_version',3),('sensor_id','different-sensor'),('total_packets',original['target_total_packets']+1)]:
        damaged=tmp/('corrupt-'+key);shutil.copytree(d,damaged)
        journal=original.copy();journal[key]=value;(damaged/'pending-stats.json').write_text(json.dumps(journal))
        e=env.copy();e.update(SNIFFER_STATE_DIR=str(damaged),SNIFFER_SENSOR_ID=sensor,DATABASE_URL=conninfo)
        p=subprocess.run([sniffer,'--no-env','--quiet','--read',str(root/'tests/pcaps/empty.pcap')],cwd=damaged,env=e,capture_output=True,text=True,timeout=10)
        assert p.returncode!=0 and json.loads((damaged/'pending-stats.json').read_text())==journal;checks+=1
    run([sniffer,'--no-env','--quiet','--read',str(root/'tests/pcaps/empty.pcap')],d)
    expect_total(750001,d);checks+=1
    assert not (d/'pending-stats.json').exists();checks+=1
print('POSTGRES_INTEGRATION_OK',checks,'checks')
