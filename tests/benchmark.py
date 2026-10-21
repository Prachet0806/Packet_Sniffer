"""Replay benchmark: wall time includes startup, analysis and durable shutdown."""
import json,os,pathlib,subprocess,sys,tempfile,time
exe=pathlib.Path(sys.argv[1]).resolve();root=pathlib.Path(__file__).resolve().parent.parent
count=int(sys.argv[2]) if len(sys.argv)>2 else 100000
raw=(root/'tests/pcaps/eth-tcp-http.pcap').read_bytes()
env={k:v for k,v in os.environ.items() if not k.startswith(('SNIFFER_','STATS_','AWS_RDS_')) and k not in ('DATABASE_URL','POSTGRES_CONNINFO','LOG_LEVEL')}
with tempfile.TemporaryDirectory(prefix='sniffer-bench-') as temp:
    temp=pathlib.Path(temp);source=temp/'benchmark.pcap';source.write_bytes(raw[:24]+raw[24:]*count)
    env['SNIFFER_STATE_DIR']=str(temp)
    start=time.perf_counter();p=subprocess.run([str(exe),'--no-env','--no-db','--quiet','--read',str(source)],cwd=temp,env=env,capture_output=True,timeout=120)
    elapsed=time.perf_counter()-start;assert p.returncode==0,p.stderr
    result=json.loads((temp/'stats.json').read_text());assert result['total_packets']==count and result['analyzed']==count
    print(json.dumps({'packets':count,'seconds':elapsed,'packets_per_second':round(count/elapsed),'queue_drops':result['queue_drops'],'http_messages':result['http'],'note':'identical sequence numbers exercise retransmission deduplication; this is replay throughput, not live capture capacity'},indent=2))
