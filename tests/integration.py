"""Isolated CLI, corpus, JSON, API and shutdown regression checks; no capture driver needed."""
import json, os, pathlib, socket, struct, subprocess, sys, tempfile, time
sniffer, fixture, regression, smoke = map(str, map(pathlib.Path,sys.argv[1:5]))
root=pathlib.Path(sys.argv[5]);checks=0
base={k:v for k,v in os.environ.items() if not k.startswith(('SNIFFER_','STATS_','AWS_RDS_')) and k not in ('DATABASE_URL','POSTGRES_CONNINFO','LOG_LEVEL')}
with tempfile.TemporaryDirectory(prefix='sniffer-tests-') as temp:
    temp=pathlib.Path(temp)
    def run(args,name,expect=0,extra=None):
        global checks
        d=temp/name;d.mkdir();env=base.copy();env['SNIFFER_STATE_DIR']=str(d);env.update(extra or {})
        result=subprocess.run(args,cwd=d,env=env,capture_output=True,text=True,timeout=15)
        assert (result.returncode==0) == (expect==0),(name,result.returncode,result.stdout,result.stderr)
        checks+=1;return result,d
    r,d=run([regression],'regression');assert 'REGRESSION_OK' in r.stdout
    legacy=temp/'legacy';legacy.mkdir();original='{"total_packets":99,"total_bytes":999,"ethernet":99,"ethernet_bytes":999}'
    (legacy/'stats.json').write_text(original)
    e=base.copy();e['SNIFFER_STATE_DIR']=str(legacy)
    p=subprocess.run([sniffer,'--no-env','--quiet','--no-db','--read',str(root/'tests/pcaps/eth-tcp-http.pcap')],cwd=legacy,env=e,capture_output=True,text=True,timeout=15)
    assert p.returncode==0 and (legacy/'stats.json.legacy').read_text()==original
    assert json.loads((legacy/'stats.json').read_text())['total_packets']==1
    checks+=1
    r,d=run([smoke,str(temp/'smoke.json')],'smoke');assert 'SMOKE_OK' in r.stdout
    run([sniffer,'--no-env','--help'],'help')
    run([sniffer,'--no-env','--no-db','--read','missing.pcap'],'missing',1)
    for key,value in [('SNIFFER_SNAPLEN','68junk'),('SNIFFER_API_PORT','999999'),('STATS_FLUSH_MS','0')]:
        run([sniffer,'--no-env','--no-db','--read',str(root/'tests/pcaps/empty.pcap')],key,1,{key:value})
    run([sniffer,'--no-env','--no-db','--read',str(root/'tests/pcaps/empty.pcap'),'--filter','tcp and ('],'bad-bpf',1)
    for p in sorted((root/'tests/pcaps').glob('*.pcap')):
        r,d=run([sniffer,'--no-env','--no-db','--quiet','--read',str(p)],p.stem)
        assert not r.stderr,(p.name,r.stderr)
        assert 'IPv4:' not in r.stdout and '[HTTP]' not in r.stdout
        stats=json.loads((d/'stats.json').read_text());raw=p.read_bytes();pos=24;count=cap=wire=0
        while pos+16<=len(raw):
            _,_,c,w=struct.unpack_from('<IIII',raw,pos);count+=1;cap+=c;wire+=w;pos+=16+c
        assert (stats['total_packets'],stats['total_bytes'],stats['wire_bytes'])==(count,cap,wire),(p.name,stats)
        assert stats['analyzed']==count,(p.name,stats)
        if p.stem=='sll2':assert stats['ipv4']==1
        if p.stem=='invalid-sll2-legacy':assert stats['unsupported']==1
        if p.stem=='eth-tcp-http':assert stats['http']==1
    # Explicit CLI logging overrides environment configuration.
    r,d=run([sniffer,'--no-env','--no-db','--log-level','0','--read',str(root/'tests/pcaps/eth-tcp-http.pcap')],'precedence',extra={'LOG_LEVEL':'3'})
    assert '[HTTP]' not in r.stdout
    d=temp/'api';d.mkdir();env=base.copy();env.update(SNIFFER_STATE_DIR=str(d),SNIFFER_API_TOKEN='test-secret')
    reserved=socket.socket();reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1];reserved.close();env['SNIFFER_API_PORT']=str(port)
    proc=subprocess.Popen([fixture],cwd=d,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        assert proc.stdout.readline().strip()=='API_UP'
        stalled=socket.create_connection(('127.0.0.1',port),timeout=2)
        def request(parts):
            with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
                for p in parts:s.sendall(p);time.sleep(.01)
                data=b''
                while True:
                    b=s.recv(65536)
                    if not b:break
                    data+=b
                h,body=data.split(b'\r\n\r\n',1);return int(h.split()[1]),json.loads(body)
        status,body=request([b'GET /health HTTP/1.1\r\n',b'authorization: Bearer test-secret\r\n\r\n']);assert status==200 and body['alive']
        assert request([b'GET /stats HTTP/1.1\r\n\r\n'])[0]==401
        status,body=request([b'GET /stats HTTP/1.1\r\nAuthorization: Bearer test-secret\r\n\r\n']);assert status==200 and body['schema_version']==2
        assert request([b'GET /health HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n'])[0]==400
        assert request([b'GET /health HTTP/1.1\r\n\r\nAuthorization: Bearer test-secret'])[0]==400
        # A second fixture must fail synchronous startup on an occupied port.
        occupied=temp/'occupied';occupied.mkdir();e=env.copy();e['SNIFFER_STATE_DIR']=str(occupied)
        result=subprocess.run([fixture],cwd=occupied,env=e,capture_output=True,text=True,timeout=5);assert result.returncode!=0
        stalled.close();out,err=proc.communicate(timeout=12);assert proc.returncode==0 and 'API_DOWN' in out,(out,err)
        checks+=7
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
print('INTEGRATION_OK',checks,'checks')
