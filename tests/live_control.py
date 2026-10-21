"""Explicit privileged loopback-only capture control/shutdown test."""
import json,os,pathlib,signal,socket,subprocess,sys,tempfile,time
exe=str(pathlib.Path(sys.argv[1]).resolve());s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
env={k:v for k,v in os.environ.items() if not k.startswith(('SNIFFER_','STATS_','AWS_RDS_')) and k not in ('DATABASE_URL','POSTGRES_CONNINFO','LOG_LEVEL')}
with tempfile.TemporaryDirectory(prefix='sniffer-live-') as temp:
    proc=subprocess.Popen([exe,'--no-env','--no-db','--quiet','--iface','lo','--filter','tcp port 1','--write','recorded.pcap','--api-port',str(port),'--api-token','reader'],cwd=temp,env={**env,'SNIFFER_STATE_DIR':temp,'SNIFFER_API_CONTROL_TOKEN':'controller'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        def request(path,body=b'',token='reader'):
            method='POST' if body else 'GET'
            with socket.create_connection(('127.0.0.1',port),timeout=3) as c:
                c.sendall((f'{method} {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body)
                response=b''
                while True:
                    part=c.recv(8192)
                    if not part:break
                    response+=part
                header,content=response.split(b'\r\n\r\n',1);return int(header.split()[1]),json.loads(content)
        end=time.monotonic()+5
        while True:
            try:
                status,health=request('/health')
                if health['capture']['running']:break
            except OSError:pass
            if time.monotonic()>end:raise AssertionError('capture never ready')
            time.sleep(.02)
        body=b'{"bpf":"tcp and (port 1 or port 2)"}'
        assert request('/filter',body)[0]==403
        assert request('/filter',body,'controller')[0]==200
        assert request('/filter',b'{"bpf":"tcp and ("}','controller')[0]==400
        assert request('/health')[1]['capture']['running']
        assert request('/filter',b'{"bpf":"udp and port 49001"}','controller')[0]==200
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:udp.sendto(b'test-recording',('127.0.0.1',49001))
        deadline=time.monotonic()+3
        while request('/stats')[1]['total_packets']==0:
            if time.monotonic()>deadline:raise AssertionError('synthetic packet was not captured')
            time.sleep(.05)
        start=time.monotonic();proc.send_signal(signal.SIGTERM);out,err=proc.communicate(timeout=5)
        assert proc.returncode==0,(out,err);assert time.monotonic()-start<5
        raw=(pathlib.Path(temp)/'recorded.pcap').read_bytes();assert len(raw)>24
        print('LIVE_CONTROL_OK 7 checks; only synthetic loopback traffic is captured')
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
