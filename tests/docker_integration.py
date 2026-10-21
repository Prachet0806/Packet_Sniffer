"""Read-only checks against the isolated Compose deployment described in tests/README.md."""
import base64,json,pathlib,subprocess,sys,urllib.request
root=pathlib.Path(__file__).resolve().parent.parent
base=sys.argv[1] if len(sys.argv)>1 else 'http://127.0.0.1:57300'
password=sys.argv[2] if len(sys.argv)>2 else 'change-me'
auth=base64.b64encode(('admin:'+password).encode()).decode()
def call(path,data=None):
    req=urllib.request.Request(base+path,data=json.dumps(data).encode() if data else None,headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=10) as r:return json.load(r)
assert call('/api/health')['database']=='ok'
health=call('/api/datasources/uid/sniffer-postgres/health');assert health['status']=='OK',health
panel=call('/api/dashboards/uid/sniffer-overview')['dashboard'];assert len(panel['panels'])==8
result=call('/api/ds/query',{'queries':[{'refId':'A','datasource':{'uid':'sniffer-postgres','type':'postgres'},'rawSql':"SELECT SUM(total_packets) AS packets FROM protocol_stats_v2 WHERE sensor_id='replay'",'rawQuery':True,'format':'table'}],'from':'0','to':'now'})
a=result['results']['A'];assert not a.get('error'),a
values=a['frames'][0]['data']['values'];assert sum(v for column in values for v in column if isinstance(v,(int,float)))>=1,values
for p in panel['panels']:
    sql=p['targets'][0]['rawSql'].replace('${sensor:sqlstring}',"'replay'")
    response=call('/api/ds/query',{'queries':[{'refId':'A','datasource':{'uid':'sniffer-postgres','type':'postgres'},'rawSql':sql,'rawQuery':True,'format':p['targets'][0]['format']}],'from':'0','to':'now'})
    assert not response['results']['A'].get('error'),(p['title'],response)
print('DOCKER_GRAFANA_OK: datasource health, replay storage, dashboard provisioning and all 8 panel queries')
