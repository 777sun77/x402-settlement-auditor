#!/usr/bin/env python3
"""Start with run.sh, curl free/402/400 routes, save evidence, and always stop."""
import base64
import datetime
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
BASE='http://127.0.0.1:8787'
PUBLIC='https://audit.example.test'


def main():
    env=dict(os.environ, PUBLIC_BASE_URL=PUBLIC)
    # A previous execution environment may have ended its whole process namespace.
    pid_file=ROOT/'data/server.pid'
    if pid_file.exists():
        old=int(pid_file.read_text())
        try:os.kill(old,0)
        except ProcessLookupError:pid_file.unlink()
        else:raise SystemExit('Existing recorded PID is alive; inspect it before smoke testing')
    subprocess.run(['bash','run.sh'],cwd=ROOT,env=env,check=True)
    pid=int(pid_file.read_text());checks=[]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            def curl(path,body=None):
                cmd=['curl','-sS','--max-time','10','-D',tmp+'/headers','-o',tmp+'/body','-w','%{http_code}',BASE+path]
                if body is not None:cmd+=['-H','Content-Type: application/json','--data-binary',json.dumps(body)]
                p=subprocess.run(cmd,capture_output=True,text=True,check=True)
                return int(p.stdout),Path(tmp+'/headers').read_text(),Path(tmp+'/body').read_text()
            request={'tx_hash':'0x389a08dba01e0d65999b775cd9724d73d82bd3908ae5666ae631ef87e4dfde99'}
            s,h,raw=curl('/v1/audit',request);obj=json.loads(raw);assert s==402
            header=next(x.split(':',1)[1].strip() for x in h.splitlines() if x.lower().startswith('payment-required:'))
            assert json.loads(base64.b64decode(header))==obj
            assert obj['resource']['url']==PUBLIC+'/v1/audit'
            checks.append({'path':'POST /v1/audit','status':s,'payment_required_matches_body':True,'resource_url':obj['resource']['url']})
            for path in ['/','/guide','/terms','/example','/health']:
                s,h,raw=curl(path);assert s==200,(path,s)
                item={'path':'GET '+path,'status':s,'bytes':len(raw.encode())}
                if path=='/guide':assert 'recovery' in raw
                if path=='/example':
                    v=json.loads(raw);assert v['verdict']=='matches' and v['partial'] is False
                    item.update(verdict=v['verdict'],block=v['transaction']['block_number'],codes=v['trailing_calldata']['codes'])
                if path=='/health':item['health']=json.loads(raw)
                checks.append(item)
            s,h,raw=curl('/v1/audit',{'tx_hash':'bad'});assert s==400
            checks.append({'path':'POST /v1/audit invalid input','status':s,'response':json.loads(raw)})
            with sqlite3.connect('file:'+str(ROOT/'data/payments.db')+'?mode=ro',uri=True) as db:
                assert db.execute('SELECT COUNT(*) FROM payments').fetchone()[0]==0
    finally:
        os.kill(pid,signal.SIGTERM)
        # The listener must close; PID may briefly remain as an adopted zombie.
        for _ in range(40):
            p=subprocess.run(['curl','-s','--max-time','1',BASE+'/health'],capture_output=True)
            if p.returncode:break
            time.sleep(.1)
        else:raise AssertionError('server did not stop')
        pid_file.unlink(missing_ok=True)
    evidence={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks,
              'payment_or_signing_performed':False,'payment_rows':0,'server_stopped':True}
    (ROOT/'data/local-checks.json').write_text(json.dumps(evidence,indent=2)+'\n')
    for x in checks:print(x['path'],x['status'])
    print('Server stopped; payment database empty.')

if __name__=='__main__':main()
