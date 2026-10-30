import base64
import hashlib
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from payments import PaymentStore,PaymentService,b64
from server import Server,ROOT
from tests.test_payments import MockFacilitator,FakeRPC,payload,BASE,REQUEST


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.fac=MockFacilitator()
        cls.service=PaymentService(PaymentStore(Path(cls.tmp.name)/'db'),cls.fac,BASE,
            audit_fn=lambda req:{'verdict':'matches','partial':False},rpc_factory=FakeRPC)
        cls.server=Server(('127.0.0.1',0),cls.service)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.tmp.cleanup()
    def send(self,method,path,body=None,headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        conn.request(method,path,body,headers or {})
        r=conn.getresponse();status=r.status;h=dict(r.getheaders());raw=r.read();conn.close()
        return status,h,raw
    def test_free_pages_and_health(self):
        for path in ['/','/guide','/terms','/example','/health']:
            status,h,raw=self.send('GET',path)
            self.assertEqual(status,200,path);self.assertTrue(raw)
        status,h,raw=self.send('GET','/health');obj=json.loads(raw)
        self.assertEqual(obj['server_sha256'],hashlib.sha256((ROOT/'server.py').read_bytes()).hexdigest())
        status,h,raw=self.send('GET','/example');self.assertEqual(json.loads(raw)['verdict'],'matches')
    def test_unpaid_challenge_and_invalid_input_without_charge(self):
        before=self.fac.settles
        status,h,raw=self.send('POST','/v1/audit',json.dumps(REQUEST),{'Content-Type':'application/json'})
        self.assertEqual(status,402)
        self.assertEqual(json.loads(raw),json.loads(base64.b64decode(h['PAYMENT-REQUIRED'])))
        status,h,raw=self.send('POST','/v1/audit','{"tx_hash":"bad"}',{'Content-Type':'application/json','PAYMENT-SIGNATURE':b64(payload())})
        self.assertEqual(status,400);self.assertEqual(self.fac.settles,before)
    def test_legacy_header_paid_delivery_and_replay(self):
        body=json.dumps(REQUEST);headers={'Content-Type':'application/json','X-PAYMENT':b64(payload())}
        first=self.send('POST','/v1/audit',body,headers)
        second=self.send('POST','/v1/audit',body,headers)
        self.assertEqual(first[0],200);self.assertEqual(first[2],second[2])
        self.assertIn('PAYMENT-RESPONSE',first[1])
    def test_malformed_json_and_wrong_media_type(self):
        before=self.fac.settles
        for body,ctype,code in [('{"tx_hash":NaN}','application/json',400),('{','application/json',400),
                                 ('{"x":1,"x":2}','application/json',400),('{}','text/plain',415),('x'*32001,'application/json',413)]:
            self.assertEqual(self.send('POST','/v1/audit',body,{'Content-Type':ctype})[0],code)
        self.assertEqual(self.fac.settles,before)

if __name__=='__main__':unittest.main()
