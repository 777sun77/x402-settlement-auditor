import base64
import concurrent.futures
import copy
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from auditor import EXAMPLE_TX, validate_input
from payments import (PaymentService, PaymentStore, Facilitators, b64, challenge, requirements,
                      PAY_TO, NETWORK, canonical, parse_payment, RETENTION)
from transport import RemoteError, RPC

BASE='https://audit.example.test'
PAYER='0x'+'11'*20
TX='0x'+'22'*32
REQUEST={'tx_hash':EXAMPLE_TX}


def payload():
    now=int(time.time())
    return {'x402Version':2,'resource':{'url':BASE+'/v1/audit'},'accepted':requirements(),
            'payload':{'signature':'0x'+'00'*65,'authorization':{'from':PAYER,'to':PAY_TO,'value':'10000',
            'validAfter':str(now-10),'validBefore':str(now+200),'nonce':'0x'+'aa'*32}}}


class FakeRPC:
    def call(self, method, params):
        if method=='eth_blockNumber':return '0x64'
        if method=='eth_getLogs':return []
        raise AssertionError(method)


class MockFacilitator:
    def __init__(self):
        self.verifies=0;self.settles=0;self.failure=False;self.uncertain=False
        self.enter=None;self.release=None
    def verify(self,p):
        self.verifies+=1
        return ('https://mock.test', None)
    def settle(self,url,p):
        self.settles+=1
        if self.enter:
            self.enter.set();self.release.wait(timeout=4)
        if self.uncertain:raise RemoteError('timeout after possible broadcast')
        return {'success':not self.failure,'transaction':'' if self.failure else TX,
                'network':NETWORK,'payer':PAYER,'errorReason':'insufficient_funds' if self.failure else None}


class PaymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'payments.db'
        self.store=PaymentStore(self.path);self.fac=MockFacilitator();self.audit_calls=0
        def audit_fn(req):
            self.audit_calls+=1
            return {'tx_hash':req['tx_hash'],'verdict':'matches','partial':False}
        self.engine=audit_fn
        self.service=PaymentService(self.store,self.fac,BASE,audit_fn,FakeRPC)
        self.payload=payload();self.header=b64(self.payload)
    def tearDown(self):self.tmp.cleanup()
    def call(self,body=None,header=None):return self.service.process(REQUEST if body is None else body, self.header if header is None else header)

    def test_challenge_exact_contract(self):
        status,obj,headers=self.service.process(REQUEST)
        self.assertEqual(status,402)
        self.assertEqual(json.loads(base64.b64decode(headers['PAYMENT-REQUIRED'])),obj)
        self.assertEqual(obj['resource']['url'],BASE+'/v1/audit')
        self.assertEqual(obj['x402Version'],2)
        self.assertEqual(obj['accepts'][0],requirements())
        self.assertEqual((self.fac.verifies,self.fac.settles),(0,0))

    def test_invalid_input_precedes_all_payment_work(self):
        for body in [{'tx_hash':'bad'},{'tx_hash':EXAMPLE_TX,'expected':{'amount':2}},None,[],{'tx_hash':EXAMPLE_TX,'expected':{'valid_at':False}}]:
            self.assertEqual(self.service.process(body,self.header)[0],400)
        self.assertEqual((self.fac.verifies,self.fac.settles,self.audit_calls),(0,0,0))
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM payments').fetchone()[0],0)

    def test_identical_retries_and_restart_replay(self):
        first=self.call();second=self.call()
        self.assertEqual(first,second);self.assertEqual(first[0],200)
        receipt=json.loads(base64.b64decode(first[2]['PAYMENT-RESPONSE']))
        self.assertEqual(receipt,{'success':True,'network':NETWORK,'transaction':TX,'payer':PAYER})
        self.service=PaymentService(PaymentStore(self.path),self.fac,BASE,self.engine,FakeRPC)
        self.assertEqual(self.call(),first)
        self.assertEqual((self.fac.settles,self.audit_calls),(1,1))
        # Semantically identical JSON/base64 encoding is recoverable, too.
        alt=base64.b64encode(json.dumps(self.payload,indent=2).encode()).decode()
        self.assertEqual(self.call(header=alt),first)
        with self.store.connect() as db:
            row=dict(db.execute('SELECT * FROM payments').fetchone())
            self.assertNotIn(self.header,canonical(row));self.assertNotIn(self.payload['payload']['signature'],canonical(row))

    def test_reused_nonce_different_body_or_signature_is_conflict(self):
        self.call()
        changed={'tx_hash':'0x'+'33'*32}
        self.assertEqual(self.call(changed)[0],409)
        p=copy.deepcopy(self.payload);p['payload']['signature']='0x'+'01'*65
        self.assertEqual(self.call(header=b64(p))[0],409)
        self.assertEqual(self.fac.settles,1)

    def test_two_service_instances_concurrent_duplicates(self):
        self.fac.enter=threading.Event();self.fac.release=threading.Event()
        service2=PaymentService(PaymentStore(self.path),self.fac,BASE,self.engine,FakeRPC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(self.call)
            self.assertTrue(self.fac.enter.wait(timeout=2))
            second=service2.process(REQUEST,self.header)
            self.assertEqual(second[0],202);self.assertEqual(second[2]['Retry-After'],'15')
            self.fac.release.set();self.assertEqual(first.result(timeout=2)[0],200)
        self.assertEqual((self.fac.settles,self.audit_calls),(1,1))

    def test_definite_settlement_failure_is_402_no_output_or_second_settle(self):
        self.fac.failure=True
        self.assertEqual(self.call()[0],402);self.assertEqual(self.call()[0],402)
        self.assertEqual((self.fac.settles,self.audit_calls),(1,0))

    def test_verification_failure_never_reserves_or_settles(self):
        self.fac.verify=lambda p:(None,'payment_verification_failed')
        self.assertEqual(self.call()[0],402);self.assertEqual(self.fac.settles,0)
        self.assertIsNone(self.store.get(parse_payment(self.header,BASE)[1]))

    def test_timeout_stays_pending_across_restart_without_resubmission(self):
        self.fac.uncertain=True
        self.assertEqual(self.call()[0],202)
        self.service=PaymentService(PaymentStore(self.path),self.fac,BASE,self.engine,FakeRPC)
        self.assertEqual(self.call()[0],202);self.assertEqual(self.fac.settles,1)

    def test_rpc_failure_after_settlement_returns_200_partial_and_receipt(self):
        def broken(req):raise RemoteError('offline')
        self.service.audit_fn=broken
        first=self.call();second=self.call()
        self.assertEqual(first[0],200);self.assertTrue(first[1]['partial']);self.assertIsNone(first[1]['verdict'])
        self.assertIn('PAYMENT-RESPONSE',first[2]);self.assertEqual(first,second);self.assertEqual(self.fac.settles,1)

    def test_payment_rpc_failure_before_settlement_is_503(self):
        class Offline:
            def call(self,*args):raise RemoteError('offline')
        self.service.rpc_factory=Offline
        self.assertEqual(self.call()[0],503);self.assertEqual(self.fac.settles,0)

    def test_expired_results_are_tombstones(self):
        self.call();key=parse_payment(self.header,BASE)[1]
        self.store.update(key,created=time.time()-RETENTION-1,completed=time.time()-RETENTION-1)
        self.assertEqual(self.call()[0],410);self.assertEqual(self.fac.settles,1)
        row=self.store.get(key);self.assertIsNone(row['body']);self.assertIsNone(row['result'])

    def test_expired_authorization_still_recovers_stored_result(self):
        first=self.call()
        with patch('payments.time.time',return_value=time.time()+500):self.assertEqual(self.call(),first)
        self.assertEqual(self.fac.settles,1)

    def test_invalid_payment_requirements_and_300_second_bound(self):
        for change in ('version','payee','asset','expiry'):
            p=copy.deepcopy(self.payload)
            if change=='version':p['x402Version']=1
            if change=='payee':p['accepted']['payTo']=PAYER
            if change=='asset':p['accepted']['asset']=PAYER
            if change=='expiry':p['payload']['authorization']['validBefore']=str(int(time.time())+1000)
            self.assertEqual(self.call(header=b64(p))[0],402)
        self.assertEqual(self.fac.settles,0)

    def test_reconcile_found_hash_survives_an_rpc_outage(self):
        self.fac.uncertain=True;self.assertEqual(self.call()[0],202)
        calls=[]
        class RecoverRPC:
            def call(self,method,params):
                calls.append(method)
                if method=='eth_blockNumber':return '0x65'
                if method=='eth_getLogs':return [{'transactionHash':TX}]
                raise RemoteError('receipt unavailable')
        self.service.rpc_factory=RecoverRPC
        self.assertEqual(self.call()[0],202)
        key=parse_payment(self.header,BASE)[1]
        self.assertEqual(json.loads(self.store.get(key)['settlement'])['transaction'],TX)
        self.assertEqual(self.fac.settles,1)
        self.assertEqual(self.call()[0],202)
        self.assertEqual(calls.count('eth_getLogs'),1)

    def test_reconcile_after_crash_recovers_original_nonce(self):
        self.fac.uncertain=True;self.assertEqual(self.call()[0],202)
        nonce=self.payload['payload']['authorization']['nonce']
        class RecoverRPC(FakeRPC):
            def call(self,method,params):
                if method=='eth_getLogs':return [{'transactionHash':TX}]
                return super().call(method,params)
        result={'verdict':'matches','selected':{'event':{'nonce':nonce}}}
        self.service.rpc_factory=RecoverRPC
        with patch('payments.audit',return_value=result):recovered=self.call()
        self.assertEqual(recovered[0],200);self.assertEqual(self.fac.settles,1)
        self.assertEqual(json.loads(base64.b64decode(recovered[2]['PAYMENT-RESPONSE']))['transaction'],TX)

    def test_finalized_expired_unused_authorization_resolves_without_settlement(self):
        self.fac.uncertain=True;self.assertEqual(self.call()[0],202)
        expires=int(self.payload['payload']['authorization']['validBefore'])
        class FinalizedRPC(FakeRPC):
            def call(self,method,params):
                if method=='eth_getBlockByNumber':
                    return {'timestamp':hex(expires+10),'hash':'0x'+'bb'*32}
                if method=='eth_call':return '0x'+'00'*32
                return super().call(method,params)
        self.service.rpc_factory=FinalizedRPC
        with patch('payments.time.time',return_value=expires+20):
            result=self.call()
        self.assertEqual(result[0],402)
        self.assertEqual(result[1]['error'],'authorization_expired_unused')
        self.assertEqual(self.fac.settles,1);self.assertEqual(self.audit_calls,0)

    def test_oversized_result_is_partial_with_original_payment_receipt(self):
        self.service.audit_fn=lambda req:{'evidence':'x'*480001}
        result=self.call()
        self.assertEqual(result[0],200);self.assertTrue(result[1]['partial'])
        self.assertIn('PAYMENT-RESPONSE',result[2])
        self.assertLess(len(canonical(result[1])),500000)


class FacilitatorTransportTests(unittest.TestCase):
    def test_fallback_selected_only_before_settlement(self):
        f=object.__new__(Facilitators);f.urls=('https://primary.test','https://fallback.test');f.support={u:True for u in f.urls}
        def remote(url,payload,timeout):
            if 'primary' in url:raise RemoteError('offline')
            return 200,{'isValid':True,'payer':PAYER}
        with patch('payments.http_json',side_effect=remote):
            self.assertEqual(f.verify(payload()),('https://fallback.test',None))
        with patch('payments.http_json',side_effect=RemoteError('timeout')) as h:
            with self.assertRaises(RemoteError):f.settle('https://primary.test',payload())
            self.assertEqual(h.call_count,1)

    def test_rpc_retry_and_chain_check(self):
        calls=[]
        def remote(url,obj,timeout):
            calls.append((url,obj['method']))
            if url=='https://primary.test':raise RemoteError('offline')
            return 200,{'jsonrpc':'2.0','id':1,'result':'0x2105' if obj['method']=='eth_chainId' else '0x64'}
        rpc=RPC(['https://primary.test','https://fallback.test'])
        with patch('transport.http_json',side_effect=remote),patch('transport.time.sleep'):
            self.assertEqual(rpc.call('eth_blockNumber',[]),'0x64')
        self.assertEqual(calls.count(('https://primary.test','eth_chainId')),2)
        self.assertEqual(rpc.reads[-1]['rpc'],'https://fallback.test')

if __name__=='__main__':unittest.main()
