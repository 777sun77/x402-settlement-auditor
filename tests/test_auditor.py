import copy
import json
import unittest
from pathlib import Path
from auditor import audit, validate_input, EXAMPLE_TX
from decoder import (decode_authorization, decode_suffix, find_calls, MARKER, USDC,
                     keccak_self_test, BYTES_AUTH_SELECTORS, AGGREGATE3)

ROOT = Path(__file__).resolve().parents[1]
SNAP = json.loads((ROOT/'data/example-snapshot.json').read_text())
EXAMPLE = json.loads((ROOT/'data/example.json').read_text())


def word(n): return n.to_bytes(32, 'big')


def aggregate(inner):
    raw = bytes.fromhex(inner[2:]); padded = raw+b'\x00'*((-len(raw))%32)
    return AGGREGATE3+(word(32)+word(1)+word(32)+bytes.fromhex(USDC[2:]).rjust(32,b'\x00')+word(0)+word(96)+word(len(raw))+padded).hex()


class SnapshotRPC:
    def __init__(self, snapshot=None, state=True):
        self.snap = copy.deepcopy(snapshot or SNAP); self.reads = []; self.state=state
    def call(self, method, params):
        self.reads.append({'method':method,'params':params,'rpc':'mock://snapshot'})
        if method == 'eth_call': return '0x'+word(int(self.state)).hex()
        return {'eth_getTransactionByHash':self.snap['transaction'],
                'eth_getTransactionReceipt':self.snap['receipt'],
                'eth_getBlockByNumber':self.snap['block']}[method]


class DecoderTests(unittest.TestCase):
    def test_keccak(self): keccak_self_test()

    def test_real_schema2_suffix(self):
        c = decode_authorization(SNAP['transaction']['input'])
        self.assertEqual(c['trailing']['codes'], ['cdp_facil1'])
        self.assertEqual(c['trailing']['schema_id'], 2)
        self.assertEqual(c['abi_bytes'], 292)
        self.assertNotIn('signature',c)

    def test_suffix_schemas_0_1_and_unknown(self):
        for schema in (0,1):
            prefix = bytes.fromhex('11'*20) if schema else b''
            result = decode_suffix(prefix+b'one,two'+bytes([7,schema])+MARKER)
            self.assertEqual(result['codes'], ['one','two'])
            self.assertEqual(result['format'], 'erc8021')
        self.assertEqual(decode_suffix(b'x\x00\xff'+MARKER)['format'],'raw')
        self.assertEqual(decode_suffix(b'x\x05\x00'+MARKER)['format'],'raw')
        self.assertEqual(decode_suffix(b'garbage')['raw'],'0x67617262616765')

    def test_cbor_lengths_duplicate_keys_and_bad_code(self):
        for raw in (b'\xa1\x61w\x61!', b'\xa2\x61w\x61a\x61w\x61b', b'\xbf\xff'):
            out = decode_suffix(raw+len(raw).to_bytes(2,'big')+b'\x02'+MARKER)
            self.assertEqual(out['format'], 'raw')
        data=b'\xa2\x61a\x63app\x61s\x82\x63one\x63two'
        out=decode_suffix(data+len(data).to_bytes(2,'big')+b'\x02'+MARKER)
        self.assertEqual(out['codes'],['app','one','two'])

    def test_all_authorization_overloads_and_trailing(self):
        original = bytes.fromhex(SNAP['transaction']['input'][2:])
        for selector in ('0xe3ee160e','0xef55bec6', *BYTES_AUTH_SELECTORS):
            common=original[4:4+6*32]
            if selector in BYTES_AUTH_SELECTORS:
                args=common+word(7*32)+word(65)+b'\x01'*65+b'\x00'*31
            else: args=original[4:292]
            c=decode_authorization(selector+(args+b'raw tail').hex())
            self.assertEqual(c['value'],10000)
            self.assertEqual(c['trailing']['raw'],'0x'+b'raw tail'.hex())
            with self.assertRaises(ValueError):decode_authorization(selector+args[:-5].hex())

    def test_multicall_nested_and_outer_suffix(self):
        inner=SNAP['transaction']['input'][:2+292*2]
        data=aggregate(aggregate(inner))
        suffix=b'one\x03\x00'+MARKER
        calls,warnings,tail=find_calls({'to':'0xca11bde05977b3631167028862be2a173976ca11','input':data+suffix.hex()})
        self.assertEqual(calls[0]['path'],[0,0]); self.assertEqual(warnings,[])
        self.assertEqual(tail['codes'],['one'])

    def test_unknown_facilitator_selector_hint(self):
        inner=SNAP['transaction']['input'][:2+292*2]
        c,w,t=find_calls({'to':'0x'+'11'*20,'input':'0x12345678'+word(32).hex()+inner[2:]})
        self.assertEqual(c[0]['detection'],'wrapper_selector_scan')
        self.assertTrue(w)


class EngineTests(unittest.TestCase):
    def request(self, expected=None):
        return validate_input({'tx_hash':EXAMPLE_TX,'expected':expected or {}})
    def test_example_and_block_pinned_state(self):
        rpc=SnapshotRPC(); out=audit(EXAMPLE['example_request'],rpc)
        self.assertEqual(out['verdict'],'matches');self.assertFalse(out['partial'])
        self.assertEqual(out['authorization_state']['eth_call'][1], {'blockHash':SNAP['block']['hash'],'requireCanonical':True})
    def test_mismatch_each_expected_field(self):
        for field,value in [('pay_to','0x'+'11'*20),('payer','0x'+'11'*20),('asset','0x'+'11'*20),('amount','1'),('valid_at',1)]:
            out=audit(self.request({field:value}),SnapshotRPC())
            self.assertEqual(out['verdict'],'mismatch',field)
            self.assertEqual(out['checks'][field]['status'],'fail')
    def test_validity_bounds_are_strict(self):
        c=decode_authorization(SNAP['transaction']['input'])
        for v in (c['validAfter'],c['validBefore']):
            self.assertEqual(audit(self.request({'valid_at':v}),SnapshotRPC())['verdict'],'mismatch')
    def test_unused_nonce_not_match(self):
        self.assertEqual(audit(self.request(),SnapshotRPC(state=False))['verdict'],'mismatch')
    def test_raw_tail_does_not_reject(self):
        s=copy.deepcopy(SNAP);s['transaction']['input']=s['transaction']['input'][:586]+'deadbeef'
        out=audit(self.request(),SnapshotRPC(s))
        self.assertEqual(out['verdict'],'matches');self.assertEqual(out['trailing_calldata']['format'],'raw')
    def test_plain_transfer_is_not_eip3009(self):
        s=copy.deepcopy(SNAP);s['receipt']['logs']=s['receipt']['logs'][1:];s['transaction']['input']='0x'
        out=audit(self.request(),SnapshotRPC(s))
        self.assertEqual(out['verdict'],'not_an_x402_settlement');self.assertEqual(len(out['usdc_transfers']),1)
    def test_unexecuted_multicall_leg_cannot_match(self):
        s=copy.deepcopy(SNAP);s['transaction']['input']=aggregate(s['transaction']['input']);s['receipt']['logs']=[]
        self.assertEqual(audit(self.request(),SnapshotRPC(s))['verdict'],'not_an_x402_settlement')
    def test_receipt_fallback_and_unknown_window(self):
        s=copy.deepcopy(SNAP);s['transaction']['input']='0xdeadbeef'
        self.assertEqual(audit(self.request(),SnapshotRPC(s))['verdict'],'matches')
        out=audit(self.request({'valid_at':1793245403}),SnapshotRPC(s))
        self.assertTrue(out['partial']);self.assertIsNone(out['verdict'])
    def test_failed_missing_pending_and_bad_identity(self):
        s=copy.deepcopy(SNAP);s['receipt']['status']='0x0'
        self.assertEqual(audit(self.request(),SnapshotRPC(s))['verdict'],'failed_tx')
        for tx,receipt,verdict,partial in [(None,None,'not_found',False),(SNAP['transaction'],None,None,True)]:
            s=copy.deepcopy(SNAP);s.update(transaction=tx,receipt=receipt)
            out=audit(self.request(),SnapshotRPC(s));self.assertEqual(out['verdict'],verdict);self.assertEqual(out['partial'],partial)
        s=copy.deepcopy(SNAP);s['block']['hash']='0x'+'12'*32
        self.assertTrue(audit(self.request(),SnapshotRPC(s))['partial'])
    def test_validation(self):
        for value in ({'tx_hash':'bad'},{'tx_hash':EXAMPLE_TX,'expected':{'amount':10000}},
                      {'tx_hash':EXAMPLE_TX,'expected':{'amount':'01'}},
                      {'tx_hash':EXAMPLE_TX,'expected':{'valid_at':True}},
                      {'tx_hash':EXAMPLE_TX,'expected':{'amount':str(2**256)}},
                      {'tx_hash':EXAMPLE_TX,'expected':{'payer':'0x123'}},
                      {'tx_hash':EXAMPLE_TX,'foo':1}):
            with self.assertRaises(ValueError):validate_input(value)


class LiveReadOnlyTests(unittest.TestCase):
    def test_worked_example_on_public_base_rpc(self):
        # Only eth_chainId/getTransaction/getReceipt/getBlock/eth_call. No signing or settle.
        out=audit(EXAMPLE['example_request'])
        self.assertEqual(out['verdict'],'matches',out['errors'])
        self.assertFalse(out['partial']);self.assertEqual(out['transaction']['block_number'],53228028)
        self.assertEqual(out['trailing_calldata']['codes'],['cdp_facil1'])
        self.assertTrue(out['authorization_state']['used_or_canceled'])
        self.assertTrue(out['rpc_reads'][0]['rpc'].startswith('https://'))

if __name__=='__main__':unittest.main()
