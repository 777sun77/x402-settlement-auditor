import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from auditor import audit, validate_input, partial_result, EXAMPLE_TX
from transport import RPC, RemoteError
from decoder import (decode_authorization, decode_suffix, find_calls, MARKER, USDC,
                     keccak_self_test, BYTES_AUTH_SELECTORS, AGGREGATE3)

ROOT = Path(__file__).resolve().parents[1]
SNAP = json.loads((ROOT/'data/example-snapshot.json').read_text())
EXAMPLE = json.loads((ROOT/'data/example.json').read_text())
LOCATOR = {'block_number': 53228028, 'tx_index': 242}


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
                'eth_getTransactionByBlockNumberAndIndex':self.snap['transaction'],
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


class LocatorTests(unittest.TestCase):
    def test_valid_forms_and_normalization_without_rpc(self):
        with patch('transport.http_json', side_effect=AssertionError('validation must be pure')):
            self.assertEqual(validate_input({'tx_hash': '0x'+EXAMPLE_TX[2:].upper()}),
                             {'tx_hash': EXAMPLE_TX, 'expected': {'asset': USDC}})
            for locator in (LOCATOR, {'block_number': 0, 'tx_index': 0}):
                self.assertEqual(validate_input(locator), {**locator, 'expected': {'asset': USDC}})
            for locator in ({'tx_hash': EXAMPLE_TX}, LOCATOR):
                req = validate_input({**locator, 'expected': EXAMPLE['example_request']['expected']})
                self.assertEqual(req['expected'], validate_input(EXAMPLE['example_request'])['expected'])

    def test_invalid_shapes_and_integer_types(self):
        invalid = [None, [], 'tx', {}, {'expected': {}}, {'block_number': 0}, {'tx_index': 0},
                   {'tx_hash': None}, {'tx_hash': EXAMPLE_TX, **LOCATOR},
                   {'tx_hash': EXAMPLE_TX, 'block_number': 0},
                   {'tx_hash': EXAMPLE_TX, 'tx_index': 0}, {**LOCATOR, 'unknown': 1}]
        for field in LOCATOR:
            invalid.extend({**LOCATOR, field: value} for value in (-1, True, False, 1.0, 0.5, '1', None, [], {}))
        for locator in ({'tx_hash': EXAMPLE_TX}, LOCATOR):
            invalid.extend({**locator, 'expected': value} for value in
                           (None, [], {'foo': 1}, {'amount': 1}, {'valid_at': True}))
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_input(value)

    def test_resolution_runs_identical_audit_and_retains_source(self):
        expected = EXAMPLE['example_request']['expected']
        rpc = SnapshotRPC()
        out = audit(validate_input({**LOCATOR, 'expected': expected}), rpc)
        by_hash = audit(validate_input(EXAMPLE['example_request']), SnapshotRPC())
        self.assertEqual(out['tx_hash'], EXAMPLE_TX)
        self.assertEqual(out['locator'], {**LOCATOR, 'rpc': 'mock://snapshot'})
        self.assertEqual(rpc.reads[0], {'method': 'eth_getTransactionByBlockNumberAndIndex',
                         'params': ['0x32c31fc', '0xf2'], 'rpc': 'mock://snapshot'})
        self.assertEqual(rpc.reads[1]['params'], [EXAMPLE_TX])
        for field in set(by_hash)-{'rpc_reads'}:
            self.assertEqual(out[field], by_hash[field], field)

    def test_empty_position_is_not_found_without_receipt_reads(self):
        snap = copy.deepcopy(SNAP); snap['transaction'] = None
        rpc = SnapshotRPC(snap)
        out = audit(validate_input(LOCATOR), rpc)
        self.assertEqual(out['verdict'], 'not_found'); self.assertFalse(out['partial'])
        self.assertIsNone(out['tx_hash']); self.assertEqual(len(rpc.reads), 1)
        self.assertEqual(out['locator'], {**LOCATOR, 'rpc': 'mock://snapshot'})

    def test_resolution_outage_and_post_resolution_outage_are_partial(self):
        for failed_method in ('eth_getTransactionByBlockNumberAndIndex', 'eth_getTransactionReceipt'):
            rpc = SnapshotRPC(); original = rpc.call
            def call(method, params):
                if method == failed_method: raise RemoteError('offline')
                return original(method, params)
            rpc.call = call
            out = audit(validate_input(LOCATOR), rpc)
            self.assertTrue(out['partial']); self.assertIsNone(out['verdict'])
            resolved = failed_method == 'eth_getTransactionReceipt'
            self.assertEqual(out['tx_hash'], EXAMPLE_TX if resolved else None)
            self.assertEqual(out['locator']['rpc'], 'mock://snapshot' if resolved else None)
        fallback = partial_result(validate_input(LOCATOR), 'engine unavailable')
        self.assertIsNone(fallback['tx_hash']); self.assertEqual(fallback['locator'], {**LOCATOR, 'rpc': None})

    def test_inconsistent_rpc_identity_is_partial(self):
        for section, field, value in [('transaction', 'hash', 'invalid'),
                                      ('transaction', 'blockNumber', '0x0'),
                                      ('transaction', 'transactionIndex', '0x0'),
                                      ('receipt', 'blockNumber', '0x0'),
                                      ('receipt', 'transactionIndex', '0x0')]:
            snap = copy.deepcopy(SNAP); snap[section][field] = value
            with self.subTest(section=section, field=field):
                out = audit(validate_input(LOCATOR), SnapshotRPC(snap))
                self.assertTrue(out['partial']); self.assertIsNone(out['verdict'])

    def test_resolution_uses_chain_checked_rpc_fallback(self):
        calls = []
        sources = ['https://offline.test', 'https://wrong-chain.test', 'https://base.test']
        def remote(url, obj, timeout):
            method = obj['method']; calls.append((url, method))
            if url == sources[0]: raise RemoteError('offline')
            if method == 'eth_chainId':
                value = '0x1' if url == sources[1] else '0x2105'
            else:
                self.assertIn((url, 'eth_chainId'), calls)
                value = SnapshotRPC().call(method, obj['params'])
            return 200, {'jsonrpc': '2.0', 'id': 1, 'result': value}
        with patch('transport.http_json', side_effect=remote), patch('transport.time.sleep'):
            out = audit(validate_input(LOCATOR), RPC(sources))
        self.assertEqual(out['verdict'], 'matches', out['errors'])
        self.assertEqual(out['locator']['rpc'], sources[2])
        self.assertEqual(calls.count((sources[1], 'eth_chainId')), 2*len(out['rpc_reads']))
        self.assertNotIn((sources[1], 'eth_getTransactionByBlockNumberAndIndex'), calls)
        self.assertEqual(calls.count((sources[2], 'eth_chainId')), 1)


class LiveReadOnlyTests(unittest.TestCase):
    def test_block_index_resolves_worked_example_on_public_base_rpc(self):
        out = audit(validate_input({**LOCATOR, 'expected': EXAMPLE['example_request']['expected']}))
        self.assertEqual(out['tx_hash'], EXAMPLE_TX, out['errors'])
        self.assertEqual(out['verdict'], 'matches', out['errors'])
        self.assertFalse(out['partial'])
        self.assertEqual(out['locator'], {**LOCATOR, 'rpc': out['rpc_reads'][0]['rpc']})
        self.assertEqual(out['rpc_reads'][0]['method'], 'eth_getTransactionByBlockNumberAndIndex')
        self.assertTrue(out['locator']['rpc'].startswith('https://'))

    def test_worked_example_on_public_base_rpc(self):
        # Only eth_chainId/getTransaction/getReceipt/getBlock/eth_call. No signing or settle.
        out=audit(EXAMPLE['example_request'])
        self.assertEqual(out['verdict'],'matches',out['errors'])
        self.assertFalse(out['partial']);self.assertEqual(out['transaction']['block_number'],53228028)
        self.assertEqual(out['trailing_calldata']['codes'],['cdp_facil1'])
        self.assertTrue(out['authorization_state']['used_or_canceled'])
        self.assertTrue(out['rpc_reads'][0]['rpc'].startswith('https://'))

if __name__=='__main__':unittest.main()
