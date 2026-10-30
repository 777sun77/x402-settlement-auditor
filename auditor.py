"""Read-only Base settlement engine; no private keys or transaction submission."""
import datetime
import re
from collections import Counter
from decoder import (USDC, AUTH_USED_TOPIC, TRANSFER_TOPIC, address, hex_bytes,
                     decode_logs, find_calls, topic)
from transport import RPC

AUTH_STATE_SELECTOR = topic('authorizationState(address,bytes32)')[:10]
EXAMPLE_TX = '0x389a08dba01e0d65999b775cd9724d73d82bd3908ae5666ae631ef87e4dfde99'


def validate_input(obj):
    if not isinstance(obj, dict) or set(obj)-{'tx_hash', 'block_number', 'tx_index', 'expected'}:
        raise ValueError('body must contain tx_hash OR block_number and tx_index, plus optional expected only')
    fields = set(obj)-{'expected'}
    if fields == {'tx_hash'}:
        tx = obj['tx_hash']
        if not isinstance(tx, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', tx):
            raise ValueError('tx_hash must be 0x followed by 64 hex digits')
        locator = {'tx_hash': tx.lower()}
    elif fields == {'block_number', 'tx_index'}:
        for k in ('block_number', 'tx_index'):
            if type(obj[k]) is not int or obj[k] < 0:
                raise ValueError(k+' must be a nonnegative integer')
        locator = {k: obj[k] for k in ('block_number', 'tx_index')}
    else:
        raise ValueError('provide exactly one of tx_hash OR both block_number and tx_index')
    exp = obj.get('expected', {})
    if not isinstance(exp, dict) or set(exp)-{'pay_to', 'amount', 'asset', 'payer', 'valid_at'}:
        raise ValueError('expected has unknown fields or is not an object')
    out = dict(exp)
    for k in ('pay_to', 'asset', 'payer'):
        if k in exp: out[k] = address(exp[k])
    out.setdefault('asset', USDC)
    if 'amount' in exp:
        a = exp['amount']
        if not isinstance(a, str) or not re.fullmatch(r'0|[1-9][0-9]{0,77}', a) or int(a) >= 2**256:
            raise ValueError('amount must be a canonical uint256 atomic-unit string')
    if 'valid_at' in exp and (type(exp['valid_at']) is not int or not 0 <= exp['valid_at'] < 2**64):
        raise ValueError('valid_at must be a nonnegative integer Unix second below 2^64')
    return {**locator, 'expected': out}


def request_identity(request):
    identity = {'tx_hash': request.get('tx_hash')}
    if 'block_number' in request:
        identity['locator'] = {'block_number': request['block_number'],
                               'tx_index': request['tx_index'], 'rpc': None}
    return identity


def partial_result(request, error):
    return {**request_identity(request), 'network': 'eip155:8453', 'verdict': None,
            'partial': True, 'errors': [error], 'checks': unchecked_fields(request['expected']),
            'warning': 'Inconclusive. Recover with the identical input and payment header; do not pay again.'}


def unchecked_fields(expected):
    return {k: {'status': 'not_checked', **({'expected': expected[k]} if k in expected else {})}
            for k in ('pay_to', 'amount', 'asset', 'payer', 'valid_at')}


def check_fields(payment, call, exp):
    actual = {'pay_to': payment['to'], 'payer': payment['from'],
              'amount': payment['value'], 'asset': USDC}
    checks = {}
    for k in ('pay_to', 'amount', 'asset', 'payer', 'valid_at'):
        if k not in exp:
            checks[k] = {'status': 'not_checked'}
        elif k == 'valid_at':
            ok = call['validAfter'] < exp[k] < call['validBefore'] if call else None
            checks[k] = {'status': 'not_checked' if ok is None else 'pass' if ok else 'fail',
                         'expected': exp[k], 'actual': None if not call else
                         {'validAfter': call['validAfter'], 'validBefore': call['validBefore']}}
        else:
            checks[k] = {'status': 'pass' if exp[k] == actual[k] else 'fail',
                         'expected': exp[k], 'actual': actual[k]}
    return checks


def audit(request, rpc=None):
    rpc = rpc or RPC()
    result = {**request_identity(request), 'network': 'eip155:8453', 'partial': False,
              'verdict': None, 'expected': request['expected'], 'checks': unchecked_fields(request['expected']),
              'errors': [], 'warnings': [], 'rpc_reads': rpc.reads,
              'scope': 'On-chain EIP-3009 settlement evidence; off-chain x402 challenge provenance is not authenticated.'}
    try:
        result['transaction'] = {'status': 'not_found', 'block_number': None, 'block_hash': None, 'timestamp': None}
        if 'locator' in result:
            tx = rpc.call('eth_getTransactionByBlockNumberAndIndex',
                          [hex(request['block_number']), hex(request['tx_index'])])
            result['locator']['rpc'] = rpc.reads[-1]['rpc']
            if tx is None:
                result['verdict'] = 'not_found'; return result
            h = tx.get('hash')
            if not isinstance(h, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', h):
                raise ValueError('RPC returned an invalid transaction hash')
            h = result['tx_hash'] = h.lower()
            if (int(tx['blockNumber'], 16) != request['block_number']
                or int(tx['transactionIndex'], 16) != request['tx_index']):
                raise ValueError('RPC transaction locator mismatch')
        else:
            h = request['tx_hash']
            tx = rpc.call('eth_getTransactionByHash', [h])
        receipt = rpc.call('eth_getTransactionReceipt', [h])
        if tx is None and receipt is None:
            result['verdict'] = 'not_found'; return result
        if not tx or not receipt or not receipt.get('blockNumber'):
            result['transaction']['status'] = 'pending'
            result['partial'] = True; result['errors'].append('transaction or receipt pending/unavailable'); return result
        if 'locator' in result and (int(receipt['blockNumber'], 16) != request['block_number']
                                   or int(receipt['transactionIndex'], 16) != request['tx_index']):
            raise ValueError('RPC receipt locator mismatch')
        block = rpc.call('eth_getBlockByNumber', [receipt['blockNumber'], False])
        if (not block or tx.get('hash', '').lower() != h or receipt.get('transactionHash', '').lower() != h
            or tx.get('blockHash') != receipt.get('blockHash') or receipt.get('blockHash') != block.get('hash')
            or tx.get('blockNumber') != receipt.get('blockNumber') or receipt.get('blockNumber') != block.get('number')):
            raise ValueError('RPC transaction/receipt/block identity mismatch')
        number = int(block['number'], 16); timestamp = int(block['timestamp'], 16)
        result['transaction'] = {'status': 'success' if int(receipt['status'],16) == 1 else 'failed',
                                 'block_number': number, 'block_hash': block['hash'], 'timestamp': timestamp,
                                 'timestamp_utc': datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat(),
                                 'sender': tx.get('from'), 'target': tx.get('to')}
        if int(receipt['status'], 16) not in (0, 1):
            raise ValueError('unsupported receipt status')
        if int(receipt['status'], 16) == 0:
            calls, warnings, trailing = find_calls(tx)
            for c in calls: c['value'] = str(c['value'])
            result.update(decoded_calls=calls, trailing_calldata=trailing, usdc_transfers=[])
            result['warnings'].extend(warnings)
            result['verdict'] = 'failed_tx'; return result
        events = decode_logs(receipt['logs'])
        transfers = events['transfers']; used = events['authorizations_used']
        # Public atomic amounts are strings to preserve uint256 precision for JSON clients.
        for t in transfers: t['value'] = str(t['value'])
        result.update(usdc_transfers=transfers, authorization_events=used,
                      canceled_authorizations=events['authorizations_canceled'])
        if events['errors']: raise ValueError('malformed USDC logs: '+ '; '.join(events['errors']))
        calls, warnings, trailing = find_calls(tx)
        result.update(decoded_calls=calls, trailing_calldata=trailing)
        result['warnings'].extend(warnings)
        if trailing['format'] == 'raw': result['warnings'].append('Unrecognized trailing calldata is informational and does not invalidate a payment')
        for c in calls: c['value'] = str(c['value'])
        candidates = []
        for t in transfers:
            for u in used:
                if t['from'] != u['authorizer']: continue
                bound = [c for c in calls if (c['from'], c['to'], c['value'], c['nonce']) ==
                         (t['from'], t['to'], t['value'], u['nonce']) and
                         c['target'] in (USDC, None)]
                for c in bound:
                    candidates.append({'transfer': t, 'event': u, 'call': c, 'evidence': 'calldata_and_receipt'})
                # An unknown wrapper can be supported by one unambiguous Transfer + AuthorizationUsed pair.
                if not bound and not calls and len(transfers) == len(used) == 1:
                    candidates.append({'transfer': t, 'event': u, 'call': None, 'evidence': 'receipt_only'})
        if not candidates:
            result['verdict'] = 'not_an_x402_settlement'
            result['warnings'].append('Transfer alone or unexecuted authorization calldata is insufficient evidence')
            return result
        for c in candidates: c['checks'] = check_fields(c['transfer'], c['call'], request['expected'])
        matches = [c for c in candidates if all(v['status'] != 'fail' for v in c['checks'].values())]
        pool = matches or candidates
        # Duplicate selector hints cannot make an otherwise identical payment ambiguous.
        unique = {(c['transfer']['logIndex'], c['event']['nonce']): c for c in pool}
        if len(unique) != 1:
            result['partial'] = True; result['errors'].append('multiple settlement candidates; supply payer/pay_to/amount to disambiguate')
            return result
        selected = next(iter(unique.values()))
        result['selected'] = selected; result['checks'] = selected['checks']
        call = selected['call']; auth = selected['event']
        if call:
            result['checks']['valid_at_block'] = {'status': 'pass' if call['validAfter'] < timestamp < call['validBefore'] else 'fail', 'actual': timestamp}
        else:
            result['warnings'].append('Receipt fallback cannot recover authorization validity bounds')
        data = AUTH_STATE_SELECTOR + auth['authorizer'][2:].rjust(64, '0') + auth['nonce'][2:]
        params = [{'to': USDC, 'data': data}, {'blockHash': block['hash'], 'requireCanonical': True}]
        raw_state = rpc.call('eth_call', params)
        state_bytes = hex_bytes(raw_state, 32)
        state_int = int.from_bytes(state_bytes, 'big')
        if state_int not in (0, 1): raise ValueError('invalid authorizationState bool')
        result['authorization_state'] = {'authorizer': auth['authorizer'], 'nonce': auth['nonce'],
            'used_or_canceled': bool(state_int), 'block_number': number, 'block_hash': block['hash'],
            'rpc': rpc.reads[-1]['rpc'], 'eth_call': params}
        result['checks']['authorization_state'] = {'status': 'pass' if state_int else 'fail'}
        statuses = [v['status'] for v in result['checks'].values()]
        if 'fail' in statuses: result['verdict'] = 'mismatch'
        elif any(result['checks'][k]['status'] == 'not_checked' for k in request['expected']):
            result['partial'] = True; result['errors'].append('requested field cannot be checked with available evidence')
        else: result['verdict'] = 'matches'
        return result
    except Exception as exc:
        # RPC exceptions contain only sanitized diagnostics. No payment input enters this engine.
        result.update(partial=True, verdict=None)
        result['errors'].append('%s: %s' % (type(exc).__name__, str(exc)[:300]))
        return result
