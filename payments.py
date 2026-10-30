"""Durable x402 v2 exact payment state machine. Never retry an uncertain settle."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from auditor import audit, partial_result, validate_input
from decoder import USDC, address, hex_bytes, AUTH_USED_TOPIC
from transport import http_json, RemoteError, RPC

NETWORK = 'eip155:8453'
PAY_TO = '0x8424f298f5385290567f4adee3e8ab7d7ced9bc7'
ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
PRICE = '10000'
RETENTION = 30*86400


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value): return hashlib.sha256(value.encode()).hexdigest()

def b64(value): return base64.b64encode(canonical(value).encode()).decode()


def requirements():
    return {'scheme': 'exact', 'network': NETWORK, 'amount': PRICE, 'asset': ASSET,
            'payTo': PAY_TO, 'maxTimeoutSeconds': 300, 'extra': {'name': 'USD Coin', 'version': '2'}}


def challenge(base_url, error='Payment required'):
    return {'x402Version': 2, 'error': error,
            'resource': {'url': base_url+'/v1/audit', 'description': 'Independent Base x402 settlement audit',
                         'mimeType': 'application/json'}, 'accepts': [requirements()]}


def parse_payment(header, base_url):
    if not isinstance(header, str) or len(header) > 16384: raise ValueError('payment header too large')
    try:
        obj = json.loads(base64.b64decode(header, validate=True))
        if obj['x402Version'] != 2: raise ValueError('x402Version must be 2')
        accepted = obj['accepted']; want = requirements()
        for k, v in want.items():
            actual = accepted[k]
            if k in ('asset', 'payTo'): actual, v = address(actual), address(v)
            if actual != v: raise ValueError('accepted requirements differ from challenge')
        if obj.get('resource') and obj['resource'].get('url') != base_url+'/v1/audit':
            raise ValueError('payment resource URL differs from challenge')
        a = obj['payload']['authorization']
        payer = address(a['from']); address(a['to']); hex_bytes(a['nonce'], 32)
        for k in ('value', 'validAfter', 'validBefore'):
            if not isinstance(a[k], str) or not re.fullmatch(r'0|[1-9][0-9]{0,77}', a[k]) or int(a[k]) >= 2**256:
                raise ValueError('invalid authorization number')
        if address(a['to']) != PAY_TO or a['value'] != PRICE or int(a['validAfter']) >= int(a['validBefore']):
            raise ValueError('authorization does not match price/payee or has invalid bounds')
        sig = hex_bytes(obj['payload']['signature'])
        if not 64 <= len(sig) <= 2048: raise ValueError('invalid signature length')
        key = USDC+':'+payer+':'+a['nonce'].lower()
        return obj, key, digest(canonical(obj)), digest(header)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise ValueError('malformed or unsupported x402 v2 exact payment') from None


class Facilitators:
    def __init__(self, urls):
        self.urls = tuple(urls)
        self.support = {}
        for url in self.urls:
            try:
                status, obj = http_json(url+'/supported', timeout=6)
                self.support[url] = status == 200 and any(
                    k.get('x402Version') == 2 and k.get('scheme') == 'exact' and k.get('network') == NETWORK
                    for k in obj.get('kinds', []))
            except Exception: self.support[url] = False

    def verify(self, payload):
        for url in self.urls:
            if not self.support[url]: continue
            try:
                status, obj = http_json(url+'/verify', {'x402Version': 2, 'paymentPayload': payload,
                                                        'paymentRequirements': requirements()}, timeout=12)
                if status >= 500 or status == 429: continue
                if obj.get('isValid') is not True: return None, 'payment_verification_failed'
                if obj.get('payer') and address(obj['payer']) != address(payload['payload']['authorization']['from']):
                    return None, 'facilitator_payer_mismatch'
                return url, None
            except (RemoteError, ValueError): continue
        return None, 'facilitator_unavailable'

    def settle(self, url, payload):
        status, obj = http_json(url+'/settle', {'x402Version': 2, 'paymentPayload': payload,
                                                'paymentRequirements': requirements()}, timeout=25)
        if status >= 500 or status == 429: raise RemoteError('uncertain facilitator settlement')
        return obj


class PaymentStore:
    def __init__(self, path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_dir = self.path.parent/'locks'; self.lock_dir.mkdir(exist_ok=True)
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('''CREATE TABLE IF NOT EXISTS payments (
                nonce_key TEXT PRIMARY KEY, payment_hash TEXT NOT NULL UNIQUE,
                header_hash TEXT NOT NULL, body_hash TEXT NOT NULL, body TEXT,
                authorization TEXT NOT NULL, created REAL NOT NULL, completed REAL,
                state TEXT NOT NULL, facilitator TEXT, start_block INTEGER,
                scan_block INTEGER, settlement TEXT, result TEXT, error TEXT)''')
        os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def cleanup(self):
        with self.connect() as db:
            db.execute("UPDATE payments SET state='expired', body=NULL, result=NULL WHERE COALESCE(completed,created) < ? AND state!='expired'",
                       (time.time()-RETENTION,))

    def get(self, key):
        self.cleanup()
        with self.connect() as db:
            row = db.execute('SELECT * FROM payments WHERE nonce_key=?', (key,)).fetchone()
            return dict(row) if row else None

    def update(self, key, **values):
        # Field names come exclusively from the implementation, never HTTP input.
        with self.connect() as db:
            db.execute('UPDATE payments SET '+','.join(k+'=?' for k in values)+' WHERE nonce_key=?', (*values.values(), key))

    def reserve(self, key, ph, hh, bh, body, auth, facilitator, start_block):
        with self.connect() as db:
            db.execute('INSERT INTO payments (nonce_key,payment_hash,header_hash,body_hash,body,authorization,created,state,facilitator,start_block,scan_block) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                (key, ph, hh, bh, canonical(body), canonical(auth), time.time(), 'settling', facilitator, start_block, max(0, start_block-2)))

    @contextlib.contextmanager
    def lock(self, key):
        # 256 bounded lock stripes, shared across threads AND independent processes.
        path = self.lock_dir/(digest(key)[:2]+'.lock')
        with open(path, 'a') as f:
            try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False; return
            try: yield True
            finally: fcntl.flock(f, fcntl.LOCK_UN)


class PaymentService:
    def __init__(self, store, facilitators, base_url, audit_fn=audit, rpc_factory=RPC):
        self.store, self.facilitators, self.base_url = store, facilitators, base_url
        self.audit_fn, self.rpc_factory = audit_fn, rpc_factory

    def required(self, error='Payment required'):
        obj = challenge(self.base_url, error)
        return 402, obj, {'PAYMENT-REQUIRED': b64(obj)}

    def pending(self):
        return 202, {'status': 'pending', 'message': 'Retry identical input with the original payment header; do not pay again.'}, {'Retry-After': '15'}

    def process(self, original, header=None):
        # All business input validation precedes payment parsing, verify, persistence, settle.
        try: request = validate_input(original)
        except (ValueError, TypeError) as exc: return 400, {'error': str(exc)}, {}
        if not header: return self.required()
        try: payload, key, ph, hh = parse_payment(header, self.base_url)
        except ValueError as exc: return self.required(str(exc))
        bh = digest(canonical(original))
        row = self.store.get(key)
        if row and (row['body_hash'] != bh or row['payment_hash'] != ph):
            return 409, {'error': 'payment nonce is already bound to a different request or authorization'}, {}
        with self.store.lock(key) as locked:
            if not locked: return self.pending()
            row = self.store.get(key)
            if row:
                if row['body_hash'] != bh or row['payment_hash'] != ph:
                    return 409, {'error': 'payment nonce is already bound to a different request or authorization'}, {}
                if row['state'] == 'expired': return 410, {'error': 'result expired; original payment cannot be reused'}, {}
                if row['state'] == 'done': return self.delivered(row)
                if row['state'] == 'failed': return self.required(row['error'] or 'settlement_failed')
                if row['state'] == 'settling':
                    try: self.reconcile(key, row)
                    except Exception: return self.pending()
                    row = self.store.get(key)
                    if row['state'] == 'settling': return self.pending()
                    if row['state'] == 'failed': return self.required(row['error'])
                # Resume the normalized input committed before settlement, in either locator form.
                return self.finish(key, json.loads(row['body']))
            now = int(time.time()); a = payload['payload']['authorization']
            if not int(a['validAfter']) < now < int(a['validBefore']) or int(a['validBefore']) > now+300:
                return self.required('authorization_expired_or_outside_300_second_timeout')
            url, error = self.facilitators.verify(payload)
            if error: return self.required(error)
            try: start = int(self.rpc_factory().call('eth_blockNumber', []), 16)
            except Exception: return 503, {'error': 'payment RPC unavailable before settlement; no payment attempted'}, {'Retry-After': '15'}
            self.store.reserve(key, ph, hh, bh, request, a, url, start)
            try:
                settlement = self.facilitators.settle(url, payload)
                transaction = settlement.get('transaction', '')
                if transaction and not re.fullmatch(r'0x[0-9a-fA-F]{64}', transaction):
                    raise RemoteError('malformed settlement transaction')
                if settlement.get('success') is True:
                    if not transaction or settlement.get('network') != NETWORK:
                        raise RemoteError('malformed settlement receipt')
                    if settlement.get('payer') and address(settlement['payer']) != address(a['from']):
                        raise RemoteError('settlement payer mismatch')
                    response = {'success': True, 'network': NETWORK, 'transaction': transaction,
                                'payer': address(a['from'])}
                    self.store.update(key, state='settled', settlement=canonical(response))
                elif settlement.get('success') is False and not transaction and settlement.get('errorReason') != 'settlement_pending':
                    self.store.update(key, state='failed', error='settlement_failed', completed=time.time())
                    return self.required('settlement_failed')
                else:
                    if transaction:
                        self.store.update(key, settlement=canonical({'transaction': transaction}))
                    return self.pending()
            except Exception:
                # A timeout may occur after broadcast. Persisted settling state is NEVER resubmitted.
                return self.pending()
            return self.finish(key, request)

    def delivered(self, row):
        return 200, json.loads(row['result']), {'PAYMENT-RESPONSE': b64(json.loads(row['settlement']))}

    def finish(self, key, request):
        row = self.store.get(key)
        try: result = self.audit_fn(request)
        except Exception: result = partial_result(request, 'audit engine unavailable after payment')
        if len(canonical(result).encode()) > 480000:
            identity = {k: result[k] for k in ('tx_hash', 'locator') if k in result}
            result = {**partial_result(request, 'audit evidence exceeds the 480000-byte output limit'), **identity}
        self.store.update(key, state='done', result=canonical(result), completed=time.time())
        return self.delivered(self.store.get(key))

    def reconcile(self, key, row):
        """Find the original nonce on-chain, validate its receipt, and never call settle."""
        rpc = self.rpc_factory(); a = json.loads(row['authorization'])
        receipt = json.loads(row['settlement']) if row['settlement'] else {}
        hashes = [receipt['transaction']] if receipt.get('transaction') else []
        if not hashes:
            latest = int(rpc.call('eth_blockNumber', []), 16)
            cursor = row['scan_block']
            # Bounded work per retry; cursors persist. Small ranges work on public RPC limits.
            for _ in range(4):
                if cursor > latest: break
                end = min(latest, cursor+499)
                logs = rpc.call('eth_getLogs', [{'address': USDC, 'fromBlock': hex(cursor), 'toBlock': hex(end),
                    'topics': [AUTH_USED_TOPIC, '0x'+address(a['from'])[2:].rjust(64,'0'), a['nonce'].lower()]}])
                hashes.extend(log['transactionHash'] for log in logs if not log.get('removed'))
                cursor = end+1
                # Keep a short overlap at the live head to tolerate shallow reorgs.
                self.store.update(key, scan_block=max(row['start_block']-2, cursor-12) if cursor>latest else cursor)
                if hashes: break
        if hashes and not receipt.get('transaction'):
            # Persist the discovered hash before any further RPC. Otherwise a read
            # failure could advance the cursor past the only matching event.
            self.store.update(key, settlement=canonical({'transaction': hashes[0]}))
        for h in dict.fromkeys(hashes):
            # This hash identifies the API fee, independently of the stored audit locator.
            req = validate_input({'tx_hash': h, 'expected': {'pay_to': PAY_TO, 'amount': PRICE, 'payer': a['from']}})
            result = audit(req, rpc)
            if result.get('verdict') == 'matches' and result['selected']['event']['nonce'].lower() == a['nonce'].lower():
                response = {'success': True, 'network': NETWORK, 'transaction': h, 'payer': address(a['from'])}
                self.store.update(key, state='settled', settlement=canonical(response)); return
        if not hashes and time.time() > int(a['validBefore']):
            # A persisted intent can precede a crash without ever reaching the
            # facilitator. Only finalized, expired-and-unused evidence resolves
            # that uncertainty as unpaid. Wall clock alone is insufficient.
            block = rpc.call('eth_getBlockByNumber', ['finalized', False])
            if block and int(block['timestamp'], 16) > int(a['validBefore']):
                from auditor import AUTH_STATE_SELECTOR
                data = AUTH_STATE_SELECTOR + address(a['from'])[2:].rjust(64, '0') + a['nonce'][2:]
                state = rpc.call('eth_call', [{'to': USDC, 'data': data},
                    {'blockHash': block['hash'], 'requireCanonical': True}])
                if hex_bytes(state, 32) == bytes(32):
                    self.store.update(key, state='failed', error='authorization_expired_unused', completed=time.time())
