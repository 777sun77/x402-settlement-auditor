#!/usr/bin/env python3
"""x402 Settlement Auditor (Base). Start with python3 server.py; stdlib + system curl."""
import hashlib
import html
import json
import os
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from auditor import EXAMPLE_TX
from payments import PaymentService, PaymentStore, Facilitators, NETWORK, PAY_TO, PRICE

VERSION = '1.0.0'
ROOT = Path(__file__).resolve().parent


def config_base():
    base = os.environ.get('PUBLIC_BASE_URL', 'http://127.0.0.1:8787')
    parsed = urlsplit(base)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.query or parsed.fragment or parsed.username or parsed.password or base.endswith('/'):
        raise ValueError('PUBLIC_BASE_URL must be an absolute http(s) base URL without credentials, query, fragment or trailing slash')
    return base


def fingerprint():
    files = ('server.py', 'auditor.py', 'decoder.py', 'payments.py', 'transport.py')
    checksums = {f: hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in files}
    try:
        p = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=2)
        sha = p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired): sha = None
    return {'version': VERSION, 'git_sha': sha, 'server_sha256': checksums['server.py'], 'code_sha256': checksums}


def page(title, content):
    return '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>'''+html.escape(title)+''' · x402 Settlement Auditor</title><style>
:root{color-scheme:dark;--ink:#e8f1f3;--muted:#9eafb9;--line:#2b3a45;--accent:#7ce8cf}*{box-sizing:border-box}body{margin:0;background:#0d1720;color:var(--ink);font:16px/1.65 system-ui,sans-serif}main,nav,footer{max-width:980px;margin:auto;padding:24px}nav{display:flex;gap:22px;border-bottom:1px solid var(--line);flex-wrap:wrap}a{color:var(--accent)}nav a{text-decoration:none}nav .brand{margin-right:auto;color:var(--ink);font-weight:700}h1{font-size:clamp(2rem,5vw,3.6rem);line-height:1.12;letter-spacing:-.04em;margin:38px 0 20px}h2{margin-top:36px;font-size:1.35rem}p{max-width:780px}small,.muted{color:var(--muted)}.tag{font:12px ui-monospace,monospace;letter-spacing:.12em;color:var(--accent)}.panel{border:1px solid var(--line);padding:22px;border-radius:12px;background:#12212c;margin:24px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,monospace;background:#081119;padding:20px;border:1px solid var(--line);border-radius:8px}code{overflow-wrap:anywhere;color:#a6e9db}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}footer{border-top:1px solid var(--line);font-size:13px;margin-top:40px}.button{display:inline-block;border:1px solid var(--accent);border-radius:6px;padding:9px 17px;text-decoration:none;margin-right:12px}ul{padding-left:22px}</style>
<nav><a class="brand" href="/">x402 / Settlement Auditor</a><a href="/guide">Guide</a><a href="/example">Example JSON</a><a href="/terms">Terms</a><a href="/health">Health</a></nav><main>'''+content+'''</main><footer>Base mainnet · Native USDC · 0.01 USDC per audit<br>Charlie (Speedbot agent) / GitHub 777sun77</footer></html>'''


def home():
    return page('Independent settlement evidence', '''<div class="tag">BASE MAINNET / PAYMENT EVIDENCE</div><h1>A transaction hash is a claim.<br>Check what actually settled.</h1><p>For agents and merchants checking an x402 exact payment: compare the payer, recipient, atomic amount, token and authorization window against your original 402 challenge.</p><div class="panel"><strong>One POST. Reproducible evidence.</strong><p>Decode EIP-3009 authorizations, bind them to USDC receipt logs, query nonce state at the settlement block, and read ERC-8021 builder attribution.</p><code>POST /v1/audit · 0.01 USDC · eip155:8453</code></div><p><a class="button" href="/guide">Read the integration guide</a><a href="/example">Inspect a real computed audit →</a></p><h2>Evidence you can inspect</h2><p>Each completed audit includes field-level checks, emitted transfers, block identity and the RPC source for every read. A partial result explicitly marks uncertainty. Attribution suffixes are informational.</p><p class="muted">On-chain authorization evidence supports a settlement check. It cannot prove which off-chain challenge was shown or that purchased content was delivered.</p>''')


def guide(base):
    example = json.loads((ROOT/'data/example.json').read_text())
    request = example['example_request']
    req = html.escape(json.dumps(request, indent=2))
    snippet = html.escape(json.dumps({k: example[k] for k in ('verdict','partial','checks','transaction','trailing_calldata')}, indent=2))
    endpoint = html.escape(base+'/v1/audit')
    return page('Integration guide', f'''<div class="tag">INTEGRATION GUIDE / V{VERSION}</div><h1>Audit an alleged x402 settlement.</h1><p>Use this API when a buyer provides a Base mainnet transaction hash and you want independent evidence that its EIP-3009 payment matches your challenge. Supply all available expected fields to narrow the claim.</p>
<h2>Price and payment</h2><p>Each audit costs <strong>0.01 USDC</strong> (10,000 atomic units). Network: <code>eip155:8453</code>. Asset: <code>{html.escape('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913')}</code>. Payee: <code>{PAY_TO}</code>. Timeout: 300 seconds. This is the direct API price; Speedbot may display its marketplace commission separately.</p><p>Send a valid request to <code>{endpoint}</code>. Without payment it returns HTTP 402, an x402 v2 PaymentRequired JSON body and the identical JSON base64-encoded in <code>PAYMENT-REQUIRED</code>. Your wallet signs the native USDC EIP-3009 exact authorization. Retry the identical input with <code>PAYMENT-SIGNATURE</code> (legacy header name <code>X-PAYMENT</code> is also accepted; its payload must still be v2). Do not send a plain token transfer. This service never requests a private key.</p>
<h2>Request schema</h2><table><tr><th>Field</th><th>Type / meaning</th></tr><tr><td>tx_hash</td><td>Required 0x + 64 hex digits. Base mainnet only.</td></tr><tr><td>expected</td><td>Optional object; omitted fields are not_checked. Unknown fields are rejected.</td></tr><tr><td>expected.pay_to / payer</td><td>Optional 20-byte 0x addresses, compared case-insensitively.</td></tr><tr><td>expected.amount</td><td>Optional canonical unsigned uint256 decimal string in atomic units (6 decimals for USDC).</td></tr><tr><td>expected.asset</td><td>Optional address; defaults to Base native USDC. Other assets fail the asset check; this engine decodes USDC only.</td></tr><tr><td>expected.valid_at</td><td>Optional integer Unix second, 0 ≤ t &lt; 2^64. Checks validAfter &lt; t &lt; validBefore, not equality to block time.</td></tr></table>
<h2>Worked example: real Base mainnet settlement</h2><p><a href="https://basescan.org/tx/{EXAMPLE_TX}">{EXAMPLE_TX}</a> settled 0.01 USDC in block 53,228,028. Its schema-2 CBOR attribution contains <code>cdp_facil1</code>. The expected values below describe that historical payment; its recipient is distinct from this API’s payee.</p><pre>{req}</pre><p>Inspect the full audit at <a href="/example">GET /example</a>. It was computed by the same engine against public Base RPC and committed as a startup-independent cache. It is free and makes no payment.</p><pre>{snippet}</pre>
<h2>Response schema</h2><p>A successful paid request returns the audit object directly, plus <code>PAYMENT-RESPONSE</code>: base64 JSON with <code>success, network, transaction, payer</code>. That transaction pays for this API call; <code>tx_hash</code> inside the audit is the historical transaction being inspected.</p><table><tr><th>Field</th><th>Meaning</th></tr><tr><td>verdict</td><td>matches | mismatch | not_an_x402_settlement | failed_tx | not_found. Null when partial and inconclusive.</td></tr><tr><td>partial / errors / warnings</td><td>Boolean completeness flag and diagnostic arrays. An RPC outage after payment returns 200 with partial=true and error details.</td></tr><tr><td>transaction</td><td>Status, block number/hash, Unix/UTC timestamp, transaction sender and target.</td></tr><tr><td>decoded_calls / selected</td><td>Direct authorization, nested aggregate3 calls, or wrapper selector hints. Selected evidence binds from/to/value/nonce to actual USDC Transfer and AuthorizationUsed events. value is an atomic-unit string; validAfter/validBefore are Unix seconds; nonce is bytes32.</td></tr><tr><td>authorization_state</td><td>authorizationState(authorizer,nonce), block hash/number, source RPC and exact eth_call parameters. True means used or canceled; AuthorizationUsed receipt evidence distinguishes use.</td></tr><tr><td>usdc_transfers / authorization_events</td><td>Actually emitted logs, including receipt log index. Plain Transfer alone cannot prove EIP-3009 settlement.</td></tr><tr><td>checks</td><td>Each expected field has status pass/fail/not_checked, expected and actual where available. Includes block validity and nonce-state checks.</td></tr><tr><td>trailing_calldata</td><td>Raw trailing hex, format none/raw/erc8021, schema_id, codes and decoded fields when supported. Unknown or malformed suffixes never reject payment.</td></tr><tr><td>rpc_reads</td><td>Source URL, method and parameters for each successful read. Chain identity is checked for every source. Historical eth_call is pinned by block hash with requireCanonical.</td></tr></table>
<h2>Verdicts and limits</h2><p><code>matches</code> means the selected on-chain authorization settlement matches all supplied expectations. With no expectations, only the default asset and settlement evidence are checked. <code>mismatch</code> means a field or evidence check failed. <code>not_an_x402_settlement</code> means no supported authorization settlement was established; it is not proof of absence under every contract ABI. <code>not_found</code> means the source has no transaction/receipt. Pending or ambiguous transactions return a partial result with a null verdict.</p><p>USDC transferWithAuthorization and receiveWithAuthorization (v/r/s and bytes overloads) and nested Multicall3 aggregate3 are decoded. Unknown facilitator contracts use receipt-bound selector hints or an unambiguous Transfer + AuthorizationUsed log fallback; validity bounds may be unavailable. Attribution supports schema 0, 1 and bounded schema-2 CBOR; unknown CBOR types remain raw. Unknown-wrapper ABI boundaries cannot establish a suffix boundary. Calldata decoding is capped at 32 KiB and eight nested calls. Large/unsupported transactions may be inconclusive.</p><p>Request limit: 32,000 UTF-8 bytes; payment header: 16 KiB; maximum 32 simultaneous connections. Audit output is capped at 480,000 bytes; larger evidence returns an explicitly partial result. No bulk audit endpoint. Public RPCs have timeouts, retries and rate limits. This is a block snapshot, not a finality guarantee or a cross-provider quorum. A confirmed transfer cannot prove the original x402 challenge, facilitator identity, fair value, delivery or legal entitlement.</p>
<h2>Errors and recovery</h2><table><tr><th>HTTP</th><th>Behavior</th></tr><tr><td>200</td><td>Paid audit, including negative verdicts or partial results after settlement. A cached retry returns the stored object and original PAYMENT-RESPONSE.</td></tr><tr><td>202</td><td>Concurrent or uncertain settlement. Numeric Retry-After: 15. Retry identical input and the original payment header. Never create a new payment to recover.</td></tr><tr><td>400 / 413 / 415</td><td>Invalid input, oversized body, unsupported media type. Validation precedes settlement; no charge.</td></tr><tr><td>402</td><td>Payment missing, invalid, unavailable or definitively failed settlement. No audit output is released.</td></tr><tr><td>409</td><td>Nonce reused with a different input or authorization. No second settlement.</td></tr><tr><td>410</td><td>30-day result retention expired. The nonce remains blocked and does not start another charge.</td></tr><tr><td>503</td><td>Service busy or pre-settlement RPC unavailable; no settlement attempted. Retry the same authorization.</td></tr></table>
<p>Payment state is committed to SQLite before settlement. Identical paid retries are serialized across threads/processes. After an uncertain settlement or restart, the service scans for the original authorizer/nonce and verifies its receipt. It never resubmits an uncertain settlement, including through the fallback facilitator. Recovery scans at most 2,000 blocks per retry and retain progress; a long outage can require several retries. An unresolved attempt stays pending until chain evidence is available; expired-and-unused nonce state at a finalized block can resolve it as unpaid without resubmission. A stored partial result is replayed as stored. Do not pay twice for a failed RPC read.</p><p>Input and output are retained for 30 days. Nonce/hash and payment receipt tombstones remain for replay prevention. See <a href="/terms">provider terms</a> and contact Speedbot for recovery support.</p><h2>Protocol references</h2><p><a href="https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md">x402 v2 types and facilitator interface</a> · <a href="https://github.com/x402-foundation/x402/blob/main/specs/extensions/builder_code.md">Builder-code schema 2</a> · <a href="https://blog.base.dev/builder-codes-and-erc-8021-fixing-onchain-attribution">Base attribution format</a></p>''')


def terms():
    return page('Provider terms', '''<div class="tag">PROVIDER TERMS</div><h1>Terms of service</h1><p>Operator: <strong>Charlie (Speedbot agent) / GitHub 777sun77</strong>.</p><p>Content is informational. Audits describe observed public-chain evidence and user-supplied expectations. They are not financial, legal or security advice. There is no warranty of accuracy, completeness, availability, fitness or finality. Public RPC and facilitator services can fail or return inconsistent data.</p><h2>Pricing and refunds</h2><p>The direct price is 0.01 native USDC on Base mainnet per accepted audit. Validation errors are not charged: validation occurs before settlement. Missing or invalid payments do not deliver output. A paid audit can report a mismatch, failed transaction, missing transaction or an explicitly partial result after an RPC failure. Recovery with the original authorization does not incur another settlement. For disputed delivery or payment recovery, contact Speedbot; this service has no automatic outbound refund signer.</p><h2>Data and recovery</h2><p>Working input and audit results are retained for 30 days. Payment nonces, input/header hashes, public authorization fields and receipts remain as financial/replay-prevention records. Full payment headers and signatures are not logged or retained. After expiry, recovery returns HTTP 410 and never charges again with that payment. Public example data is retained as documentation.</p><h2>Contact</h2><p>Contact via <a href="https://speedbot.dev">Speedbot</a> for provider support and recovery, or email <a href="mailto:contact@speedbot.dev">contact@speedbot.dev</a>.</p>''')


class Handler(BaseHTTPRequestHandler):
    server_version = 'x402-auditor/'+VERSION
    sys_version = ''

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, fmt, *args):
        # Never log headers, bodies, arbitrary URLs, or facilitator echo text.
        pass

    def reply(self, status, obj, headers=None, is_html=False):
        body = obj.encode('utf-8') if is_html else json.dumps(obj, separators=(',', ':'), ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if is_html else 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass

    def do_GET(self):
        try:
            if self.path == '/': self.reply(200, home(), is_html=True)
            elif self.path == '/guide': self.reply(200, guide(self.server.service.base_url), is_html=True)
            elif self.path == '/terms': self.reply(200, terms(), is_html=True)
            elif self.path == '/example': self.reply(200, self.server.example)
            elif self.path == '/health': self.reply(200, {'ok': True, 'network': NETWORK, 'price': PRICE,
                'price_usdc': '0.01', 'pay_to': PAY_TO, **self.server.identity,
                'facilitators': getattr(self.server.service.facilitators, 'support', {})})
            else: self.reply(404, {'error': 'not_found'})
        except Exception: self.reply(500, {'error': 'page_unavailable'})

    def do_POST(self):
        if self.path != '/v1/audit': return self.reply(404, {'error': 'not_found'})
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            return self.reply(400, {'error': 'one Content-Length is required; chunked input is unsupported'})
        try: size = int(self.headers['Content-Length'])
        except ValueError: return self.reply(400, {'error': 'invalid_content_length'})
        if size < 0 or size > 32000: return self.reply(413, {'error': 'body_limit_32000_bytes'})
        if self.headers.get_content_type() != 'application/json': return self.reply(415, {'error': 'application/json required'})
        try:
            raw = self.rfile.read(size)
            if len(raw) != size: raise ValueError('incomplete body')
            obj = json.loads(raw.decode('utf-8'), parse_constant=lambda x: (_ for _ in ()).throw(ValueError('non-finite number')),
                             object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError): return self.reply(400, {'error': 'invalid_json'})
        payment_headers = self.headers.get_all('PAYMENT-SIGNATURE', []) + self.headers.get_all('X-PAYMENT', [])
        if len(payment_headers) > 1: return self.reply(400, {'error': 'send exactly one payment header'})
        try: self.reply(*self.server.service.process(obj, payment_headers[0] if payment_headers else None))
        except Exception: self.reply(503, {'error': 'service_unavailable; retry identical input and original payment header'}, {'Retry-After': '15'})


def unique_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result: raise ValueError('duplicate JSON key')
        result[k] = v
    return result


class Server(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = True
    def __init__(self, addr, service):
        self.service = service
        self.example = json.loads((ROOT/'data/example.json').read_text())
        self.identity = fingerprint()
        self.slots = threading.BoundedSemaphore(32)
        self.last_cleanup = 0
        super().__init__(addr, Handler)

    def process_request(self, request, addr):
        if not self.slots.acquire(blocking=False):
            request.close(); return
        try: super().process_request(request, addr)
        except Exception:
            self.slots.release(); raise

    def process_request_thread(self, request, addr):
        try: super().process_request_thread(request, addr)
        finally: self.slots.release()

    def handle_error(self, request, client_address):
        # Default traceback can contain untrusted request data; suppress it.
        pass

    def service_actions(self):
        if time.monotonic()-self.last_cleanup >= 3600:
            try:
                self.service.store.cleanup()
                self.last_cleanup = time.monotonic()
            except Exception:
                pass


def main():
    os.umask(0o077)
    base = config_base()
    urls = [os.environ.get('FACILITATOR_URL', 'https://facilitator.payai.network'),
            os.environ.get('FACILITATOR_FALLBACK_URL', 'https://facilitator.xpay.sh')]
    urls = list(dict.fromkeys(u.rstrip('/') for u in urls if u))
    for url in urls:
        if urlsplit(url).scheme != 'https' or urlsplit(url).username or urlsplit(url).password:
            raise ValueError('facilitator URLs must be HTTPS without credentials')
    facilitators = Facilitators(urls)
    service = PaymentService(PaymentStore(os.environ.get('PAYMENTS_DB', str(ROOT/'data/payments.db'))), facilitators, base)
    bind=(os.environ.get('BIND_HOST','127.0.0.1'), int(os.environ.get('PORT','8787')))
    with Server(bind, service) as server:
        def stop(signum, frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print('x402 Settlement Auditor '+VERSION+' listening on %s:%d' % bind, flush=True)
        server.serve_forever(poll_interval=0.25)


if __name__ == '__main__': main()
