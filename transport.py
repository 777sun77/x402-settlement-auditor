"""Bounded JSON HTTPS transport. curl honors the managed environment proxy and CA."""
import json
import subprocess
import time


class RemoteError(Exception):
    pass


def http_json(url, payload=None, timeout=12):
    cmd = ['curl', '--silent', '--show-error', '--connect-timeout', '4',
           '--max-time', str(timeout), '--max-filesize', '4000000',
           '--proto', '=https,http', '--write-out', '\n%{http_code}',
           '--user-agent', 'x402-settlement-auditor/1.0', url]
    if payload is not None:
        cmd += ['--header', 'Content-Type: application/json', '--data-binary', '@-']
    try:
        p = subprocess.run(cmd, input=json.dumps(payload) if payload is not None else None,
                           text=True, capture_output=True, timeout=timeout+2)
    except (OSError, subprocess.TimeoutExpired):
        raise RemoteError('transport unavailable or timed out') from None
    # Never include remote body/stderr in exceptions: a facilitator may echo signatures.
    if p.returncode: raise RemoteError('transport failed (curl %d)' % p.returncode)
    raw, _, code = p.stdout.rpartition('\n')
    try: value = json.loads(raw)
    except ValueError: raise RemoteError('remote response is not JSON') from None
    if not isinstance(value, dict): raise RemoteError('remote response is not an object')
    return int(code), value


DEFAULT_RPCS = ('https://mainnet.base.org', 'https://base.llamarpc.com', 'https://base-rpc.publicnode.com')


class RPC:
    def __init__(self, urls=DEFAULT_RPCS):
        self.urls = tuple(urls)
        self.reads = []
        self.checked = set()

    def _request(self, url, method, params):
        status, obj = http_json(url, {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}, 8)
        if status != 200 or obj.get('jsonrpc') != '2.0' or obj.get('id') != 1 or 'result' not in obj or obj.get('error'):
            raise RemoteError('RPC %s rejected by %s' % (method, url))
        return obj['result']

    def call(self, method, params):
        for url in self.urls:
            for attempt in range(2):
                try:
                    if url not in self.checked:
                        if self._request(url, 'eth_chainId', []) != '0x2105':
                            raise RemoteError('RPC chain is not Base mainnet')
                        self.checked.add(url)
                    value = self._request(url, method, params)
                    self.reads.append({'method': method, 'rpc': url, 'params': params})
                    return value
                except RemoteError:
                    if attempt == 0: time.sleep(0.15)
        raise RemoteError('all Base RPC sources failed for '+method)
