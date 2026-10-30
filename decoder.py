"""Bounds-checked Ethereum ABI/event decoder, adapted from the local reference.
No RPC or payment side effects. Ethereum Keccak implementation is stdlib-only.
"""
import datetime as dt
import re

USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
MULTICALL3 = "0xca11bde05977b3631167028862be2a173976ca11"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
AGGREGATE3 = "0x82ad56cb"
AUTH_SELECTORS = {"0xe3ee160e": "transferWithAuthorization",
                  "0xef55bec6": "receiveWithAuthorization"}
MASK64 = (1 << 64) - 1
ROTATIONS = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
             25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008)


def _rotate(value, bits):
    return ((value << bits) | (value >> ((64 - bits) % 64))) & MASK64


def _keccak_f(state):
    for rc in ROUND_CONSTANTS:
        columns = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
                   for x in range(5)]
        delta = [columns[(x-1) % 5] ^ _rotate(columns[(x+1) % 5], 1)
                 for x in range(5)]
        for i in range(25):
            state[i] ^= delta[i % 5]
        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                moved[y + 5*((2*x + 3*y) % 5)] = _rotate(
                    state[x + 5*y], ROTATIONS[x + 5*y])
        for y in range(5):
            for x in range(5):
                state[x + 5*y] = (moved[x + 5*y] ^
                    ((~moved[(x+1) % 5 + 5*y]) & moved[(x+2) % 5 + 5*y]))
        state[0] ^= rc


def keccak256(message):
    """Ethereum Keccak-256, with Keccak padding (not SHA3-256 padding)."""
    rate = 136
    padded = bytearray(message)
    padded.append(0x01)
    padded.extend(b"\x00" * ((-len(padded)) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset+rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane*8:lane*8+8], "little")
        _keccak_f(state)
    return b"".join(word.to_bytes(8, "little") for word in state)[:32]


def topic(signature):
    return "0x" + keccak256(signature.encode("ascii")).hex()


AUTH_USED_TOPIC = topic("AuthorizationUsed(address,bytes32)")
AUTH_CANCELED_TOPIC = topic("AuthorizationCanceled(address,bytes32)")
# The live corpus also uses the dynamic bytes-signature overloads. Derive their
# selectors here rather than trusting an external selector database.
BYTES_AUTH_SELECTORS = {
    topic("transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)")[:10]: "transferWithAuthorization",
    topic("receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)")[:10]: "receiveWithAuthorization",
}
AUTH_SELECTORS.update(BYTES_AUTH_SELECTORS)


def keccak_self_test():
    if keccak256(b"").hex() != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
        raise RuntimeError("Keccak empty-message self-test failed")
    if topic("Transfer(address,address,uint256)") != TRANSFER_TOPIC:
        raise RuntimeError("Keccak Transfer self-test failed")


def hex_bytes(value, size=None):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
        raise ValueError("invalid hex byte string")
    result = bytes.fromhex(value[2:])
    if size is not None and len(result) != size:
        raise ValueError("expected %d bytes, got %d" % (size, len(result)))
    return result


def address(value):
    return "0x" + hex_bytes(value, 20).hex()


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise ValueError("invalid RPC quantity")
    return int(value, 16)


def usdc_amount(raw):
    return "%d.%06d" % divmod(raw, 1_000_000)


def utc_time(timestamp):
    try:
        return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def _word(data, offset):
    if offset < 0 or offset + 32 > len(data):
        raise ValueError("ABI word outside calldata")
    return data[offset:offset+32]


def _uint(data, offset):
    return int.from_bytes(_word(data, offset), "big")


def _address_word(word):
    if len(word) != 32 or any(word[:12]):
        raise ValueError("noncanonical ABI address")
    return "0x" + word[12:].hex()


def decode_authorization(calldata):
    data = hex_bytes(calldata)
    selector = "0x" + data[:4].hex()
    if selector not in AUTH_SELECTORS:
        raise ValueError("unsupported authorization selector")
    args = data[4:]
    if selector in BYTES_AUTH_SELECTORS:
        offset = _uint(args, 6*32)
        if offset < 7*32 or offset % 32:
            raise ValueError("invalid authorization signature bytes offset")
        size = _uint(args, offset)
        begin = offset + 32
        end = begin + size
        padded_end = begin + ((size+31)//32)*32
        if padded_end > len(args) or any(args[end:padded_end]):
            raise ValueError("invalid authorization signature bytes bounds/padding")
        signature = {"encoding": "bytes", "bytes": "0x" + args[begin:end].hex()}
    else:
        if len(args) < 9 * 32:
            raise ValueError("authorization calldata must have nine ABI words")
        if _uint(args, 6*32) > 255:
            raise ValueError("noncanonical uint8 signature v")
        padded_end = 9 * 32
        signature = {"encoding": "v,r,s", "v": _uint(args, 6*32),
                     "r": "0x" + _word(args, 7*32).hex(),
                     "s": "0x" + _word(args, 8*32).hex()}
    return {"kind": AUTH_SELECTORS[selector], "selector": selector,
            "from": _address_word(_word(args, 0)),
            "to": _address_word(_word(args, 32)), "value": _uint(args, 64),
            "validAfter": _uint(args, 96), "validBefore": _uint(args, 128),
            "nonce": "0x" + _word(args, 160).hex(),
            "abi_bytes": 4 + padded_end,
            "trailing": decode_suffix(args[padded_end:])}


def decode_aggregate3(calldata):
    """Decode aggregate3((address,bool,bytes)[]), with bounds validation."""
    data = hex_bytes(calldata)
    if "0x" + data[:4].hex() != AGGREGATE3:
        raise ValueError("not aggregate3")
    args = data[4:]
    start = _uint(args, 0)
    if start < 32 or start % 32:
        raise ValueError("invalid Call3 array offset")
    count = _uint(args, start)
    heads = start + 32
    if count > (len(args) - heads) // 32:
        raise ValueError("Call3 array head outside calldata")
    calls = []
    for i in range(count):
        relative = _uint(args, heads + 32*i)
        if relative < 32*count or relative % 32:
            raise ValueError("invalid Call3 tuple offset")
        item = heads + relative
        target = _address_word(_word(args, item))
        allow = _uint(args, item + 32)
        if allow not in (0, 1):
            raise ValueError("noncanonical Call3 bool")
        tail = _uint(args, item + 64)
        if tail < 96 or tail % 32:
            raise ValueError("invalid Call3 bytes offset")
        size = _uint(args, item + tail)
        begin = item + tail + 32
        end = begin + size
        padded_end = begin + ((size + 31) // 32)*32
        if padded_end > len(args):
            raise ValueError("Call3 bytes outside calldata")
        if any(args[end:padded_end]):
            raise ValueError("nonzero Call3 bytes padding")
        calls.append({"target": target, "allowFailure": bool(allow),
                      "callData": "0x" + args[begin:end].hex()})
    return calls


def inspect_calldata(tx):
    calls, aggregates = [], []

    def visit(target, calldata, path, allow_failure=None, depth=0):
        if depth > 8:
            raise ValueError("aggregate3 nesting exceeds eight levels")
        data = hex_bytes(calldata)
        selector = "0x" + data[:4].hex()
        if selector in AUTH_SELECTORS and (target == USDC or not path):
            call = decode_authorization(calldata)
            call.update(target=target, path=path, allowFailure=allow_failure)
            calls.append(call)
        elif selector == AGGREGATE3:
            children = decode_aggregate3(calldata)
            aggregates.append({"target": target, "path": path, "calls": children})
            for i, child in enumerate(children):
                visit(child["target"], child["callData"], path + [i],
                      child["allowFailure"], depth + 1)

    target = address(tx["to"]) if tx.get("to") is not None else None
    visit(target, tx.get("input", "0x"), [])
    return calls, aggregates


def decode_logs(logs):
    decoded = {"transfers": [], "authorizations_used": [],
               "authorizations_canceled": [], "errors": []}
    for index, log in enumerate(logs):
        if not isinstance(log, dict):
            decoded["errors"].append("log %d: expected object" % index)
            continue
        try:
            emitter = address(log.get("address"))
        except ValueError:
            decoded["errors"].append("log %d: invalid emitter" % index)
            continue
        if emitter != USDC:
            continue
        topics = log.get("topics", [])
        if not isinstance(topics, list):
            decoded["errors"].append("USDC log %d: topics is not a list" % index)
            continue
        event = topics[0].lower() if topics and isinstance(topics[0], str) else None
        if event not in (TRANSFER_TOPIC, AUTH_USED_TOPIC, AUTH_CANCELED_TOPIC):
            continue
        try:
            if log.get("removed", False) is not False:
                raise ValueError("removed event")
            if len(topics) != 3:
                raise ValueError("event must have exactly three topics")
            who = _address_word(hex_bytes(topics[1], 32))
            entry = {"receipt_log_position": index, "logIndex": log.get("logIndex"),
                     "emitter": emitter, "topic0": event}
            if event == TRANSFER_TOPIC:
                entry.update({"from": who,
                              "to": _address_word(hex_bytes(topics[2], 32)),
                              "value": int.from_bytes(hex_bytes(log.get("data"), 32), "big")})
                entry["amount_usdc"] = usdc_amount(entry["value"])
                decoded["transfers"].append(entry)
            else:
                hex_bytes(log.get("data"), 0)
                entry.update(authorizer=who, nonce="0x" + hex_bytes(topics[2], 32).hex())
                key = "authorizations_used" if event == AUTH_USED_TOPIC else "authorizations_canceled"
                decoded[key].append(entry)
        except (ValueError, TypeError) as exc:
            decoded["errors"].append("USDC log %d: %s" % (index, exc))
    return decoded


MARKER = bytes.fromhex('80218021802180218021802180218021')


def _cbor(data):
    """Small bounded definite-length CBOR reader; no tags, floats or indefinite data."""
    pos = 0
    def read(depth=0):
        nonlocal pos
        if depth > 12 or pos >= len(data):
            raise ValueError('CBOR bounds/depth')
        b = data[pos]; pos += 1
        major, n = b >> 5, b & 31
        if n >= 24:
            size = {24: 1, 25: 2, 26: 4, 27: 8}.get(n)
            if size is None or pos + size > len(data):
                raise ValueError('unsupported CBOR length')
            n = int.from_bytes(data[pos:pos+size], 'big'); pos += size
        if major == 0: return n
        if major == 1: return -1-n
        if major in (2, 3):
            if pos+n > len(data): raise ValueError('CBOR string bounds')
            value = data[pos:pos+n]; pos += n
            return '0x'+value.hex() if major == 2 else value.decode('utf-8')
        if major == 4:
            if n > 256: raise ValueError('CBOR array limit')
            return [read(depth+1) for _ in range(n)]
        if major == 5:
            if n > 256: raise ValueError('CBOR map limit')
            out = {}
            for _ in range(n):
                k = read(depth+1)
                if not isinstance(k, str) or k in out: raise ValueError('CBOR map key')
                out[k] = read(depth+1)
            return out
        if major == 7 and n in (20, 21, 22): return {20: False, 21: True, 22: None}[n]
        raise ValueError('unsupported CBOR type')
    result = read()
    if pos != len(data): raise ValueError('CBOR trailing bytes')
    return result


def decode_suffix(raw):
    """Only decode attribution entirely outside the ABI payload. Always retain raw."""
    out = {'raw': '0x'+raw.hex(), 'format': 'none' if not raw else 'raw',
           'schema_id': None, 'codes': []}
    if len(raw) < 18 or not raw.endswith(MARKER): return out
    schema = raw[-17]; out['schema_id'] = schema
    try:
        if schema in (0, 1):
            n = raw[-18]
            registry_size = 20 if schema == 1 else 0
            if len(raw) != registry_size+n+18: raise ValueError('suffix length mismatch')
            codes_raw = raw[registry_size:registry_size+n].decode('ascii')
            codes = codes_raw.split(',') if codes_raw else []
            if any(not re.fullmatch(r'[\x21-\x2b\x2d-\x7e]+', c) for c in codes):
                raise ValueError('invalid ASCII code')
            if schema == 1: out['registry'] = '0x'+raw[:20].hex()
        elif schema == 2:
            if len(raw) < 19 or int.from_bytes(raw[-19:-17], 'big') != len(raw)-19:
                raise ValueError('CBOR suffix length mismatch')
            fields = _cbor(raw[:-19])
            if not isinstance(fields, dict): raise ValueError('expected CBOR map')
            codes = []
            for key in ('a', 'w', 's'):
                v = fields.get(key, [])
                values = v if isinstance(v, list) and key == 's' else [v] if isinstance(v, str) else []
                if key in fields and not values and v != []: raise ValueError('invalid code field')
                if any(not isinstance(c, str) or not re.fullmatch(r'[a-z0-9_]{1,32}', c) for c in values):
                    raise ValueError('invalid builder code')
                codes.extend(values)
            out['fields'] = fields
        else:
            return out
        out.update(format='erc8021', codes=codes)
    except (ValueError, UnicodeError, TypeError) as exc:
        out['error'] = str(exc)
    return out


def find_calls(tx):
    """Explicit aggregate3 traversal, then heuristic wrapper scan; logs bind candidates."""
    calls, warnings, outer_end = [], [], None
    raw = hex_bytes(tx.get('input', '0x'))
    if len(raw) > 32768: return [], ['calldata exceeds 32 KiB decoder limit'], decode_suffix(b'')
    def visit(target, data, path, depth=0):
        nonlocal outer_end
        if depth > 8: raise ValueError('multicall depth limit')
        sel = '0x'+data[:4].hex()
        if sel in AUTH_SELECTORS:
            call = decode_authorization('0x'+data.hex())
            call.update(target=target, path=path, detection='direct' if not path else 'aggregate3')
            if not path: outer_end = call['abi_bytes']
            calls.append(call)
        elif sel == AGGREGATE3:
            children = decode_aggregate3('0x'+data.hex())
            args = data[4:]; start = _uint(args, 0); heads = start+32
            end = heads+len(children)*32
            for i, child in enumerate(children):
                item = heads+_uint(args, heads+32*i)
                tail = item+_uint(args, item+64)
                end = max(end, tail+32+((_uint(args, tail)+31)//32)*32)
                visit(child['target'], hex_bytes(child['callData']), path+[i], depth+1)
            if not path: outer_end = 4+end
    try: visit((tx.get('to') or '').lower(), raw, [])
    except ValueError as exc: warnings.append('ABI decoding: '+str(exc))
    if not calls:
        # Unknown facilitator ABI: selector hits are hints, never execution proof.
        for sel in AUTH_SELECTORS:
            needle = bytes.fromhex(sel[2:]); pos = 0
            while len(calls) < 32:
                pos = raw.find(needle, pos)
                if pos < 0: break
                try:
                    call = decode_authorization('0x'+raw[pos:].hex())
                    call.update(target=None, path=None, detection='wrapper_selector_scan', byte_offset=pos)
                    # The enclosing wrapper's ABI boundary is unknown. Do not duplicate
                    # its remaining calldata as a suffix on every selector hint.
                    call['trailing'] = {'format': 'raw', 'raw': '0x', 'schema_id': None,
                                        'codes': [], 'boundary_unknown': True}
                    calls.append(call)
                except ValueError: pass
                pos += 4
        if calls: warnings.append('Wrapper selector scan is heuristic; only receipt-bound authorizations count')
    trailing = decode_suffix(raw[outer_end:]) if outer_end is not None else decode_suffix(b'')
    if outer_end is None and raw.endswith(MARKER):
        # Unknown ABI boundary: report tail raw, without asserting it is outside payload.
        trailing = {'raw': '0x'+raw[-min(len(raw), 512):].hex(), 'format': 'raw',
                    'schema_id': raw[-17] if len(raw)>16 else None, 'codes': [],
                    'boundary_unknown': True}
    return calls, warnings, trailing
