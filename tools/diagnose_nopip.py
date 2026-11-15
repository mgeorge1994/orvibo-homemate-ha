#!/usr/bin/env python3
"""
Zero-dependency connection diagnostic for the ORVIBO HomeMate integration.

Needs ONLY the Python 3 that ships with macOS/Linux -- no `pip`, no
`cryptography`. It embeds a small pure-Python AES-128.

Run it on a machine that reaches the internet the normal way (your laptop
on the same network as HA is fine):

    python3 tools/diagnose_nopip.py --user you@example.com --password 'secret'

It reports exactly where the connection breaks (DNS -> TCP -> TLS ->
handshake) and prints the server's decrypted reply. Paste the output back.
Talks only to ORVIBO's own server.
"""
import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
import zlib

# --------------------------------------------------------------------------
# Tiny pure-Python AES-128 (ECB). Verified against FIPS-197.
# --------------------------------------------------------------------------
_SBOX = []
_INV_SBOX = []


def _init_sbox():
    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xformed = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ \
            ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (xformed ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _init_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _key_expansion(key):
    assert len(key) == 16
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[rnd * 4 + c][r]


def _bytes_to_state(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _encrypt_block(block, w):
    s = _bytes_to_state(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, 10):
        s = [[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        s = [s[r][r:] + s[r][:r] for r in range(4)]  # ShiftRows
        ns = [[0] * 4 for _ in range(4)]
        for c in range(4):
            col = [s[r][c] for r in range(4)]
            ns[0][c] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
            ns[1][c] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
            ns[2][c] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
            ns[3][c] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
        s = ns
        _add_round_key(s, w, rnd)
    s = [[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    s = [s[r][r:] + s[r][:r] for r in range(4)]
    _add_round_key(s, w, 10)
    return _state_to_bytes(s)


def _decrypt_block(block, w):
    s = _bytes_to_state(block)
    _add_round_key(s, w, 10)
    for rnd in range(9, 0, -1):
        s = [s[r][-r:] + s[r][:-r] if r else s[r] for r in range(4)]  # InvShiftRows
        s = [[_INV_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        _add_round_key(s, w, rnd)
        ns = [[0] * 4 for _ in range(4)]
        for c in range(4):
            col = [s[r][c] for r in range(4)]
            ns[0][c] = _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9)
            ns[1][c] = _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13)
            ns[2][c] = _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11)
            ns[3][c] = _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14)
        s = ns
    s = [s[r][-r:] + s[r][:-r] if r else s[r] for r in range(4)]
    s = [[_INV_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, 0)
    return _state_to_bytes(s)


def aes_ecb_encrypt(data, key):
    w = _key_expansion(key)
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    return b"".join(_encrypt_block(data[i:i + 16], w) for i in range(0, len(data), 16))


def aes_ecb_decrypt(data, key):
    w = _key_expansion(key)
    out = b"".join(_decrypt_block(data[i:i + 16], w) for i in range(0, len(data), 16))
    if out and 1 <= out[-1] <= 16:
        out = out[:-out[-1]]
    return out


# --------------------------------------------------------------------------
# HomeMate framing (mirrors homemate.py)
# --------------------------------------------------------------------------
PK_KEY = b"khggd54865SNJHGF"
HOST = "homemate.orvibo.com"
PORTS = [10002, 10001, 10003, 10004, 10005]
_CERT_DIR = os.path.join(os.path.dirname(__file__), "..",
                         "custom_components", "orvibo_homemate", "certs")


def crc_bytes(body):
    return bytes.fromhex(format(zlib.crc32(body) & 0xFFFFFFFF, "08X"))


def build_frame(payload, pt="pk", key=PK_KEY, sid=None):
    body = aes_ecb_encrypt(json.dumps(payload, separators=(",", ":")).encode(), key)
    total = 42 + len(body)
    h = bytearray(42)
    h[0:2] = b"hd"; h[2:4] = total.to_bytes(2, "big"); h[4:6] = pt.encode()
    h[6:10] = crc_bytes(body)
    h[10:42] = (sid or "").ljust(32)[:32].encode("ascii", "replace")
    return bytes(h) + body


def parse_reply(raw, key=PK_KEY):
    pt = raw[4:6].decode("ascii", "replace")
    body = raw[42:int.from_bytes(raw[2:4], "big")]
    k = PK_KEY if pt == "pk" else key
    plain = aes_ecb_decrypt(body, k)
    return pt, json.loads(plain.decode("utf-8", "replace"))


def ssl_ctx():
    cc = os.path.join(_CERT_DIR, "client_cert.pem")
    ck = os.path.join(_CERT_DIR, "client_key.pem")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if os.path.exists(cc) and os.path.exists(ck):
        ctx.load_cert_chain(cc, ck)
    else:
        print(f"  WARNING: client cert not found at {cc}")
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except Exception:
        pass
    return ctx


def try_port(host, port, use_tls):
    print(f"\n--- {host}:{port} tls={'on' if use_tls else 'off'} ---")
    try:
        raw_sock = socket.create_connection((host, port), timeout=8)
    except Exception as e:
        print(f"  TCP connect FAILED: {type(e).__name__}: {e}")
        return False
    print("  TCP connect: OK")
    s = raw_sock
    if use_tls:
        try:
            s = ssl_ctx().wrap_socket(raw_sock, server_hostname=host)
            print(f"  TLS handshake: OK ({s.version()})")
        except Exception as e:
            print(f"  TLS handshake FAILED: {type(e).__name__}: {e}")
            raw_sock.close()
            return False
    payload = {"cmd": 0, "serial": 10101, "clientType": 1, "uniSerial": 1,
               "serverRecord": False, "ver": "5.2.6.308", "source": 1,
               "softwareVersion": "5.2.6.308", "systemVersion": "diag",
               "hardwareVersion": "diag", "language": "en",
               "identifier": "ha-diagnose", "phoneName": "diag"}
    try:
        s.sendall(build_frame(payload))
        s.settimeout(8)
        raw = s.recv(4096)
    except Exception as e:
        print(f"  handshake send/recv FAILED: {type(e).__name__}: {e}")
        s.close()
        return False
    if not raw:
        print("  no reply (server closed).")
        s.close(); return False
    print(f"  reply: {len(raw)} bytes header={raw[:10].hex()}")
    try:
        pt, obj = parse_reply(raw)
        print(f"  DECRYPTED reply (pt={pt}): {obj}")
        if obj.get("key"):
            print("  >>> SESSION KEY RECEIVED -- THIS COMBO WORKS <<<")
            s.close(); return True
        print("  (no 'key' field -- note the keys above)")
    except Exception as e:
        print(f"  decrypt failed: {e}; raw body: {raw[10:70].hex()}")
    s.close()
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--ports", default=",".join(map(str, PORTS)))
    args = ap.parse_args()

    print("=== AES self-test ===")
    tv = aes_ecb_encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"),
                         bytes.fromhex("000102030405060708090a0b0c0d0e0f"))[:16]
    print("  FIPS-197:", "PASS" if tv.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a" else "FAIL " + tv.hex())

    print("\n=== DNS ===")
    try:
        print(f"  {args.host} -> {socket.gethostbyname_ex(args.host)[2]}")
    except Exception as e:
        print(f"  DNS FAILED: {e}")
        return

    ports = [int(p) for p in args.ports.split(",")]
    for port in ports:
        if try_port(args.host, port, True):
            print("\nRESULT: working combo found (TLS). Use that port.")
            return
    print("\nNo TLS combo worked; trying plain TCP:")
    for port in ports:
        if try_port(args.host, port, False):
            print("\nRESULT: plain-TCP combo worked (unexpected).")
            return
    print("\nRESULT: nothing completed the handshake. Paste all output above.")


if __name__ == "__main__":
    main()
