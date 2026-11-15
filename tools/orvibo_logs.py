#!/usr/bin/env python3
"""ORVIBO access-log diagnostic v2 - drains all pages."""
import argparse, hashlib, json, os, socket, ssl, tempfile, time, zlib
CLIENT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIBCTANBgkqhkiG9w0BAQsFADCBojELMAkGA1UEBhMCQ04x
EjAQBgNVBAgMCUd1YW5nRG9uZzERMA8GA1UEBwwIU2hlblpoZW4xIjAgBgNVBAoM
GU9SVklCTyBUZWNobm9sb2d5IENvLixMdGQxCzAJBgNVBAsMAklUMRUwEwYDVQQD
DAwqLm9ydmliby5jb20xJDAiBgkqhkiG9w0BCQEWFWhlaGFpbGlhbmdAb3J2aWJv
LmNvbTAeFw0xODA4MjIwNjI4MTdaFw00ODA4MTQwNjI4MTdaMGkxCzAJBgNVBAYT
AkNOMRIwEAYDVQQIEwlHdWFuZ0RvbmcxIjAgBgNVBAoTGU9SVklCTyBUZWNobm9s
b2d5IENvLixMdGQxCzAJBgNVBAsTAklUMRUwEwYDVQQDDAwqLm9ydmliby5jb20w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD44AVAMBk75aQ+tIjx+G3L
yv0Ckg6MuR1hDZfKLpq/dRkxZP0TZ7UL7oIbK590NUgcJto2njxU3EhtFD4a/Uzg
RNJWXgyQnrr5V+Uksp8tHLU5fs0W1U9k82IOCfFBawiad8i/sONCmEVXUaVY9mLr
5tMpTrx1llqEFisI9Opf81gJRc1yE5CjUCnK3ENmAqKOdPPADgzEPuv69Jc/rL2M
XLFLfLAsHxZOf5pFftTE5X5/r00lFxUW+4lmxnSrDolYHUh3Egm+ZYxJgq+ycI29
8mgY2bAvUsntx0yn2AKAaUVaktPVCboKnLIKP7J9j9EaVuwvwN0cwD1jWv3KsuhR
AgMBAAGjGDAWMBQGBCoDgxwEDAwKMDAwMDAwMTQ0NDANBgkqhkiG9w0BAQsFAAOC
AQEAXamhyBvmizbbNn11EVyv3vk+o8fYHEl/oAbBTUp3+6XezKWfbt9G/vdwMtLh
GcoU1UCOK+gNTP7B+8hYrxwwob8CDMBtsqq857+RXkw4hUw5RP0IGoJW/1oEaJwQ
1XtTNCbBj3CNKtb7Uu/b7WyuY7gy9VcV5c4bK5g59x+z3SMZFwVPs97T+rIs17+E
F7CXjNlahu7xtvyuItxTDyW9Nj9FwTjOBf7SyXXuMyS3emY39pwy8654gcSLr5IY
JXQc5tBirT3xggBy8AsSuBYUol7QJtV0Ehn09wMqW/QBPctoHjKeP0JNVD3sne8S
0yFmUl6/Oa1p03G8Xf4xG5dfhg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEGTCCAwGgAwIBAgIJAMgC1Osv+BiBMA0GCSqGSIb3DQEBCwUAMIGiMQswCQYD
VQQGEwJDTjESMBAGA1UECAwJR3VhbmdEb25nMREwDwYDVQQHDAhTaGVuWmhlbjEi
MCAGA1UECgwZT1JWSUJPIFRlY2hub2xvZ3kgQ28uLEx0ZDELMAkGA1UECwwCSVQx
FTATBgNVBAMMDCoub3J2aWJvLmNvbTEkMCIGCSqGSIb3DQEJARYVaGVoYWlsaWFu
Z0BvcnZpYm8uY29tMB4XDTE4MDgyMjA2MjYzMFoXDTQ4MDgxNDA2MjYzMFowgaIx
CzAJBgNVBAYTAkNOMRIwEAYDVQQIDAlHdWFuZ0RvbmcxETAPBgNVBAcMCFNoZW5a
aGVuMSIwIAYDVQQKDBlPUlZJQk8gVGVjaG5vbG9neSBDby4sTHRkMQswCQYDVQQL
DAJJVDEVMBMGA1UEAwwMKi5vcnZpYm8uY29tMSQwIgYJKoZIhvcNAQkBFhVoZWhh
aWxpYW5nQG9ydmliby5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQC27ZN/n9WSI7Qr3zg8XEx5tIbBU+S5kbEBKJpRPw99TN3ljiP3qgAEmnZK4FYa
VSMdlIekyhUDXAQXRR0tN6STB2McIWbciZ/PnsyauVTB9vjcSXTRq2gsUcmfCM8q
nHREaa4T9fbuCBBN4v9xmm7OuyKC6Q1BvCjzOqGAMCQRtyXMZwC1t+mVKhYa97b/
T2yTjTwkrh72S7xkPv23OXnNAaVZUY6QyqFK62dE0eTIobrfDeRm51yRtr/SmMoW
X8SwRG6JK1usOj4bSTAA4fftNz8yB+jopNN+Sg1ZRG9SJuk/dxRESNwNrMMOU0o6
aoEJwWFB5jTxjBz7KhBG5vbjAgMBAAGjUDBOMB0GA1UdDgQWBBTS1g5JoJjqLP4B
elFJY/He3L/7ojAfBgNVHSMEGDAWgBTS1g5JoJjqLP4BelFJY/He3L/7ojAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBf7oyDUparavLZhPdn7UwfmxnU
gA+PK4nXKX7rqg8DRzeLkOOBGwxUzUJlxigtSI4+TIfqKVSt/4WKo0R7Ivpg4yKz
lxDWPxVVncfMBxr/AZEVNFlVyVXWUekEoBckIyr5zRjPK3PfAtnd7jAQwYdsl2zG
8zsJag4tbw7dyWFbQtezY7ZPx4c+mEPTwKbB5AAlidCOO+9axmhxliuoSy67CJER
dZxEx2poqHRLDFbyir+C1OBPkXnTCHbP/eGiABhizmt7nkQMAyrdvc69PcgmhYhA
YIowNqpmqRFbVwL7DHMzJ09vDCsZufD0TvR1DMDO3rGB/NlUQ6vktk4zg/UE
-----END CERTIFICATE-----
"""
CLIENT_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD44AVAMBk75aQ+
tIjx+G3Lyv0Ckg6MuR1hDZfKLpq/dRkxZP0TZ7UL7oIbK590NUgcJto2njxU3Eht
FD4a/UzgRNJWXgyQnrr5V+Uksp8tHLU5fs0W1U9k82IOCfFBawiad8i/sONCmEVX
UaVY9mLr5tMpTrx1llqEFisI9Opf81gJRc1yE5CjUCnK3ENmAqKOdPPADgzEPuv6
9Jc/rL2MXLFLfLAsHxZOf5pFftTE5X5/r00lFxUW+4lmxnSrDolYHUh3Egm+ZYxJ
gq+ycI298mgY2bAvUsntx0yn2AKAaUVaktPVCboKnLIKP7J9j9EaVuwvwN0cwD1j
Wv3KsuhRAgMBAAECggEBAPZO2EN/lunFy/jXOhWoVhn0itTpcobpil8MUeaimzrT
DJzrIuD6qZ7mbVOwp74eIYDjHuIhVvpxjSiPeSvC9zuaQUWDDRJwVgICcGESeyDt
oZoGmbl4YXw6uBfG1UN2R+yAkmjNCw5Un4Pc5TUXnC12pBPkvfXuWSUSv4K8yd0s
iJES9ccIym1AHVwdtrepQgxLCRK3k5OQ+M6yk+NCuVNlooUTvpgUEl93eG+/OUtD
CUnOZAnKXzTTjatIgbaA2o67OFf/TYGRaCWpAYD8S2rDGJh8l1CcsfHTeUxKPSld
PLuhxq8ZzZHS8aXkFO7aMC1bqyOof7W2NBa5tahBADECgYEA/6mqJvbPObvaRC5I
xEWVhfWHbbazy8mjnjsB7XAwkG71PhntzYjpMKwaES++qNX0GIUSgVa3luDqOew4
zwo1Vwc5iOHgKZNo2KLbqblMahcPMHXt3xYxxRa4oe41AVkTzTV+q3FGNB8h09gg
9BwTAVjs6I3UtICaDPkaFhDi0k0CgYEA+TQQTzo1OpnKkD5AuAgX+mo/W3FKqZNB
PussQBDT2rYB3GpJMjc2eLKfefSkNitymho0ar5Dm7CYn8RqOTsGJcc/Czpu6pyn
f0Z8TiyF0c4F5LWvGjWzWBoS8+bRmY+V9BL56uK3x0gx0RvHGnlgro5UeVb02yzD
lZ8tp5W6SBUCgYAnPJi6hiJjj+r9j8TnKm66MmZodiO94OJVhGTVVeR+JilJMJ2I
b7yqFZ+ih5tROhTONo4Sf4aJh1crMI+/ZqetBZTU5yWJ+++ZX9UqhR+vIH7aRx8M
n9FfmA8Z+v7ziAI7+jvIgAfwM97zLjZQgIaCLG2fezTrxtjdqNVSEaFd+QKBgEFP
u9aH0tuA4u3a4utYc7BVmDVHA+JdjYQH7pj70ApKGULDOFvIzKXlapZz33Wy/V4V
8Bbptp5fMiDtQUmuhnXwOj2fGuKyG9PnjTyPvqK19CV02GduG4rDiqQRom00jIBj
WMyOjsvTx/qd5RizJvuYodsLRzEKElhsV3LMcv3hAoGAdOEUJYLM4HIb71elqZXl
KI1BfMDgQZVWUm8Rto9UQXxDNvV0dVatCxIXEKsOnbJKlbLBq3vxRvI7OvnDs8+D
ZDD/ebv5p4ThCk6Xq7wGdPRA9iKCzFUiXX2Zxx8orDj8th+h8aLrMFebOUdGKrbr
L254LLY50nydp6ll0jMa/ck=
-----END PRIVATE KEY-----
"""
PK_KEY = b"khggd54865SNJHGF"
HOST="homemate.orvibo.com"; PORT=10002
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
def crc_bytes(body):
    return bytes.fromhex(format(zlib.crc32(body) & 0xFFFFFFFF, "08X"))


def build_frame(aes_enc, payload, pt, key, sid):
    body = aes_enc(json.dumps(payload, separators=(",", ":")).encode(), key)
    total = 42 + len(body)
    h = bytearray(42)
    h[0:2] = b"hd"; h[2:4] = total.to_bytes(2, "big"); h[4:6] = pt.encode()
    h[6:10] = crc_bytes(body)
    h[10:42] = (sid or "").ljust(32)[:32].encode("ascii", "replace")
    return bytes(h) + body


def read_frame(sock, aes_dec, session_key, timeout=10):
    """Read exactly one hd-frame and return (pt, sessionId, payload)."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < 42:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    total = int.from_bytes(buf[2:4], "big")
    while len(buf) < total:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    pt = buf[4:6].decode("ascii", "replace")
    sid = buf[10:42].decode("ascii", "replace").strip()
    body = buf[42:total]
    key = PK_KEY if pt == "pk" else session_key
    payload = json.loads(aes_dec(body, key).decode("utf-8", "replace"))
    return pt, sid, payload


def md5pw(p): return hashlib.md5(p.encode()).hexdigest().upper()
def ssl_ctx():
    cfd,cc=tempfile.mkstemp(suffix=".pem"); os.write(cfd,CLIENT_CERT_PEM.encode()); os.close(cfd)
    kfd,ck=tempfile.mkstemp(suffix=".pem"); os.write(kfd,CLIENT_KEY_PEM.encode()); os.close(kfd)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.load_cert_chain(cc,ck)
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try: ctx.minimum_version=ssl.TLSVersion.TLSv1
    except Exception: pass
    try: ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except Exception: pass
    return ctx
_serial=[int(time.time())&0x7fffffff]
def nxt(): _serial[0]=(_serial[0]+1)&0x7fffffff; return _serial[0]
def request(s, skey, sid, cmd, fields, to=15):
    """Send one request and drain ALL pages (matching by serial). Returns merged tables."""
    p={"cmd":cmd,"serial":nxt(),"clientType":1,"uniSerial":int(time.time()*1000),"serverRecord":False,"ver":"5.2.6.308"}
    p.update(fields); serial=p["serial"]
    s.sendall(build_frame(aes_ecb_encrypt,p,cmd and "dk" or "pk",skey,sid))
    merged={}; first=None; guard=0
    while True:
        guard+=1
        if guard>30: break
        pt,_,obj=read_frame(s,aes_ecb_decrypt,skey,timeout=to)
        if obj.get("serial")!=serial:
            continue   # leftover page from a previous request: drain & ignore
        if first is None: first=obj
        for k,v in obj.items():
            if isinstance(v,list): merged.setdefault(k,[]).extend(v)
        tp=obj.get("tPage") or 1; pi=obj.get("pageIndex") or 0
        if pi+1>=tp: break
    return first, merged
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--user",required=True); ap.add_argument("--password",required=True)
    a=ap.parse_args()
    raw=socket.create_connection((HOST,PORT),timeout=10); s=ssl_ctx().wrap_socket(raw,server_hostname=HOST)
    print("TLS:",s.version())
    # handshake (cmd 0, pk) - special, read one frame
    p={"cmd":0,"serial":nxt(),"clientType":1,"uniSerial":1,"serverRecord":False,"ver":"5.2.6.308","source":1,"softwareVersion":"5.2.6.308","systemVersion":"diag","hardwareVersion":"diag","language":"en","identifier":"ha-diag","phoneName":"diag"}
    s.sendall(build_frame(aes_ecb_encrypt,p,"pk",PK_KEY,None))
    _,sid,obj=read_frame(s,aes_ecb_decrypt,None); skey=obj.get("key","").encode()[:16].ljust(16,b"\0")
    first,_=request(s,skey,sid,2,{"userName":a.user,"password":md5pw(a.password),"type":3,"needAccountDetailError":True})
    userId=first.get("userId",""); fams=first.get("familyList") or []
    familyId=fams[0].get("familyId") if fams else ""
    print("login status=%s userId=%s familyId=%s"%(first.get("status"),userId,familyId))
    print("\n######## cmd 147 (all pages) ########")
    _,tabs=request(s,skey,sid,147,{"userName":a.user,"userId":userId,"familyId":familyId,"pageIndex":0,"dataType":"","lastUpdateTime":0,"deviceFlag":0})
    print("tables returned:",{k:len(v) for k,v in tabs.items()})
    devs=tabs.get("device",[])
    for d in devs: print("  DEVICE:",json.dumps({k:d.get(k) for k in ("deviceName","deviceId","uid","deviceType","model","extAddr") if k in d},ensure_ascii=False))
    for du in tabs.get("doorUserBind",[]): print("  DOORUSER:",json.dumps(du,ensure_ascii=False))
    luid=""; ldid=""
    for d in devs: luid=d.get("uid") or luid; ldid=d.get("deviceId") or ldid
    if not luid:
        for f in fams:
            for g in (f.get("gatewayList") or []):
                if g.get("uid"): luid=g["uid"]
    print("\nlock uid=%r deviceId=%r"%(luid,ldid))
    print("\n######## cmd 130 status records ########")
    first,tabs=request(s,skey,sid,130,{"uid":luid,"userName":a.user,"familyId":familyId,"deviceId":ldid,"maxSequence":-1,"minSequence":-1,"readCount":20,"type":0})
    print("reply keys:",list(first.keys()),"status=",first.get("status"))
    recs=tabs.get("statusRecordList") or tabs.get("statusRecord") or []
    print("RECORDS:",len(recs))
    for r in recs[:25]: print("  ",json.dumps(r,ensure_ascii=False))
    s.close(); print("\nDONE - paste everything.")
if __name__=="__main__": main()
