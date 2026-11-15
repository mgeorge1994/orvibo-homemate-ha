"""
Offline unit tests for the HomeMate wire protocol.

These verify the parts that can be checked without the live ORVIBO server:
crypto correctness, framing round-trips, and header layout. They do NOT
contact ORVIBO.

Run:  python -m pytest tests/ -v
  or: python tests/test_protocol.py
"""
import json
import os
import sys
import zlib

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "custom_components", "orvibo_homemate"),
)

import homemate as hm  # noqa: E402


def test_fips197_aes128_vector():
    """Prove our AES-128-ECB primitive matches FIPS-197 (no padding block)."""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    # strip PKCS7's extra block by encrypting exactly one block and trimming
    ct = hm.aes_encrypt(pt, key)[:16]
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_pk_key_is_16_bytes():
    assert len(hm.PK_KEY) == 16  # AES-128 key used directly


def test_aes_roundtrip_pk():
    data = json.dumps({"cmd": 0, "serial": 42}).encode()
    ct = hm.aes_encrypt(data, hm.PK_KEY)
    assert ct != data
    assert len(ct) % 16 == 0
    assert hm.aes_decrypt(ct, hm.PK_KEY) == data


def test_aes_roundtrip_session_key():
    key = b"0123456789abcdef"
    data = b'{"order":"unlock"}'
    assert hm.aes_decrypt(hm.aes_encrypt(data, key), key) == data


def test_md5_password_uppercase_hex():
    assert hm.md5_password("password") == "5F4DCC3B5AA765D61D8327DEB882CF99"


def test_crc_hex_and_bytes():
    body = b"hello world"
    expected = format(zlib.crc32(body) & 0xFFFFFFFF, "08X")
    assert hm._crc_hex(body) == expected
    assert hm._crc_bytes(body) == bytes.fromhex(expected)
    assert len(hm._crc_bytes(body)) == 4


def test_build_frame_header_layout_pk():
    payload = {"cmd": hm.CMD_REQUEST_KEY, "serial": 123}
    frame = hm.build_frame(payload, protocol_type="pk", key=hm.PK_KEY, session_id=None)
    assert frame[0:2] == b"hd"
    assert int.from_bytes(frame[2:4], "big") == len(frame)
    assert frame[4:6] == b"pk"
    body = frame[hm.HEADER_LEN:]
    assert frame[6:10] == hm._crc_bytes(body)
    # no session yet -> 32 spaces
    assert frame[10:42] == b" " * 32


def test_build_frame_header_layout_session():
    key = b"ABCDEF0123456789"
    sid = "S1234567890ABCDEF"
    payload = {"cmd": hm.CMD_CONTROL, "serial": 7, "order": "unlock"}
    frame = hm.build_frame(payload, protocol_type="dk", key=key, session_id=sid)
    assert frame[4:6] == b"dk"
    # sessionId is left-justified, space-padded to 32
    assert frame[10:42].decode().strip() == sid


def test_parse_frame_roundtrip_pk():
    payload = {"cmd": 0, "serial": 999, "key": "ABCDEF0123456789", "SessionId": "SID123"}
    frame = hm.build_frame(payload, protocol_type="pk", key=hm.PK_KEY, session_id=None)
    parsed = hm.parse_frame(frame, session_key=None)
    assert parsed.protocol_type == "pk"
    assert parsed.payload == payload


def test_parse_frame_roundtrip_session():
    key = b"0123456789abcdef"
    payload = {"cmd": 15, "serial": 5, "result": 0, "deviceId": "dev123"}
    frame = hm.build_frame(payload, protocol_type="dk", key=key, session_id="SID")
    parsed = hm.parse_frame(frame, session_key=key)
    assert parsed.payload["deviceId"] == "dev123"


def test_session_id_comes_from_header_not_body():
    """Regression: the server returns sessionId in the frame HEADER, and the
    session key in the body. The client must read the id from the header."""
    reply = hm.build_frame(
        {"serial": 1, "cmd": 0, "key": "6wW6BoJQ097NKMD3", "status": 0},
        protocol_type="pk", key=hm.PK_KEY, session_id="SESS_ABC123",
    )
    fr = hm.parse_frame(reply, session_key=None)
    assert fr.session_id == "SESS_ABC123"          # from header
    assert "SessionId" not in fr.payload           # not in body
    assert fr.payload["key"] == "6wW6BoJQ097NKMD3"  # key is in body


def test_frames_from_buffer_handles_coalescing():
    key = b"0123456789abcdef"
    f1 = hm.build_frame({"cmd": 1, "serial": 1}, protocol_type="dk", key=key, session_id="S")
    f2 = hm.build_frame({"cmd": 2, "serial": 2}, protocol_type="dk", key=key, session_id="S")
    buf = bytearray(f1 + f2)
    frames = hm._frames_from_buffer(buf)
    assert len(frames) == 2
    assert len(buf) == 0
    # partial frame stays buffered
    buf = bytearray(f1 + f2[:10])
    frames = hm._frames_from_buffer(buf)
    assert len(frames) == 1
    assert bytes(buf) == f2[:10]


def test_access_record_person_and_method():
    r = hm.AccessRecord(
        message_id="m", device_id="d", time=1794725657, type=0,
        method_code=1, user_slot=1,
        text="George   unlocked with fingerprint.", sequence=10,
        battery_volts=7.34,
    )
    assert r.method == "fingerprint"
    assert r.person == "George"
    r2 = hm.AccessRecord(message_id="m", device_id="d", time=1, type=0,
                         method_code=2, user_slot=2,
                         text="Tatisor   unlocked with password.", sequence=11)
    assert r2.method == "password"
    assert r2.person == "Tatisor"


def test_unlock_method_map():
    assert hm.UNLOCK_METHODS[1] == "fingerprint"
    assert hm.UNLOCK_METHODS[2] == "password"
    assert hm.UNLOCK_METHODS[3] == "card"


if __name__ == "__main__":
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in funcs:
        fn()
        print(f"  PASS  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(funcs)} tests passed")
