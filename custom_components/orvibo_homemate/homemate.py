"""
Async client for the ORVIBO HomeMate cloud control protocol.

This is a clean-room re-implementation of the wire protocol used by the
ORVIBO Home / HomeMate Android app (package ``com.orvibo.homemate``,
analysed from version 5.2.6.308).  It lets you log in with your own
ORVIBO account and control devices (notably the S2 smart lock) by talking
to ORVIBO's servers exactly the way the app does.

It is "cloud-local": the Home Assistant instance holds a persistent TCP
session to the ORVIBO server and issues commands over it.  No ORVIBO phone
app, Google/Apple relay, or third-party bridge is involved.

-------------------------------------------------------------------------
PROTOCOL SUMMARY  (see PROTOCOL.md for the full reverse-engineering notes)
-------------------------------------------------------------------------
Transport : TCP to ``homemate.orvibo.com:10002`` (keep-alive).
Frame     : fixed 42-byte header + encrypted JSON body

    offset  size  field
    0       2     "hd"                         magic
    2       2     total length (u16, BE)       header + body
    4       2     protocol type ("pk" / "dk")  selects the key
    6       4     CRC32 of the *encrypted* body, as the 4 high... see below
    10      32    sessionId (ASCII, space-padded; 32 spaces if none yet)
    42      ..    AES-128-ECB(PKCS7) encrypted UTF-8 JSON

    The CRC field is the CRC32 of the encrypted body rendered as an
    8-char uppercase hex string, then those 8 hex chars are packed into
    4 bytes (two hex chars per byte, parsed as hex) -- see ``_crc_bytes``.

Crypto    : AES-128-ECB, PKCS7 padding.
            * protocol type "pk" -> key = PK_KEY ("khggd54865SNJHGF"),
              used for the handshake (cmd 0) and LAN discovery (cmd 86).
            * protocol type "dk" -> key = the per-session key string the
              server returns in the cmd-0 response; used for everything
              after the handshake, including login (cmd 2) and control
              (cmd 15).
            The 16-byte key string is used directly as the AES-128 key
            (no hashing).  Verified against the native libHomeMate_Security.so.

Handshake / command flow
    1. TCP connect.
    2. cmd 0  (requestServerKey, pt="pk")   -> { sessionId, key }
    3. cmd 2  (login,           pt="dk")    -> { userId, familyId, ... }
    4. cmd 4  (loadTable "device", pt="dk") -> device records (find the lock)
    5. cmd 15 (control,         pt="dk")    -> order="unlock" / "lock"

Every request JSON carries: cmd, serial, clientType=1, uniSerial,
serverRecord=false, ver, plus command-specific fields.  Responses are
correlated back to requests by ``serial``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Mutual TLS
# --------------------------------------------------------------------------
# The ORVIBO server requires the client to present a certificate (mutual TLS)
# and the app pins the server to ORVIBO's own CA. Both the client keystore
# (res/raw/client.bks) and the trust store (res/raw/clienttrust.bks) ship in
# the app with the password "ksund76kN22_wQ"; they are extracted to PEM here.
# The client certificate is a shared credential embedded in every copy of the
# public app -- it identifies "the HomeMate app", not an individual user.
_CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CLIENT_CERT = os.path.join(_CERT_DIR, "client_cert.pem")
CLIENT_KEY = os.path.join(_CERT_DIR, "client_key.pem")
SERVER_CA = os.path.join(_CERT_DIR, "server_ca.pem")


def build_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """SSL context mirroring the app: client cert + pinned ORVIBO CA.

    The 2018 ORVIBO cert has no SubjectAltName, so hostname verification is
    disabled (Python requires a SAN and would reject it); the connection is
    still authenticated by pinning ORVIBO's CA. Set ``verify=False`` to skip
    server verification entirely if ORVIBO rotates to a cert this CA no
    longer covers (the client cert is still sent, which is what the server
    requires).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    ctx.check_hostname = False
    if verify and os.path.exists(SERVER_CA):
        ctx.load_verify_locations(cafile=SERVER_CA)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    # ORVIBO's stack negotiates older TLS; allow down to TLS 1.0 for the
    # legacy endpoint but let OpenSSL pick the best both support.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    return ctx

# --------------------------------------------------------------------------
# Protocol constants (all extracted from the decompiled app / native lib)
# --------------------------------------------------------------------------
DEFAULT_HOST = "homemate.orvibo.com"
DEFAULT_PORT = 10002

PK_KEY = b"khggd54865SNJHGF"  # libHomeMate_Security.so -> global symbol `pkKey`

MAGIC = b"hd"
HEADER_LEN = 42
_SESSION_FIELD_LEN = 32

# Command codes (core/c.java + dispatch in core/g.java)
CMD_REQUEST_KEY = 0      # requestServerKey  (pt="pk")
CMD_LOGIN = 2           # login             (userName + MD5(password))
CMD_LOAD_TABLE = 4      # hub/family table sync (per-gateway)
CMD_CONTROL = 15        # control device    (order + value1..4)
CMD_DISCOVER = 86       # LAN UDP discovery (pt="pk")
CMD_QUERY_WIFI_DEVICE = 147  # bulk sync for Wi-Fi devices (lists the lock)
CMD_STATUS_RECORD = 130      # access/event records (who/when/method)

# Lock "order" values (data/k0.java)
ORDER_UNLOCK = "unlock"
ORDER_LOCK = "lock"

# Table names (data/TableName.java)
TABLE_DEVICE = "device"
TABLE_DEVICE_STATUS = "deviceStatus"
TABLE_FAMILY = "family"

# Client version string sent as "ver"; mirrors the analysed app build.
CLIENT_VER = "5.2.6.308"

CONNECT_TIMEOUT = 10.0
REQUEST_TIMEOUT = 15.0


class HomeMateError(Exception):
    """Base error for the HomeMate client."""


class HomeMateAuthError(HomeMateError):
    """Login failed / credentials rejected."""


class HomeMateTimeout(HomeMateError):
    """A request did not get a response in time."""


# --------------------------------------------------------------------------
# Crypto + framing (pure functions, fully unit-testable offline)
# --------------------------------------------------------------------------
def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad < 1 or pad > 16 or pad > len(data):
        # Not validly padded; return as-is rather than corrupting.
        return data
    return data[:-pad]


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128-ECB + PKCS7, key used directly (matches native AesEncryptEx)."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(_pkcs7_pad(plaintext)) + enc.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise HomeMateError("ciphertext length not a multiple of 16")
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return _pkcs7_unpad(dec.update(ciphertext) + dec.finalize())


def _crc_hex(body: bytes) -> str:
    """CRC32 as 8-char uppercase hex, zero-padded (util/t.java#h)."""
    return format(zlib.crc32(body) & 0xFFFFFFFF, "08X")


def _crc_bytes(body: bytes) -> bytes:
    """
    The 4 CRC bytes written at offset 6.

    The app renders CRC32 as an 8-char hex string and writes it with
    ``b5.A(str)`` which parses the string two hex chars at a time into one
    byte each -> 4 bytes.  i.e. it is just the big-endian CRC32 value.
    """
    return bytes.fromhex(_crc_hex(body))


def md5_password(password: str) -> str:
    """Password hash used by login: uppercase hex MD5 of the plaintext."""
    return hashlib.md5(password.encode("utf-8")).hexdigest().upper()


def build_frame(payload: dict[str, Any], *, protocol_type: str, key: bytes,
                session_id: str | None) -> bytes:
    """Serialise + encrypt + frame a request JSON into wire bytes."""
    body_plain = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = aes_encrypt(body_plain, key)

    total_len = HEADER_LEN + len(body)
    header = bytearray(HEADER_LEN)
    header[0:2] = MAGIC
    header[2:4] = total_len.to_bytes(2, "big")
    pt = protocol_type.encode("ascii")
    if len(pt) != 2:
        raise HomeMateError("protocol type must be 2 chars")
    header[4:6] = pt
    header[6:10] = _crc_bytes(body)

    sid = (session_id or "").ljust(_SESSION_FIELD_LEN)[:_SESSION_FIELD_LEN]
    header[10:42] = sid.encode("ascii", "replace")

    return bytes(header) + body


@dataclass
class Frame:
    protocol_type: str
    session_id: str
    payload: dict[str, Any]


def parse_frame(raw: bytes, session_key: bytes | None) -> Frame:
    """Parse one complete wire frame into its decrypted JSON payload."""
    if len(raw) < HEADER_LEN or raw[0:2] != MAGIC:
        raise HomeMateError("bad frame header")
    total_len = int.from_bytes(raw[2:4], "big")
    protocol_type = raw[4:6].decode("ascii", "replace")
    crc_field = raw[6:10]
    session_id = raw[10:42].decode("ascii", "replace").strip()
    body = raw[HEADER_LEN:total_len]

    if _crc_bytes(body) != crc_field:
        _LOGGER.warning("CRC mismatch on incoming frame (pt=%s)", protocol_type)

    if protocol_type == "pk":
        key = PK_KEY
    else:
        if session_key is None:
            raise HomeMateError("session key required to decrypt pt=%s" % protocol_type)
        key = session_key

    try:
        plain = aes_decrypt(body, key)
        payload = json.loads(plain.decode("utf-8"))
    except Exception as err:  # noqa: BLE001
        raise HomeMateError(f"failed to decrypt/parse body: {err}") from err
    return Frame(protocol_type=protocol_type, session_id=session_id, payload=payload)


def _frames_from_buffer(buf: bytearray) -> list[bytes]:
    """Pull all complete frames out of a receive buffer (handles TCP coalescing)."""
    out: list[bytes] = []
    while len(buf) >= HEADER_LEN and buf[0:2] == MAGIC:
        total_len = int.from_bytes(buf[2:4], "big")
        if total_len < HEADER_LEN or len(buf) < total_len:
            break
        out.append(bytes(buf[:total_len]))
        del buf[:total_len]
    return out


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Device:
    device_id: str
    uid: str
    name: str
    device_type: int
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


# Unlock-method code (StatusRecord.value4). Derived from observed records and
# the app's lock constants; the server also sends a ready-made ``text``.
UNLOCK_METHODS = {
    1: "fingerprint",
    2: "password",
    3: "card",
    4: "mechanical_key",
    5: "remote",
    6: "face",
    7: "temporary_password",
    8: "dynamic_password",
}

# Lock device type seen in the account (cmd 147 device record).
DEVICE_TYPE_LOCK = 107


@dataclass
class AccessRecord:
    """One lock event: who, when, by what method (plus the raw row)."""
    message_id: str
    device_id: str
    time: int              # epoch seconds of the event
    type: int              # 0 = unlock; other values = door-ajar/alarms
    method_code: int       # value4
    user_slot: int         # value2 (authorizedId / credential slot)
    text: str              # server-provided human message, e.g. "George unlocked with fingerprint."
    sequence: int
    battery_volts: float | None = None   # value3/100 (e.g. 734 -> 7.34 V)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def method(self) -> str:
        return UNLOCK_METHODS.get(self.method_code, f"method_{self.method_code}")

    @property
    def person(self) -> str:
        """Best-effort person name parsed from the server text."""
        t = (self.text or "").strip()
        for sep in (" unlocked", " locked", " opened", " "):
            if sep in t:
                return t.split(sep)[0].strip()
        return t


# --------------------------------------------------------------------------
# Async client
# --------------------------------------------------------------------------
class HomeMateClient:
    """Minimal async client for the HomeMate cloud control protocol."""

    def __init__(self, username: str, password: str, *,
                 host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 phone_id: str = "homeassistant-orvibo",
                 use_tls: bool = True, verify_ssl: bool = False,
                 ssl_context: "ssl.SSLContext | None" = None) -> None:
        self._username = username
        # password may be given already-hashed (32 hex chars) or plaintext
        self._md5pw = password.upper() if _looks_md5(password) else md5_password(password)
        self._host = host
        self._port = port
        self._phone_id = phone_id
        self._use_tls = use_tls
        self._verify_ssl = verify_ssl
        # In Home Assistant, pass a context built in an executor (load_cert_chain
        # does blocking file I/O). Standalone callers can let it build lazily.
        self._ssl_ctx = ssl_context

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._rx_task: asyncio.Task | None = None
        self._buf = bytearray()

        self._session_id: str | None = None
        self._session_key: bytes | None = None
        self.user_id: str | None = None
        self.family_id: str | None = None
        # [(familyId, gatewayUid), ...] discovered from the login reply
        self.gateways: list[tuple[str, str]] = []

        self._serial = int(time.time()) & 0x7FFFFFFF
        self._pending: dict[int, asyncio.Future] = {}
        # per-serial page accumulator: serial -> {"session_id": str, "scalars": dict, "lists": dict}
        self._accum: dict[int, dict] = {}
        self._lock = asyncio.Lock()
        self._listeners: list = []  # callbacks for unsolicited status frames

    # -- connection lifecycle ------------------------------------------
    async def connect(self) -> None:
        if self._use_tls and self._ssl_ctx is None:
            # Lazy build for standalone (non-HA) callers; HA passes a context
            # built in an executor to avoid blocking the event loop.
            self._ssl_ctx = build_ssl_context(self._verify_ssl)
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port, ssl=self._ssl_ctx,
                                    server_hostname=self._host if self._ssl_ctx else None),
            CONNECT_TIMEOUT,
        )
        self._rx_task = asyncio.ensure_future(self._rx_loop())
        await self._request_server_key()
        await self._login()

    async def close(self) -> None:
        if self._rx_task:
            self._rx_task.cancel()
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._reader = self._writer = None

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()

    def add_status_listener(self, callback) -> None:
        """Register callback(payload: dict) for unsolicited status pushes."""
        self._listeners.append(callback)

    # -- receive loop --------------------------------------------------
    async def _rx_loop(self) -> None:
        assert self._reader is not None
        try:
            while True:
                chunk = await self._reader.read(4096)
                if not chunk:
                    break
                self._buf.extend(chunk)
                for raw in _frames_from_buffer(self._buf):
                    self._handle_raw(raw)
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("rx loop ended: %s", err)
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(HomeMateError("connection closed"))
            self._pending.clear()
            self._accum.clear()

    def _handle_raw(self, raw: bytes) -> None:
        try:
            frame = parse_frame(raw, self._session_key)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("drop unparseable frame: %s", err)
            return
        serial = _as_int(frame.payload.get("serial"))
        if serial is not None and serial in self._pending:
            self._accumulate_page(serial, frame)
            return
        # Unsolicited (status report / push) -> notify listeners
        for cb in list(self._listeners):
            try:
                cb(frame.payload)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("status listener error")

    def _accumulate_page(self, serial: int, frame: Frame) -> None:
        """Merge a (possibly paginated) response; resolve the future on the last page.

        Multi-table/paginated replies (e.g. cmd 147) arrive as several frames
        sharing one serial, with ``tPage``/``pageIndex``. Scalars are taken
        from the first page; list fields are concatenated across pages.
        """
        payload = frame.payload
        acc = self._accum.setdefault(
            serial, {"session_id": frame.session_id, "scalars": {}, "lists": {}}
        )
        for k, v in payload.items():
            if isinstance(v, list):
                acc["lists"].setdefault(k, []).extend(v)
            else:
                acc["scalars"].setdefault(k, v)

        tpage = _as_int(payload.get("tPage"), default=0) or 0
        pindex = _as_int(payload.get("pageIndex"), default=0) or 0
        last_page = tpage <= 1 or (pindex + 1) >= tpage
        if not last_page:
            return

        merged = dict(acc["scalars"])
        merged.update(acc["lists"])
        self._accum.pop(serial, None)
        fut = self._pending.pop(serial, None)
        if fut and not fut.done():
            fut.set_result(Frame(protocol_type=frame.protocol_type,
                                 session_id=acc["session_id"], payload=merged))

    # -- request/response ----------------------------------------------
    def _next_serial(self) -> int:
        self._serial = (self._serial + 1) & 0x7FFFFFFF
        return self._serial

    async def _send(self, cmd: int, fields: dict[str, Any], *,
                    protocol_type: str, key: bytes,
                    expect_response: bool = True) -> Frame:
        if self._writer is None:
            raise HomeMateError("not connected")

        serial = self._next_serial()
        payload: dict[str, Any] = {
            "cmd": cmd,
            "serial": serial,
            "clientType": 1,
            "uniSerial": int(time.time() * 1000),
            "serverRecord": False,
            "ver": CLIENT_VER,
        }
        payload.update(fields)

        frame = build_frame(payload, protocol_type=protocol_type, key=key,
                            session_id=self._session_id)

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        if expect_response:
            self._pending[serial] = fut

        async with self._lock:
            self._writer.write(frame)
            await self._writer.drain()

        if not expect_response:
            return Frame(protocol_type=protocol_type, session_id=self._session_id or "",
                         payload={})
        try:
            result: Frame = await asyncio.wait_for(fut, REQUEST_TIMEOUT)
        except asyncio.TimeoutError as err:
            self._pending.pop(serial, None)
            raise HomeMateTimeout(f"no response for cmd {cmd}") from err
        return result

    # -- protocol steps ------------------------------------------------
    async def _request_server_key(self) -> None:
        frame = await self._send(
            CMD_REQUEST_KEY,
            {
                "source": 1,
                "softwareVersion": CLIENT_VER,
                "systemVersion": "HomeAssistant",
                "hardwareVersion": "HomeAssistant",
                "language": "en",
                "identifier": self._phone_id,
                "phoneName": "Home Assistant",
            },
            protocol_type="pk",
            key=PK_KEY,
        )
        # The session id lives in the response FRAME HEADER (not the body);
        # the body carries the session key. Both are needed for every
        # subsequent frame (sessionId -> header, key -> AES).
        if frame.session_id:
            self._session_id = frame.session_id
        elif frame.payload.get("SessionId"):
            self._session_id = frame.payload["SessionId"]
        key = frame.payload.get("key")
        if not key:
            raise HomeMateError(f"no session key in handshake response: {frame.payload}")
        self._session_key = _as_key(key)
        _LOGGER.debug("handshake ok: sessionId=%r", self._session_id)

    async def _login(self) -> None:
        resp = (await self._send(
            CMD_LOGIN,
            {
                "userName": self._username,
                "password": self._md5pw,
                "type": 3,
                "needAccountDetailError": True,
            },
            protocol_type="dk",
            key=self._session_key,  # type: ignore[arg-type]
        )).payload
        # The result code is in "status" (0 = OK); "result" kept as a fallback.
        status = _as_int(resp.get("status"), default=None)
        if status is None:
            status = _as_int(resp.get("result"), default=0)
        if status not in (0, None):
            raise HomeMateAuthError(f"login failed, status={status} "
                                    f"(12 = bad account/password): {resp}")
        self.user_id = (resp.get("userId") or resp.get("userid") or "")
        # The login reply carries the family list (each with its gateways).
        families = resp.get("familyList") or []
        self.gateways = []
        for fam in families:
            fid = fam.get("familyId") or fam.get("familyid") or ""
            if fid and not self.family_id:
                self.family_id = fid
            for gw in (fam.get("gatewayList") or []):
                guid = gw.get("uid")
                if guid:
                    self.gateways.append((fid, guid))
        self.family_id = self.family_id or resp.get("familyId") or ""
        _LOGGER.debug("login ok: userId=%s familyId=%s gateways=%s",
                      self.user_id, self.family_id, self.gateways)

    # -- public API ----------------------------------------------------
    async def get_devices(self) -> list[Device]:
        """List Wi-Fi devices (cmd 147). The S2 lock appears in the ``device`` table."""
        resp = (await self._send(
            CMD_QUERY_WIFI_DEVICE,
            {
                "userName": self._username,
                "userId": self.user_id or "",
                "familyId": self.family_id or "",
                "pageIndex": 0,
                "dataType": "",
                "lastUpdateTime": 0,
                "deviceFlag": 0,
            },
            protocol_type="dk",
            key=self._session_key,  # type: ignore[arg-type]
        )).payload
        devices: list[Device] = []
        for rec in (resp.get("device") or []):
            if not isinstance(rec, dict):
                continue
            did = rec.get("deviceId", "")
            if not did:
                continue
            devices.append(Device(
                device_id=did,
                uid=rec.get("uid", ""),
                name=rec.get("deviceName") or rec.get("name") or "",
                device_type=_as_int(rec.get("deviceType"), default=-1),
                model=rec.get("model", ""),
                raw=rec,
            ))
        return devices

    async def get_records(self, uid: str, device_id: str, *,
                          max_sequence: int = -1, min_sequence: int = -1,
                          count: int = 20, type_filter: int = 0) -> list[AccessRecord]:
        """Fetch access/event records for a lock (cmd 130).

        These are stored on ORVIBO's server, so they are retrievable even while
        the lock's Wi-Fi is asleep. Defaults return the newest ``count`` events.
        For older pages, pass ``max_sequence`` = (oldest sequence seen - 1).
        """
        resp = (await self._send(
            CMD_STATUS_RECORD,
            {
                "uid": uid,
                "userName": self._username,
                "familyId": self.family_id or "",
                "deviceId": device_id,
                "maxSequence": max_sequence,
                "minSequence": min_sequence,
                "readCount": count,
                "type": type_filter,
            },
            protocol_type="dk",
            key=self._session_key,  # type: ignore[arg-type]
        )).payload
        out: list[AccessRecord] = []
        for r in (resp.get("statusRecordList") or []):
            if not isinstance(r, dict):
                continue
            v3 = _as_int(r.get("value3"))
            out.append(AccessRecord(
                message_id=r.get("messageId", ""),
                device_id=r.get("deviceId", ""),
                time=_as_int(r.get("time"), default=0) or 0,
                type=_as_int(r.get("type"), default=0) or 0,
                method_code=_as_int(r.get("value4"), default=0) or 0,
                user_slot=_as_int(r.get("value2"), default=0) or 0,
                text=(r.get("text") or "").strip(),
                sequence=_as_int(r.get("sequence"), default=0) or 0,
                battery_volts=(v3 / 100.0) if v3 and 300 <= v3 <= 900 else None,
                raw=r,
            ))
        return out


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _looks_md5(s: str) -> bool:
    return len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s)


def _as_int(val: Any, default: int | None = None) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _extract_records(resp: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull table rows out of a cmd-4 reply.

    Single-table loads return rows in ``playLoad`` (a list, or a JSON string
    of a list). ``data``/``dataList`` are accepted as fallbacks.
    """
    pl = resp.get("playLoad")
    if isinstance(pl, str):
        try:
            pl = json.loads(pl)
        except (ValueError, TypeError):
            pl = None
    if isinstance(pl, list):
        return [r for r in pl if isinstance(r, dict)]
    if isinstance(pl, dict):
        for v in pl.values():
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    data = resp.get("data") or resp.get("dataList")
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def _as_key(key: Any) -> bytes:
    """The session key string -> 16 AES bytes (used directly)."""
    if isinstance(key, bytes):
        return key[:16].ljust(16, b"\0")
    kb = str(key).encode("utf-8")
    if len(kb) >= 16:
        return kb[:16]
    # Shorter strings should not happen, but pad defensively.
    return kb.ljust(16, b"\0")
