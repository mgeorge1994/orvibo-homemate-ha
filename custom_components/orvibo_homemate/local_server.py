"""
Local-cloud server for ORVIBO HomeMate.

Runs inside Home Assistant and impersonates ORVIBO's cloud for the lock. Point
`homemate.orvibo.com` at HA's IP in your DNS (e.g. Technitium); when the lock
wakes it connects here instead. Because we act as the server we choose the
session key, so we can decrypt everything the lock reports — access events,
state, battery, alarms — with no ORVIBO cloud involved.

The lock->server direction of ORVIBO's protocol is not fully documented, so
this server:
  * completes the TLS + cmd-0 handshake (hands the lock a session key we pick),
  * generically ACKs every other frame so the lock keeps talking,
  * decodes any frame that looks like an access record / status and hands it to
    a callback,
  * logs every frame at debug level so unrecognized shapes can be mapped.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import ssl
from collections.abc import Awaitable, Callable
from typing import Any

from .homemate import (
    PK_KEY,
    AccessRecord,
    _as_int,
    build_frame,
    parse_frame,
    _frames_from_buffer,
    CLIENT_CERT,
    CLIENT_KEY,
)

_LOGGER = logging.getLogger(__name__)

FrameCb = Callable[[str, dict[str, Any]], Awaitable[None] | None]


def build_server_ssl_context() -> ssl.SSLContext:
    """TLS server context presenting ORVIBO's cert; accepts any client cert.

    Does blocking file I/O (load_cert_chain) — build it in an executor, not the
    event loop.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def records_from_payload(payload: dict[str, Any]) -> list[AccessRecord]:
    """Extract access records from a frame the lock pushed.

    Handles both a ``statusRecordList`` array and a single inline record
    (a row carrying ``text`` / ``value4`` / ``time``).
    """
    rows: list[dict] = []
    lst = payload.get("statusRecordList")
    if isinstance(lst, list):
        rows.extend(r for r in lst if isinstance(r, dict))
    # some pushes deliver a single record inline
    if not rows and (payload.get("text") or payload.get("messageId")) and \
            payload.get("deviceId"):
        rows.append(payload)

    out: list[AccessRecord] = []
    for r in rows:
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


class LocalServer:
    """Asyncio TLS server that the lock connects to as its 'cloud'."""

    def __init__(self, host: str, port: int, on_frame: FrameCb,
                 ssl_context: ssl.SSLContext) -> None:
        self._host = host
        self._port = port
        self._on_frame = on_frame
        self._ssl_ctx = ssl_context
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._port, ssl=self._ssl_ctx,
        )
        socks = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
        _LOGGER.info("ORVIBO local server listening on %s", socks)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        _LOGGER.info("Lock connected from %s", peer)
        session_key: bytes | None = None
        session_id = secrets.token_hex(16)
        buf = bytearray()
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                for raw in _frames_from_buffer(buf):
                    session_key = await self._handle_frame(
                        raw, writer, session_key, session_id)
        except (asyncio.CancelledError, ConnectionError):
            pass
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("local client error: %s", err)
        finally:
            _LOGGER.info("Lock disconnected (%s)", peer)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _handle_frame(self, raw: bytes, writer: asyncio.StreamWriter,
                            session_key: bytes | None, session_id: str) -> bytes | None:
        try:
            frame = parse_frame(raw, session_key)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("local: undecodable frame (%s) hex=%s", err, raw[:48].hex())
            return session_key
        payload = frame.payload
        cmd = _as_int(payload.get("cmd"))
        serial = payload.get("serial")
        _LOGGER.debug("local <= pt=%s cmd=%s serial=%s payload=%s",
                      frame.protocol_type, cmd, serial, payload)

        if cmd == 0:
            # We are the server: choose the session key and hand it back.
            session_key = secrets.token_bytes(8).hex().encode()[:16]
            reply = {"serial": serial, "cmd": 0, "key": session_key.decode(),
                     "status": 0}
            writer.write(build_frame(reply, protocol_type="pk", key=PK_KEY,
                                     session_id=session_id))
            await writer.drain()
            _LOGGER.info("local: handshake complete, session established")
            return session_key

        # Generic success ACK so the lock continues its session.
        ack = {"serial": serial, "cmd": cmd, "status": 0}
        if session_key is not None:
            writer.write(build_frame(ack, protocol_type="dk", key=session_key,
                                     session_id=session_id))
            await writer.drain()

        # Hand the decoded frame to the coordinator for entity updates.
        try:
            res = self._on_frame(frame.protocol_type, payload)
            if asyncio.iscoroutine(res):
                await res
        except Exception:  # noqa: BLE001
            _LOGGER.exception("local: on_frame handler error")
        return session_key
