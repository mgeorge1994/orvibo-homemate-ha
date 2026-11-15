#!/usr/bin/env python3
"""
Connection diagnostic for the ORVIBO HomeMate integration.

Run this ON A MACHINE ON THE SAME NETWORK AS (or that can reach) the
internet the way your HA host does -- ideally the HA host itself. It does
not need Home Assistant installed, only Python 3 + `cryptography`.

    pip install cryptography
    python tools/diagnose.py --user you@example.com --password 'secret'

It walks every stage and tells you exactly where it breaks:
  1. DNS resolve of the server host
  2. raw TCP connect  (tries ports 10002,10001,10003,10004,10005)
  3. TLS handshake with ORVIBO's client certificate (mutual TLS)
  4. handshake request (cmd 0) + prints the server's decrypted reply
  5. login (cmd 2)

Paste the full output back and it pinpoints the fix (port, TLS, or a
response-field-name mismatch). It only ever talks to ORVIBO's own server.
"""
import argparse
import asyncio
import os
import socket
import ssl
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "custom_components", "orvibo_homemate"),
)
import homemate as hm  # noqa: E402

PORTS = [10002, 10001, 10003, 10004, 10005]


def _stage(msg):
    print(f"\n=== {msg} ===")


async def try_combo(host, port, use_tls, verify, user, pw):
    label = f"{host}:{port} tls={'on' if use_tls else 'off'} verify={verify}"
    print(f"\n--- trying {label} ---")
    ctx = hm.build_ssl_context(verify) if use_tls else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=ctx,
                server_hostname=host if ctx else None),
            timeout=8,
        )
    except ssl.SSLError as e:
        print(f"  TLS handshake FAILED: {e}")
        return False
    except (OSError, asyncio.TimeoutError) as e:
        print(f"  TCP/TLS connect FAILED: {type(e).__name__}: {e}")
        return False
    print("  TCP+TLS connect: OK")

    # Send cmd 0 (requestServerKey) manually and dump the reply.
    payload = {
        "cmd": hm.CMD_REQUEST_KEY, "serial": 10101, "clientType": 1,
        "uniSerial": 1, "serverRecord": False, "ver": hm.CLIENT_VER,
        "source": 1, "softwareVersion": hm.CLIENT_VER,
        "systemVersion": "diag", "hardwareVersion": "diag",
        "language": "en", "identifier": "ha-diagnose", "phoneName": "diag",
    }
    frame = hm.build_frame(payload, protocol_type="pk", key=hm.PK_KEY, session_id=None)
    writer.write(frame)
    await writer.drain()
    try:
        raw = await asyncio.wait_for(reader.read(4096), timeout=8)
    except asyncio.TimeoutError:
        print("  sent cmd 0 but got NO reply (timeout). Server may expect a "
              "different port/handshake.")
        writer.close()
        return False
    if not raw:
        print("  server closed the connection after cmd 0.")
        writer.close()
        return False
    print(f"  cmd 0 reply: {len(raw)} bytes, header={raw[:10].hex()}")
    try:
        fr = hm.parse_frame(raw, session_key=None)
        print(f"  DECRYPTED handshake reply (pt={fr.protocol_type}):")
        print("   ", fr.payload)
        if fr.payload.get("key"):
            print("  >>> session key received -> this port/TLS combo WORKS <<<")
            writer.close()
            return True
        print("  (no 'key' field -- note the exact keys above so the client "
              "can be adjusted)")
    except Exception as e:  # noqa: BLE001
        print(f"  could not decrypt reply: {e}")
        print(f"  raw body hex: {raw[10:60].hex()}")
    writer.close()
    return False


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--host", default=hm.DEFAULT_HOST)
    ap.add_argument("--ports", default=",".join(str(p) for p in PORTS),
                    help="comma-separated ports to try")
    args = ap.parse_args()

    _stage("1. DNS")
    try:
        ips = socket.gethostbyname_ex(args.host)
        print(f"  {args.host} -> {ips[2]}")
    except Exception as e:  # noqa: BLE001
        print(f"  DNS FAILED: {e}  (your network can't resolve the host)")
        return

    _stage("2-4. connect / TLS / handshake")
    ports = [int(p) for p in args.ports.split(",")]
    ok = False
    for port in ports:
        # Prefer TLS (that's what the app uses); fall back to plain.
        if await try_combo(args.host, port, True, False, args.user, args.password):
            ok = True
            break
    if not ok:
        print("\nNo TLS combo returned a session key. Trying PLAIN TCP as a "
              "last resort (unexpected for this server):")
        for port in ports:
            if await try_combo(args.host, port, False, False, args.user, args.password):
                ok = True
                break

    _stage("result")
    if ok:
        print("A working port/TLS combo was found (see '>>> WORKS' above).")
        print("If it differs from homemate.orvibo.com:10002 + TLS, set the "
              "host/port in the integration options.")
    else:
        print("No combo completed the handshake. Copy ALL output above back "
              "so the handshake/port can be corrected.")


if __name__ == "__main__":
    asyncio.run(main())
