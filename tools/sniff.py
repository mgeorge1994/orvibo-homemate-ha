#!/usr/bin/env python3
"""
Standalone calibration / smoke-test tool for the HomeMate client.

Run this on any machine (your laptop, or the HA host) to confirm the
protocol against your real ORVIBO account BEFORE relying on the Home
Assistant integration. It logs in, prints every decrypted server frame,
lists your devices, and (optionally) locks/unlocks a chosen device.

    pip install cryptography
    python tools/sniff.py --user you@example.com --password 'secret'
    python tools/sniff.py --user ... --password ... --list
    python tools/sniff.py --user ... --password ... --unlock <deviceId> <uid>

Nothing here talks to anything except ORVIBO's own server, exactly as the
app does. Use it to fill in the "needs live confirmation" items in
PROTOCOL.md (session key field names, deviceType, battery key, etc.).
"""
import argparse
import asyncio
import logging
import os
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "custom_components", "orvibo_homemate"),
)
import homemate as hm  # noqa: E402


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--host", default=hm.DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=hm.DEFAULT_PORT)
    ap.add_argument("--list", action="store_true", help="list devices and exit")
    ap.add_argument("--status", action="store_true", help="dump deviceStatus table")
    ap.add_argument("--unlock", nargs=2, metavar=("DEVICE_ID", "UID"))
    ap.add_argument("--lock", nargs=2, metavar=("DEVICE_ID", "UID"))
    ap.add_argument("--watch", type=int, default=0, help="seconds to watch for pushes")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")

    client = hm.HomeMateClient(args.user, args.password, host=args.host, port=args.port)
    client.add_status_listener(lambda p: print("PUSH:", p))

    print(f"Connecting to {args.host}:{args.port} ...")
    await client.connect()
    print(f"Logged in. userId={client.user_id} familyId={client.family_id}")

    devices = await client.get_devices()
    print(f"\n{len(devices)} device(s):")
    for d in devices:
        print(f"  name={d.name!r:30} type={d.device_type:<4} model={d.model!r:12} "
              f"deviceId={d.device_id} uid={d.uid}")

    if args.status:
        print("\ndeviceStatus:")
        for s in await client.get_device_status():
            print(" ", s)

    if args.unlock:
        print("\nunlock ->", await client.unlock(args.unlock[1], args.unlock[0]))
    if args.lock:
        print("\nlock ->", await client.lock(args.lock[1], args.lock[0]))

    if args.watch:
        print(f"\nWatching for pushes for {args.watch}s ...")
        await asyncio.sleep(args.watch)

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
