# ORVIBO HomeMate — Home Assistant integration (S2 smart lock)

Control your **ORVIBO S2 Wi-Fi smart lock** from Home Assistant by logging in
with your own ORVIBO account and talking to ORVIBO's server **the same way the
ORVIBO Home app does** — no phone app in the loop, no third-party cloud, no
IFTTT/Google/Alexa relay.

It is built from a clean-room reverse-engineering of the ORVIBO Home Android
app (`com.orvibo.homemate` 5.2.6.308) and its native crypto library. The full
protocol is documented in [`PROTOCOL.md`](PROTOCOL.md).

> **Honest scope note.** A *fully offline, LAN-only* integration is not
> achievable for the S2: it's a battery lock (10×AA, ~800-day life) whose
> Wi-Fi sleeps, so it has no always-on local endpoint. This integration is
> **"cloud-local"** — Home Assistant holds a direct session to ORVIBO's
> server and controls the lock over it. That's the practical way to get the
> lock into HA without the phone app or a third-party cloud. See the end of
> `PROTOCOL.md` for why.

---

## What works

- **Lock / unlock** the S2 (`lock` entity).
- **Lock state** (locked / unlocked), updated both on poll and from the
  lock's own asynchronous status pushes.
- **Battery** sensor (best-effort; key auto-detected — see notes).
- Config flow (UI setup) with your ORVIBO email/phone + password.

## Status / confidence

The wire protocol — framing, AES-128-ECB/PKCS7 crypto, CRC32, command codes
(0/2/4/15), and JSON envelope — is taken directly from the app and the native
`.so`, and the crypto is unit-tested against the FIPS-197 AES vector
(`tests/`, 11/11 passing). What could **not** be pinned by static analysis
alone are a few live server response details (exact key names, the lock's
`deviceType`, the battery field, and whether the server redirects after the
handshake). These are listed in `PROTOCOL.md §7`.

**Before trusting it, calibrate once** with the standalone tool:

```bash
pip install cryptography
python tools/sniff.py --user you@example.com --password 'yourpass' --list
```

That logs in, prints every decrypted server frame, and lists your devices
(with their `deviceType`, `deviceId`, `uid`). Use the output to:

1. Confirm login succeeds and note your lock's `deviceType` → put it in
   `custom_components/orvibo_homemate/const.py` → `LOCK_DEVICE_TYPES`.
2. Confirm unlock works: `python tools/sniff.py ... --unlock <deviceId> <uid>`
   (enable **remote unlock** on the lock in the ORVIBO app first — ORVIBO
   gates remote unlock per-lock).
3. Note the battery key in `--status` output if the sensor shows `unknown`.

If `sniff.py` works end-to-end, the HA integration will too.

---

## Install

1. Copy `custom_components/orvibo_homemate/` into your Home Assistant
   `config/custom_components/` directory:

   ```
   config/custom_components/orvibo_homemate/
   ```

2. Restart Home Assistant.
3. **Settings → Devices & Services → Add Integration → "ORVIBO HomeMate"**.
4. Enter the ORVIBO account email/phone and password you use in the app.
   (Host/port default to `homemate.orvibo.com:10002`.)

Your lock appears as a `lock.` entity plus a battery sensor.

### HACS (optional)
Add this repo as a custom repository (category: Integration), then install
as usual.

---

## How it works (short version)

```
Home Assistant ──TCP:10002──> homemate.orvibo.com
   cmd 0  requestServerKey  (AES key "khggd54865SNJHGF")  -> session key
   cmd 2  login  (user + MD5 password, session-key AES)
   cmd 4  loadTable "device"            -> finds the S2
   cmd 15 control order="unlock"/"lock" -> operates the lock
```

Frames are `"hd"` + length + protocol-type + CRC32 + 32-byte sessionId +
AES-128-ECB(PKCS7) JSON. Full details in [`PROTOCOL.md`](PROTOCOL.md).

---

## Troubleshooting

Enable debug logging to see decrypted frames:

```yaml
# configuration.yaml
logger:
  default: warning
  logs:
    custom_components.orvibo_homemate: debug
```

- **"invalid_auth"** — wrong ORVIBO email/phone or password. The password is
  hashed (MD5, uppercase) before sending, same as the app.
- **Lock not created** — your lock's `deviceType` isn't in
  `LOCK_DEVICE_TYPES`. Check the log line listing discovered device types and
  add yours.
- **Unlock rejected (non-zero result), lock works** — enable *remote unlock*
  on the lock in the ORVIBO app.
- **Battery shows unknown** — add the right key to `_BATTERY_KEYS` in
  `sensor.py` (see `--status` output from `sniff.py`).

---

## Legal / ethics

This is an interoperability project for a device **you own**, using **your
own** ORVIBO credentials against ORVIBO's own service — comparable to the
official app. It ships no ORVIBO code or binaries; the native crypto is
re-implemented from documented standard algorithms (AES-128-ECB). Respect
ORVIBO's terms of service and don't hammer their servers. No warranty.

## Project layout

```
custom_components/orvibo_homemate/
  homemate.py      # the protocol client (crypto, framing, async session)
  __init__.py      # integration setup
  config_flow.py   # UI setup
  coordinator.py   # persistent session + status cache
  lock.py          # lock entity
  sensor.py        # battery sensor
  const.py         # tunables (LOCK_DEVICE_TYPES, host/port, intervals)
  translations/
tools/sniff.py     # standalone login/control/calibration tool
tests/             # offline crypto + framing tests (run: python tests/test_protocol.py)
PROTOCOL.md        # full reverse-engineering writeup
```
