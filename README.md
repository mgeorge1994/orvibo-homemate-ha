# ORVIBO HomeMate — Home Assistant access-log integration (S2 smart lock)

Bring your **ORVIBO S2 smart lock's access log into Home Assistant** — who unlocked
the door, when, and with what method (fingerprint / password / card / key), plus
door and alarm events — by logging in with your own ORVIBO account and reading the
records ORVIBO stores on its server, exactly the way the ORVIBO Home app does.

Built from a clean-room reverse-engineering of the ORVIBO Home Android app
(`com.orvibo.homemate` 5.2.6.308). Full protocol notes in [`PROTOCOL.md`](PROTOCOL.md).

> **Why logs, not lock/unlock?** The S2 is a battery lock (10×AA); its Wi‑Fi
> radio sleeps, so it holds no live cloud connection and can't be commanded
> on demand (confirmed against a live account — the server reports it offline
> even while the app shows a Bluetooth link). But every access event **is**
> stored server-side, so reading the log works reliably regardless of whether
> the lock is awake. That's what this integration does.

## What you get

For each lock:

- **`sensor.<lock>_last_access`** — state like `George (fingerprint)`; attributes
  include the person, method, timestamp, the server's message text, and a
  `recent` list of the last 50 events.
- **`event.<lock>_access`** — fires an HA event per new record (types: `unlock`,
  `alarm`, `event`) with person/method/text — great for the Logbook and
  automations ("notify me when the door is unlocked", "alert on an alarm").
- **`sensor.<lock>_battery_voltage`** — battery voltage reported with records
  (e.g. 7.34 V).
- An HA bus event **`orvibo_homemate_access`** fired for every new record, if you
  prefer to trigger automations off the bus directly.

Polls ORVIBO's cloud on an interval (default 60 s), so new entries show up within
about a minute.

## Two modes

- **Cloud** (default): logs in with your ORVIBO account and reads the records
  from ORVIBO's servers. Works anywhere, needs no network changes.
- **Local server** (no ORVIBO cloud): Home Assistant runs a server that your
  lock connects to directly, after you redirect `homemate.orvibo.com` to HA in
  your DNS. HA becomes the lock's "cloud"; because it sets the session key it
  decrypts everything the lock reports. Same pattern as
  [`ha-aigostar-lan`](https://github.com/RTV4/ha-aigostar-lan), but for ORVIBO's
  protocol instead of MQTT.

  Because the S2 is a battery lock that sleeps, local mode is **event‑driven**:
  entries appear when the lock wakes and reports (after each use / periodic
  check‑in), not on demand. Local mode is **beta** — the lock→server direction
  isn't fully documented, so enable debug logging and open an issue with any
  `local <=` lines that don't decode.

### Setting up local mode

1. Add the integration and choose **Local server (DNS redirect)**. HA starts
   listening on port **10002**.
2. In your DNS resolver (Technitium, Pi‑hole, AdGuard, …) add an override so
   **`homemate.orvibo.com` → Home Assistant's IP**. In **Technitium**: *Zones →
   Add Zone → `homemate.orvibo.com` (Primary) → Add Record → type A, blank name,
   IP = HA's IP, TTL 60*.
3. Make sure the lock uses that resolver for DNS (via your router's DHCP).
4. **Power‑cycle the lock** so it re‑resolves, then wake it. It connects to HA,
   and the sensors/event entity populate.
5. Optionally block the lock's internet once it's pairing locally.

> While the override is active, the ORVIBO app and the cloud mode both point at
> HA too (same hostname) — expected. Remove the override to restore normal cloud
> use.

## Install

1. **HACS → Integrations → ⋮ → Custom repositories**, add
   `https://github.com/mgeorge1994/orvibo-homemate-ha` (category: Integration),
   then install **"ORVIBO HomeMate (S2 Lock Access Log)"**.
   (Or copy `custom_components/orvibo_homemate/` into `config/custom_components/`.)
2. Restart Home Assistant.
3. **Settings → Devices & Services → Add Integration → "ORVIBO HomeMate"**, and
   sign in with the email/phone + password you use in the ORVIBO app.

Your lock appears as a device with the sensors and event entity above.

## Example automation

```yaml
automation:
  - alias: Notify on door unlock
    trigger:
      - platform: event
        event_type: orvibo_homemate_access
    action:
      - service: notify.mobile_app_your_phone
        data:
          message: >
            {{ trigger.event.data.person }} unlocked the door
            with {{ trigger.event.data.method }}.
```

Or trigger off the event entity:

```yaml
    trigger:
      - platform: state
        entity_id: event.smart_lock_s2_access
```

## How it works (short version)

```
Home Assistant ──TLS:10002──> homemate.orvibo.com   (mutual TLS, client cert)
   cmd 0   requestServerKey          -> session key   (header carries sessionId)
   cmd 2   login (user + MD5 pw)     -> userId, familyList
   cmd 147 queryWifiDeviceData       -> finds the S2  (deviceId, type 107)
   cmd 130 status records (paged)    -> access log: who / when / method
```

Frames are `"hd"` + length + protocol-type + CRC32 + 32-byte sessionId +
AES-128-ECB(PKCS7) JSON. Records arrive in `statusRecordList`, each with `time`,
`type`, `value4` (method), the door-user, and a ready-made `text`. Full details
and the reverse-engineering story are in [`PROTOCOL.md`](PROTOCOL.md).

## Status / confidence

The protocol — mutual-TLS transport, AES-128-ECB/PKCS7 crypto (unit-tested vs
FIPS-197), framing, the login → device → records flow, and pagination — was
verified end-to-end against a live account: real access records come back
correctly. The `tools/` scripts (`orvibo_logs.py`, `diagnose*.py`) let you
reproduce that from any machine with just Python 3 (no pip).

## Troubleshooting

Enable debug logging:

```yaml
logger:
  logs:
    custom_components.orvibo_homemate: debug
```

- **"invalid_auth"** — wrong ORVIBO email/phone or password.
- **No lock / no records** — the integration logs every discovered device and its
  `deviceType` on setup; the S2 is type **107**. If yours differs, add it to
  `LOCK_DEVICE_TYPES` in `const.py`.
- **Records stop updating** — the lock only reports to the cloud when it briefly
  connects (after use); history is retained server-side, so entries appear on the
  next sync.

## Legal / ethics

Interoperability project for a device **you own**, using **your own** ORVIBO
credentials against ORVIBO's own service — comparable to the official app. Ships
no ORVIBO code or binaries; the native crypto is re-implemented from the standard
AES algorithm. Respect ORVIBO's terms and don't hammer the servers. No warranty.

## Project layout

```
custom_components/orvibo_homemate/
  homemate.py      # protocol client (crypto, framing, session, cmd 147/130)
  __init__.py      # setup
  config_flow.py   # UI login
  coordinator.py   # session + polling + new-record detection
  sensor.py        # last-access + battery sensors
  event.py         # access event entity
  const.py         # tunables (LOCK_DEVICE_TYPES, scan interval, host/port)
  certs/           # ORVIBO client cert for mutual TLS (extracted from the app)
tools/             # standalone diagnostics (no pip): orvibo_logs.py, diagnose*.py
tests/             # offline crypto/record tests (python tests/test_protocol.py)
PROTOCOL.md        # full reverse-engineering writeup
```
