# ORVIBO HomeMate cloud control protocol

Reverse-engineered from the **ORVIBO Home / HomeMate** Android app
(`com.orvibo.homemate`, version **5.2.6.308**) by static analysis of the
decompiled Java plus the native crypto library `libHomeMate_Security.so`.

This documents the "cloud-local" control path: the phone app keeps a
persistent TCP session to ORVIBO's server and sends framed, AES-encrypted
JSON commands over it. The S2 lock is reached through this server session —
**not** over your LAN (see "Why not pure-LAN" at the bottom).

---

## 1. Transport

| | |
|---|---|
| Host | `homemate.orvibo.com` (resolved by the app via DNS) |
| Port | **10002** (TCP, `SO_KEEPALIVE`, `TCP_NODELAY`) — `socket/b.java` |
| LAN discovery | UDP broadcast to `255.255.255.255:10000`, cmd 86 (gateways only) |

Source: `socket/b.java` connects to `"homemate.orvibo.com"` with
`int i10 = !str.equals("server") ? a0.B : 10002;`.

The app may be redirected to a specific login-server IP during the
handshake (`BaseResResp.loginServerIp` / `playLoad_redrect`). If the first
server returns a redirect, reconnect to that IP on the same port. The
reference client connects straight to `homemate.orvibo.com:10002`, which
works in the common case.

---

## 2. Frame format

Every message = **42-byte header** + **encrypted body**.

```
offset  size  field                     notes
0       2     "hd"                      magic (0x68 0x64)
2       2     total length (u16, BE)    header(42) + body length
4       2     protocol type             "pk" or "dk" (2 ASCII chars)
6       4     CRC32 of the body         CRC32 of the *encrypted* body
10      32    sessionId (ASCII)         left-justified, space-padded;
                                        32 spaces before a session exists
42      ...   body                      AES-128-ECB(PKCS7) UTF-8 JSON
```

Builder: `core/c.java#h1(...)` (server) and `b8/b.java#c(...)` (discovery).
Parser: `socket/h.java#b(...)` and `socket/netty/c.java`.

### CRC field
`util/t.java#h` computes `CRC32(body)` and formats it as an **8-char
uppercase hex** string, zero-padded. Those 8 hex characters are packed
into the 4 header bytes (`b5.A`/`d8.e.g`), i.e. it is the big-endian CRC32
value. The CRC covers the **encrypted** body.

---

## 3. Cryptography

AES-**128**-**ECB** with **PKCS7** padding. Confirmed by disassembling
`libHomeMate_Security.so`:

- `AesEncryptEx` runs `AES_init_ctx(ctx, key, keylen)` then
  `AES_ECB_encrypt` per 16-byte block (no IV → ECB).
- Final-block padding: `pad = 16 - (len & 0xF)`, every pad byte = `pad`
  (standard PKCS7, including a full extra block when already aligned).
- The 16-byte key **string is used directly** as the AES-128 key — there
  is no MD5/KDF step in the string-key path.

### Key selection (`protocol type`)
`t.N(pt)` returns `"pk".equals(pt)`; that boolean is the native
"use default key" flag.

| protocol type | key used | when |
|---|---|---|
| `pk` | **default key** `khggd54865SNJHGF` | handshake (cmd 0), LAN discovery (cmd 86) |
| `dk` | **session key** from the server | everything after the handshake (login, control, queries) |

The default key is the `pkKey` symbol in `libHomeMate_Security.so`
(a `char*` in `.data` pointing at `"khggd54865SNJHGF"` in `.rodata`).

The **session key** is a string the server returns in the cmd-0 response
(`core/g.java#K1`: `str2 = jSONObject.optString("key"); d0.e(ctx, sessionId, str2)`).
It is stored per-`sessionId` and used (directly, 16 bytes) for all later traffic.

---

## 4. Request JSON envelope

Built by `core/c.java#Z0` / the frame encoder. Every request carries:

```json
{
  "cmd": <int>,
  "serial": <int>,          // response correlates by this
  "clientType": 1,
  "uniSerial": <epoch_ms>,
  "serverRecord": false,
  "ver": "5.2.6.308"
  // + command-specific fields
}
```

`sessionId` is **not** in the JSON — it lives in the header. Responses echo
`serial` and include a `result` (0 = success) plus command data.

---

## 5. Command flow

```
TCP connect
  │
  ├─ cmd 0  requestServerKey   pt=pk   → { SessionId, key }
  │     body: source, softwareVersion, systemVersion, hardwareVersion,
  │           language, identifier (phone uuid), phoneName
  │
  ├─ cmd 2  login             pt=dk   → { result, userId, familyId, ... }
  │     body: userName, password=MD5(pwd) UPPERCASE hex, type=3,
  │           needAccountDetailError=true
  │
  ├─ cmd 4  loadTable         pt=dk   → device / status records
  │     body: uid, userName, lastUpdateTime(0=full), familyId,
  │           tableName ("device" | "deviceStatus" | ...), pageIndex, dataType
  │
  └─ cmd 15 control           pt=dk   → { result }
        body: uid, userName, deviceId, order, value1..4,
              delayTime, qualityOfService
```

Command codes (from `core/c.java` + the dispatch switch in `core/g.java`):

| cmd | meaning | builder |
|---|---|---|
| 0  | requestServerKey (session key handshake) | `c.o3` |
| 2  | login (user + MD5 password) | `c.f0` |
| 4  | load table (device discovery, status) | `c.I2` |
| 15 | control device | `BaseControlDevice` / `c.J` (cmd 55 is a variant) |
| 86 | LAN UDP discovery | `b8.b` |

---

## 6. The S2 lock specifically

- Lock orders (`data/k0.java`): `order="unlock"` and `order="lock"`,
  sent via **cmd 15** with the lock's `uid` + `deviceId`.
- Discover the lock from the `device` table (cmd 4): each record has
  `deviceId`, `uid`, `deviceType`, `model`, `deviceName`.
- Lock state comes from the `deviceStatus` table: `value1`
  (`0` = unlocked, `1` = locked — `BaseLockFragment`/`device/lock/b.java`).
- The lock also reports status asynchronously (unsolicited frames with a
  `deviceId`); the client exposes these via `add_status_listener`.
- `deviceType` for the lock: set `LOCK_DEVICE_TYPES` in `const.py` to the
  value your lock reports — the config flow logs every device's type on
  setup so you can read it off. The code also matches on `model` containing
  "lock"/"s2" as a fallback.

### Remote unlock caveat
ORVIBO gates remote unlock behind a per-lock setting
(`device/smartlock/RemoteUnLockSettingActivity`). If remote unlock is
disabled on the lock, the server will reject `order=unlock` (non-zero
`result`) even with valid auth. Enable "remote unlock" in the ORVIBO app
first. Locking and status reads are not gated this way.

---

## 7. What still needs live confirmation

Everything structural (framing, crypto, cmd codes, JSON keys) is taken
directly from the app and the native lib, and the crypto is unit-tested
against FIPS-197. The following can only be confirmed against a live
account + lock, because the exact server response shapes aren't fully
determined by static analysis:

1. Exact field names in the **cmd-0 response** for `SessionId` / `key`
   (the client tries `SessionId`/`sessionId` and `key`).
2. The **login response** keys for `userId` / `familyId`.
3. Whether the server **redirects** to a login-server IP after cmd 0.
4. The **`deviceType`** number for the S2, and the **battery** key in
   `deviceStatus`.
5. Whether control is accepted as **cmd 15** (`order`) directly or needs
   the `c.J` cmd-55 variant for this model.

To calibrate, run Home Assistant with
`logger: logs: custom_components.orvibo_homemate: debug` and watch the
decrypted frames, or use the standalone `tools/sniff.py` helper.

---

## 8. Why not pure-LAN (no server at all)

The S2 is a battery lock (10×AA, ~800-day life). Its Wi-Fi radio sleeps and
has no always-on LAN endpoint to connect to on demand, so there is no
reliable fully-offline LAN control. ORVIBO's own local path (`model/lan`,
UDP cmd 86) targets always-on **gateways/hubs**, not the sleeping lock.
BLE is the only radio-local channel, and it needs proximity plus the same
native crypto and a cloud-provisioned credential. The approach here —
driving ORVIBO's server the way the app does, from your HA host — is the
practical "no phone app, no third-party cloud" option.
