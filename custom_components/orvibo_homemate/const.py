"""Constants for the ORVIBO HomeMate access-log integration."""
from __future__ import annotations

DOMAIN = "orvibo_homemate"

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_MODE = "mode"
CONF_LOCAL_PORT = "local_port"

MODE_CLOUD = "cloud"
MODE_LOCAL = "local"

DEFAULT_HOST = "homemate.orvibo.com"
DEFAULT_PORT = 10002

# Port the lock connects to ("the cloud"). In local mode HA listens here and
# you point homemate.orvibo.com -> HA's IP in your DNS (e.g. Technitium).
LOCAL_LISTEN_PORT = 10002

# How often to poll the cloud for new access records (seconds).
DEFAULT_SCAN_INTERVAL = 60
MIN_SCAN_INTERVAL = 20

# Device type of the S2 lock in the cmd-147 device table.
LOCK_DEVICE_TYPES = {107}

# HA bus event fired for every new access/lock record (for automations/logbook).
EVENT_ACCESS = f"{DOMAIN}_access"

# StatusRecord.type -> coarse event category. type 0 is a normal unlock; other
# values are door/alarm events. Unknown types pass through as "event" and the
# server-provided text still describes them.
RECORD_TYPE_UNLOCK = 0
