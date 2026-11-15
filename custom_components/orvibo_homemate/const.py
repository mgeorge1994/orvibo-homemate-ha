"""Constants for the ORVIBO HomeMate access-log integration."""
from __future__ import annotations

DOMAIN = "orvibo_homemate"

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_SCAN_INTERVAL = "scan_interval"

DEFAULT_HOST = "homemate.orvibo.com"
DEFAULT_PORT = 10002

# How often to poll the cloud for new access records (seconds).
DEFAULT_SCAN_INTERVAL = 60
MIN_SCAN_INTERVAL = 20

# Device type of the S2 lock in the cmd-147 device table.
LOCK_DEVICE_TYPES = {107}

# HA bus event fired for every new access/lock record (for automations/logbook).
EVENT_ACCESS = f"{DOMAIN}_access"

# StatusRecord.type: 0 is a normal unlock; other values are door/alarm events.
RECORD_TYPE_UNLOCK = 0
