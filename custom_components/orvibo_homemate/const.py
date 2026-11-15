"""Constants for the ORVIBO HomeMate integration."""
from __future__ import annotations

DOMAIN = "orvibo_homemate"

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_PORT = "port"

DEFAULT_HOST = "homemate.orvibo.com"
DEFAULT_PORT = 10002

# How often to poll device status (seconds). The lock also pushes status
# asynchronously, which we handle live; this is the safety-net poll.
UPDATE_INTERVAL = 60

# ORVIBO deviceType values that represent a door lock.
# 71 is the value seen for ORVIBO Wi-Fi locks in the app's product table;
# adjust here if your lock reports a different deviceType (the config flow
# logs every discovered device's type to help you confirm).
LOCK_DEVICE_TYPES = {71}

# Keys that may appear in a lock status payload (deviceStatus.value1).
# value1 == 0 -> unlocked, value1 == 1 -> locked (BaseLockFragment logic).
LOCK_STATE_LOCKED = 1
LOCK_STATE_UNLOCKED = 0
