"""Connection + polling coordinator for ORVIBO HomeMate access logs."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    DEFAULT_SCAN_INTERVAL,
    EVENT_ACCESS,
    LOCK_DEVICE_TYPES,
)
from .homemate import AccessRecord, Device, HomeMateClient, HomeMateError

_LOGGER = logging.getLogger(__name__)

MAX_KEEP = 50  # recent records to retain per lock


def _is_lock(device: Device) -> bool:
    if device.device_type in LOCK_DEVICE_TYPES:
        return True
    name = (device.name or "").lower()
    model = (device.model or "").lower()
    return "lock" in name or "lock" in model or "s2" in name


class HomeMateCoordinator(DataUpdateCoordinator[dict[str, dict]]):
    """Owns the ORVIBO session and polls each lock's access records."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        interval = entry.options.get(CONF_SCAN_INTERVAL) or DEFAULT_SCAN_INTERVAL
        super().__init__(
            hass,
            _LOGGER,
            name="orvibo_homemate",
            update_interval=timedelta(seconds=interval),
        )
        self.entry = entry
        self.client = HomeMateClient(
            entry.data[CONF_USERNAME],
            entry.data[CONF_PASSWORD],
            host=entry.data.get(CONF_HOST),
            port=entry.data.get(CONF_PORT),
        )
        self.locks: dict[str, Device] = {}
        self._seen_seq: dict[str, int] = {}     # device_id -> highest sequence seen
        self._records: dict[str, list[AccessRecord]] = {}
        self._primed = False

    async def async_setup(self) -> None:
        await self.client.connect()
        for dev in await self.client.get_devices():
            _LOGGER.info("ORVIBO device: name=%r type=%s model=%s id=%s",
                         dev.name, dev.device_type, dev.model, dev.device_id)
            if _is_lock(dev):
                self.locks[dev.device_id] = dev
        if not self.locks:
            _LOGGER.warning("No ORVIBO lock found in the account")

    async def _ensure_connected(self) -> None:
        if not self.client.connected:
            await self.client.connect()
            if not self.locks:
                for dev in await self.client.get_devices():
                    if _is_lock(dev):
                        self.locks[dev.device_id] = dev

    async def _async_update_data(self) -> dict[str, dict]:
        try:
            await self._ensure_connected()
            data: dict[str, dict] = {}
            for device_id, lock in self.locks.items():
                records = await self.client.get_records(lock.uid, device_id)
                records.sort(key=lambda r: r.sequence)  # oldest -> newest

                prev = self._seen_seq.get(device_id, 0)
                new_records = [r for r in records if r.sequence > prev]
                if records:
                    self._seen_seq[device_id] = max(r.sequence for r in records)

                # Keep a rolling recent list (newest first).
                merged = {r.sequence: r for r in self._records.get(device_id, [])}
                merged.update({r.sequence: r for r in records})
                recent = sorted(merged.values(), key=lambda r: r.sequence,
                                reverse=True)[:MAX_KEEP]
                self._records[device_id] = recent

                # Fire bus events for genuinely new records — but not on the
                # first poll (that would replay history on every restart).
                if self._primed:
                    for r in new_records:
                        self._fire_event(lock, r)

                latest = recent[0] if recent else None
                data[device_id] = {
                    "device": lock,
                    "latest": latest,
                    "new": new_records,
                    "recent": recent,
                    "battery_volts": latest.battery_volts if latest else None,
                }
            self._primed = True
            return data
        except HomeMateError as err:
            raise UpdateFailed(str(err)) from err

    def _fire_event(self, lock: Device, r: AccessRecord) -> None:
        self.hass.bus.async_fire(EVENT_ACCESS, {
            "device_id": lock.device_id,
            "device_name": lock.name,
            "time": r.time,
            "type": r.type,
            "person": r.person,
            "method": r.method,
            "method_code": r.method_code,
            "text": r.text,
            "sequence": r.sequence,
            "battery_volts": r.battery_volts,
        })

    async def async_shutdown(self) -> None:
        await self.client.close()
