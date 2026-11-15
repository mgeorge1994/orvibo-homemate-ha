"""Cloud polling coordinator for ORVIBO HomeMate access logs."""
from __future__ import annotations

import logging
from collections.abc import Callable
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
from .homemate import AccessRecord, Device, HomeMateClient, HomeMateError, build_ssl_context

_LOGGER = logging.getLogger(__name__)

MAX_KEEP = 50


def _is_lock(device: Device) -> bool:
    if device.device_type in LOCK_DEVICE_TYPES:
        return True
    name = (device.name or "").lower()
    model = (device.model or "").lower()
    return "lock" in name or "lock" in model or "s2" in name


class HomeMateCoordinator(DataUpdateCoordinator[dict[str, dict]]):
    """Owns the ORVIBO cloud session and polls each lock's access records."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        interval = entry.options.get(CONF_SCAN_INTERVAL) or DEFAULT_SCAN_INTERVAL
        super().__init__(
            hass,
            _LOGGER,
            name="orvibo_homemate",
            update_interval=timedelta(seconds=interval),
        )
        self.entry = entry
        self.client: HomeMateClient | None = None
        self.locks: dict[str, Device] = {}
        self._seen_seq: dict[str, int] = {}
        self._records: dict[str, list[AccessRecord]] = {}
        self._primed = False
        self._data: dict[str, dict] = {}
        self._lock_listeners: list[Callable[[Device], None]] = []

    # -- entity wiring -------------------------------------------------
    def register_lock_listener(self, cb: Callable[[Device], None]) -> None:
        """Platforms call this; cb(lock) runs for existing and future locks."""
        self._lock_listeners.append(cb)
        for lock in self.locks.values():
            cb(lock)

    def _add_lock(self, device: Device) -> None:
        if device.device_id in self.locks:
            return
        self.locks[device.device_id] = device
        for cb in list(self._lock_listeners):
            cb(device)

    # -- setup ---------------------------------------------------------
    async def async_setup(self) -> None:
        # Build the TLS context off the event loop (load_cert_chain blocks).
        ctx = await self.hass.async_add_executor_job(build_ssl_context, False)
        self.client = HomeMateClient(
            self.entry.data[CONF_USERNAME],
            self.entry.data[CONF_PASSWORD],
            host=self.entry.data.get(CONF_HOST),
            port=self.entry.data.get(CONF_PORT),
            ssl_context=ctx,
        )
        await self.client.connect()
        for dev in await self.client.get_devices():
            _LOGGER.info("ORVIBO device: name=%r type=%s model=%s id=%s",
                         dev.name, dev.device_type, dev.model, dev.device_id)
            if _is_lock(dev):
                self._add_lock(dev)
        if not self.locks:
            _LOGGER.warning("No ORVIBO lock found in the account")

    # -- record bookkeeping -------------------------------------------
    def _ingest_record(self, device_id: str, r: AccessRecord, *, fire: bool) -> None:
        bucket = {x.sequence: x for x in self._records.get(device_id, [])}
        is_new = r.sequence not in bucket and r.sequence > self._seen_seq.get(device_id, 0)
        bucket[r.sequence] = r
        recent = sorted(bucket.values(), key=lambda x: x.sequence, reverse=True)[:MAX_KEEP]
        self._records[device_id] = recent
        if r.sequence > self._seen_seq.get(device_id, 0):
            self._seen_seq[device_id] = r.sequence
        latest = recent[0] if recent else None
        entry = self._data.setdefault(device_id, {})
        entry.update({
            "device": self.locks.get(device_id),
            "latest": latest,
            "recent": recent,
            "battery_volts": latest.battery_volts if latest else None,
            "new": [],
        })
        if is_new:
            entry["new"] = [r]
            if fire and self._primed:
                self._fire_event(device_id, r)

    async def _async_update_data(self) -> dict[str, dict]:
        assert self.client is not None
        try:
            if not self.client.connected:
                await self.client.connect()
                if not self.locks:
                    for dev in await self.client.get_devices():
                        if _is_lock(dev):
                            self._add_lock(dev)
            for device_id, lock in self.locks.items():
                records = await self.client.get_records(lock.uid, device_id)
                for r in sorted(records, key=lambda x: x.sequence):
                    self._ingest_record(device_id, r, fire=self._primed)
            self._primed = True
            return dict(self._data)
        except HomeMateError as err:
            raise UpdateFailed(str(err)) from err

    def _fire_event(self, device_id: str, r: AccessRecord) -> None:
        lock = self.locks.get(device_id)
        self.hass.bus.async_fire(EVENT_ACCESS, {
            "device_id": device_id,
            "device_name": lock.name if lock else "",
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
        if self.client is not None:
            await self.client.close()
