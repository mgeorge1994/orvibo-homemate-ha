"""Coordinator for ORVIBO HomeMate — cloud polling or local-server mode."""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_HOST,
    CONF_LOCAL_PORT,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    DEFAULT_SCAN_INTERVAL,
    EVENT_ACCESS,
    LOCAL_LISTEN_PORT,
    LOCK_DEVICE_TYPES,
    MODE_LOCAL,
)
from .homemate import AccessRecord, Device, HomeMateClient, HomeMateError

_LOGGER = logging.getLogger(__name__)

MAX_KEEP = 50


def _is_lock(device: Device) -> bool:
    if device.device_type in LOCK_DEVICE_TYPES:
        return True
    name = (device.name or "").lower()
    model = (device.model or "").lower()
    return "lock" in name or "lock" in model or "s2" in name


class HomeMateCoordinator(DataUpdateCoordinator[dict[str, dict]]):
    """Owns the ORVIBO session (cloud) or the local server, and lock state."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.entry = entry
        self.mode = entry.data.get(CONF_MODE) or "cloud"
        interval = entry.options.get(CONF_SCAN_INTERVAL) or DEFAULT_SCAN_INTERVAL
        super().__init__(
            hass,
            _LOGGER,
            name="orvibo_homemate",
            # Local mode is push-driven; cloud mode polls.
            update_interval=None if self.mode == MODE_LOCAL
            else timedelta(seconds=interval),
        )
        self.client: HomeMateClient | None = None
        self.server = None  # LocalServer, set in local mode
        self.locks: dict[str, Device] = {}
        self._seen_seq: dict[str, int] = {}
        self._records: dict[str, list[AccessRecord]] = {}
        self._primed = False
        self._data: dict[str, dict] = {}
        self._lock_listeners: list[Callable[[Device], None]] = []

        if self.mode != MODE_LOCAL:
            self.client = HomeMateClient(
                entry.data[CONF_USERNAME],
                entry.data[CONF_PASSWORD],
                host=entry.data.get(CONF_HOST),
                port=entry.data.get(CONF_PORT),
            )

    # -- entity wiring -------------------------------------------------
    def register_lock_listener(self, cb: Callable[[Device], None]) -> None:
        """Platforms call this; cb(lock) is invoked for existing + future locks."""
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
        if self.mode == MODE_LOCAL:
            await self._setup_local()
        else:
            await self._setup_cloud()

    async def _setup_cloud(self) -> None:
        assert self.client is not None
        await self.client.connect()
        for dev in await self.client.get_devices():
            _LOGGER.info("ORVIBO device: name=%r type=%s model=%s id=%s",
                         dev.name, dev.device_type, dev.model, dev.device_id)
            if _is_lock(dev):
                self._add_lock(dev)
        if not self.locks:
            _LOGGER.warning("No ORVIBO lock found in the account")

    async def _setup_local(self) -> None:
        from .local_server import LocalServer, records_from_payload
        self._records_from_payload = records_from_payload
        port = self.entry.data.get(CONF_LOCAL_PORT) or LOCAL_LISTEN_PORT
        self.server = LocalServer("0.0.0.0", port, self._on_local_frame)
        await self.server.start()
        self._primed = True  # local events are live from the first report
        self.async_set_updated_data({})

    # -- local-mode frame handling ------------------------------------
    def _on_local_frame(self, pt: str, payload: dict[str, Any]) -> None:
        records = self._records_from_payload(payload)
        if not records:
            return
        for r in records:
            if not r.device_id:
                continue
            if r.device_id not in self.locks:
                self._add_lock(Device(
                    device_id=r.device_id, uid=payload.get("uid", ""),
                    name="Smart Lock S2", device_type=107, model="S2", raw={},
                ))
            self._ingest_record(r.device_id, r, fire=True)
        self.async_set_updated_data(dict(self._data))

    # -- shared record bookkeeping ------------------------------------
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

    # -- cloud-mode polling -------------------------------------------
    async def _async_update_data(self) -> dict[str, dict]:
        if self.mode == MODE_LOCAL:
            return dict(self._data)  # push-driven
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
        if self.server is not None:
            await self.server.stop()
