"""Lock platform for ORVIBO HomeMate (S2 smart lock)."""
from __future__ import annotations

import logging

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    LOCK_DEVICE_TYPES,
    LOCK_STATE_LOCKED,
    LOCK_STATE_UNLOCKED,
)
from .coordinator import HomeMateCoordinator
from .homemate import Device, HomeMateError

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: HomeMateCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        OrviboLock(coordinator, dev)
        for dev in coordinator.devices.values()
        if _is_lock(dev)
    ]
    if not entities:
        _LOGGER.warning(
            "No ORVIBO locks matched. Discovered device types: %s. "
            "If your lock is missing, add its deviceType to LOCK_DEVICE_TYPES in const.py.",
            sorted({d.device_type for d in coordinator.devices.values()}),
        )
    async_add_entities(entities)


def _is_lock(device: Device) -> bool:
    if device.device_type in LOCK_DEVICE_TYPES:
        return True
    model = (device.model or "").lower()
    return "lock" in model or model.startswith("s2")


class OrviboLock(CoordinatorEntity[HomeMateCoordinator], LockEntity):
    """An ORVIBO smart lock controlled over the HomeMate cloud session."""

    _attr_has_entity_name = True
    _attr_name = None

    def __init__(self, coordinator: HomeMateCoordinator, device: Device) -> None:
        super().__init__(coordinator)
        self._device = device
        self._attr_unique_id = device.device_id
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.device_id)},
            name=device.name or "ORVIBO Lock",
            manufacturer="ORVIBO",
            model=device.model or "S2",
        )

    @property
    def _status(self) -> dict:
        return (self.coordinator.data or {}).get(self._device.device_id, {})

    @property
    def is_locked(self) -> bool | None:
        value1 = self._status.get("value1")
        if value1 is None:
            return None
        if int(value1) == LOCK_STATE_LOCKED:
            return True
        if int(value1) == LOCK_STATE_UNLOCKED:
            return False
        return None

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.client.connected

    async def async_lock(self, **kwargs) -> None:
        try:
            await self.coordinator.client.lock(self._device.uid, self._device.device_id)
        except HomeMateError as err:
            raise HomeMateError(f"Failed to lock: {err}") from err
        await self.coordinator.async_request_refresh()

    async def async_unlock(self, **kwargs) -> None:
        try:
            await self.coordinator.client.unlock(self._device.uid, self._device.device_id)
        except HomeMateError as err:
            raise HomeMateError(f"Failed to unlock: {err}") from err
        await self.coordinator.async_request_refresh()
