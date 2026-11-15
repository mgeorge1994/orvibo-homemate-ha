"""Battery sensor for ORVIBO HomeMate locks."""
from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HomeMateCoordinator
from .homemate import Device
from .lock import _is_lock


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: HomeMateCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        OrviboBatterySensor(coordinator, dev)
        for dev in coordinator.devices.values()
        if _is_lock(dev)
    )


class OrviboBatterySensor(CoordinatorEntity[HomeMateCoordinator], SensorEntity):
    """Battery level reported by the lock.

    ORVIBO locks report battery in the deviceStatus payload. The exact key
    varies by firmware; we try the common ones. If your lock exposes it
    under a different key, add it to ``_BATTERY_KEYS``.
    """

    _BATTERY_KEYS = ("battery", "electricity", "power", "value4", "batteryLevel")

    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: HomeMateCoordinator, device: Device) -> None:
        super().__init__(coordinator)
        self._device = device
        self._attr_unique_id = f"{device.device_id}_battery"
        self._attr_name = "Battery"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.device_id)},
        )

    @property
    def native_value(self) -> int | None:
        status = (self.coordinator.data or {}).get(self._device.device_id, {})
        for key in self._BATTERY_KEYS:
            if key in status and status[key] is not None:
                try:
                    return int(status[key])
                except (TypeError, ValueError):
                    continue
        return None
