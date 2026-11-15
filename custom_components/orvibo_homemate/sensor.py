"""Sensors for ORVIBO HomeMate locks: last access event + battery."""
from __future__ import annotations

from datetime import datetime, timezone

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfElectricPotential
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HomeMateCoordinator
from .homemate import Device


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: HomeMateCoordinator = hass.data[DOMAIN][entry.entry_id]

    def _add(lock: Device) -> None:
        async_add_entities([
            LastAccessSensor(coordinator, lock),
            LockBatterySensor(coordinator, lock),
        ])

    # Create entities for discovered locks.
    coordinator.register_lock_listener(_add)


def _device_info(lock: Device) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, lock.device_id)},
        name=lock.name or "ORVIBO Lock",
        manufacturer="ORVIBO",
        model=lock.model or "S2",
    )


class _Base(CoordinatorEntity[HomeMateCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: HomeMateCoordinator, lock: Device) -> None:
        super().__init__(coordinator)
        self._lock = lock
        self._attr_device_info = _device_info(lock)

    @property
    def _entry(self) -> dict:
        return (self.coordinator.data or {}).get(self._lock.device_id, {})


class LastAccessSensor(_Base):
    """State = who last unlocked; attributes carry method, time and recent log."""

    _attr_icon = "mdi:door-open"

    def __init__(self, coordinator: HomeMateCoordinator, lock: Device) -> None:
        super().__init__(coordinator, lock)
        self._attr_unique_id = f"{lock.device_id}_last_access"
        self._attr_name = "Last access"

    @property
    def native_value(self) -> str | None:
        latest = self._entry.get("latest")
        if not latest:
            return None
        # e.g. "George (fingerprint)"
        person = latest.person or "unknown"
        return f"{person} ({latest.method})"

    @property
    def extra_state_attributes(self) -> dict:
        latest = self._entry.get("latest")
        recent = self._entry.get("recent") or []
        attrs: dict = {
            "recent": [
                {
                    "time": datetime.fromtimestamp(r.time, timezone.utc).isoformat(),
                    "person": r.person,
                    "method": r.method,
                    "type": r.type,
                    "text": r.text,
                }
                for r in recent
            ],
        }
        if latest:
            attrs.update({
                "person": latest.person,
                "method": latest.method,
                "method_code": latest.method_code,
                "message": latest.text,
                "event_time": datetime.fromtimestamp(latest.time, timezone.utc).isoformat(),
                "event_type": latest.type,
            })
        return attrs


class LockBatterySensor(_Base):
    """Battery voltage reported alongside access records (value3 / 100)."""

    _attr_device_class = SensorDeviceClass.VOLTAGE
    _attr_native_unit_of_measurement = UnitOfElectricPotential.VOLT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_registry_enabled_default = True

    def __init__(self, coordinator: HomeMateCoordinator, lock: Device) -> None:
        super().__init__(coordinator, lock)
        self._attr_unique_id = f"{lock.device_id}_battery_voltage"
        self._attr_name = "Battery voltage"

    @property
    def native_value(self) -> float | None:
        return self._entry.get("battery_volts")
