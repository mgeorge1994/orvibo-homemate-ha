"""Event entity for ORVIBO HomeMate lock access events."""
from __future__ import annotations

from homeassistant.components.event import EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, RECORD_TYPE_UNLOCK
from .coordinator import HomeMateCoordinator
from .homemate import AccessRecord, Device

# Event types surfaced to HA. "unlock" covers normal entries; other record
# types (door-ajar, alarms) surface as "alarm"; anything else as "event".
EVENT_TYPES = ["unlock", "alarm", "event"]


def _event_type(record: AccessRecord) -> str:
    if record.type == RECORD_TYPE_UNLOCK:
        return "unlock"
    text = (record.text or "").lower()
    if any(w in text for w in ("alarm", "warn", "tamper", "pry", "forced", "not closed",
                               "unclosed", "ajar", "low battery", "hijack", "doorbell")):
        return "alarm"
    return "event"


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: HomeMateCoordinator = hass.data[DOMAIN][entry.entry_id]

    def _add(lock: Device) -> None:
        async_add_entities([AccessEventEntity(coordinator, lock)])

    coordinator.register_lock_listener(_add)


class AccessEventEntity(CoordinatorEntity[HomeMateCoordinator], EventEntity):
    """Fires an HA event for each new lock access/alarm record."""

    _attr_has_entity_name = True
    _attr_name = "Access"
    _attr_icon = "mdi:account-key"
    _attr_event_types = EVENT_TYPES

    def __init__(self, coordinator: HomeMateCoordinator, lock: Device) -> None:
        super().__init__(coordinator)
        self._lock = lock
        self._attr_unique_id = f"{lock.device_id}_access_event"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock.device_id)},
            name=lock.name or "ORVIBO Lock",
            manufacturer="ORVIBO",
            model=lock.model or "S2",
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        entry = (self.coordinator.data or {}).get(self._lock.device_id, {})
        new_records = entry.get("new") or []
        # Trigger oldest-first so the most recent ends up as current state.
        for r in sorted(new_records, key=lambda x: x.sequence):
            self._trigger_event(_event_type(r), {
                "person": r.person,
                "method": r.method,
                "method_code": r.method_code,
                "text": r.text,
                "event_time": r.time,
                "record_type": r.type,
                "sequence": r.sequence,
            })
        super()._handle_coordinator_update()
