"""Connection + data coordinator for ORVIBO HomeMate."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, UPDATE_INTERVAL
from .homemate import Device, HomeMateClient, HomeMateError

_LOGGER = logging.getLogger(__name__)


class HomeMateCoordinator(DataUpdateCoordinator[dict[str, dict]]):
    """Owns the persistent HomeMate session and the device/status cache."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="orvibo_homemate",
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )
        self.entry = entry
        self.client = HomeMateClient(
            entry.data[CONF_USERNAME],
            entry.data[CONF_PASSWORD],
            host=entry.data.get(CONF_HOST),
            port=entry.data.get(CONF_PORT),
        )
        self.devices: dict[str, Device] = {}
        self._status: dict[str, dict] = {}

    async def async_setup(self) -> None:
        """Connect, authenticate and do an initial device load."""
        await self.client.connect()
        self.client.add_status_listener(self._on_status_push)
        for dev in await self.client.get_devices():
            self.devices[dev.device_id] = dev

    def _on_status_push(self, payload: dict) -> None:
        """Handle an unsolicited status frame from the server."""
        device_id = payload.get("deviceId")
        if not device_id:
            return
        self._status[device_id] = payload
        # Push live updates to entities without waiting for the poll.
        self.async_set_updated_data(dict(self._status))

    async def _async_update_data(self) -> dict[str, dict]:
        try:
            if not self.client.connected:
                await self.client.connect()
                self.client.add_status_listener(self._on_status_push)
                for dev in await self.client.get_devices():
                    self.devices.setdefault(dev.device_id, dev)
            for rec in await self.client.get_device_status():
                did = rec.get("deviceId")
                if did:
                    self._status[did] = rec
        except HomeMateError as err:
            raise UpdateFailed(str(err)) from err
        return dict(self._status)

    async def async_shutdown(self) -> None:
        await self.client.close()
