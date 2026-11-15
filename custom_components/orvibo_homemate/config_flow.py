"""Config flow for ORVIBO HomeMate (cloud or local-server mode)."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .const import (
    CONF_HOST,
    CONF_LOCAL_PORT,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DOMAIN,
    LOCAL_LISTEN_PORT,
    MODE_CLOUD,
    MODE_LOCAL,
)
from .homemate import HomeMateAuthError, HomeMateClient, HomeMateError

_LOGGER = logging.getLogger(__name__)

CLOUD_SCHEMA = vol.Schema({
    vol.Required(CONF_USERNAME): str,
    vol.Required(CONF_PASSWORD): str,
    vol.Optional(CONF_HOST, default=DEFAULT_HOST): str,
    vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
})

LOCAL_SCHEMA = vol.Schema({
    vol.Optional(CONF_LOCAL_PORT, default=LOCAL_LISTEN_PORT): int,
})


class OrviboHomeMateConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return self.async_show_menu(
            step_id="user",
            menu_options=["cloud", "local"],
        )

    async def async_step_cloud(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_USERNAME].lower())
            self._abort_if_unique_id_configured()
            client = HomeMateClient(
                user_input[CONF_USERNAME], user_input[CONF_PASSWORD],
                host=user_input[CONF_HOST], port=user_input[CONF_PORT],
            )
            try:
                await client.connect()
                for dev in await client.get_devices():
                    _LOGGER.info("ORVIBO device: name=%r type=%s model=%s id=%s uid=%s",
                                 dev.name, dev.device_type, dev.model,
                                 dev.device_id, dev.uid)
            except HomeMateAuthError as err:
                _LOGGER.error("ORVIBO login rejected: %s", err)
                errors["base"] = "invalid_auth"
            except HomeMateError as err:
                _LOGGER.error("ORVIBO connect failed: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected ORVIBO setup error")
                errors["base"] = "unknown"
            else:
                await client.close()
                data = dict(user_input)
                data[CONF_MODE] = MODE_CLOUD
                return self.async_create_entry(
                    title=f"ORVIBO cloud ({user_input[CONF_USERNAME]})", data=data)
            await client.close()
        return self.async_show_form(step_id="cloud", data_schema=CLOUD_SCHEMA,
                                    errors=errors)

    async def async_step_local(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            await self.async_set_unique_id("orvibo_local")
            self._abort_if_unique_id_configured()
            data = {CONF_MODE: MODE_LOCAL,
                    CONF_LOCAL_PORT: user_input[CONF_LOCAL_PORT]}
            return self.async_create_entry(title="ORVIBO local server", data=data)
        return self.async_show_form(step_id="local", data_schema=LOCAL_SCHEMA)
