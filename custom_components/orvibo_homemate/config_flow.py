"""Config flow for ORVIBO HomeMate."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DOMAIN,
)
from .homemate import HomeMateAuthError, HomeMateClient, HomeMateError

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_HOST, default=DEFAULT_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
    }
)


class OrviboHomeMateConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the ORVIBO HomeMate config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_USERNAME].lower())
            self._abort_if_unique_id_configured()

            client = HomeMateClient(
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
                host=user_input[CONF_HOST],
                port=user_input[CONF_PORT],
            )
            try:
                await client.connect()
                # Log what we found so users can confirm their lock's type.
                for dev in await client.get_devices():
                    _LOGGER.info(
                        "ORVIBO device: name=%r type=%s model=%s deviceId=%s uid=%s",
                        dev.name, dev.device_type, dev.model, dev.device_id, dev.uid,
                    )
            except HomeMateAuthError:
                errors["base"] = "invalid_auth"
            except HomeMateError:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected error during ORVIBO setup")
                errors["base"] = "unknown"
            else:
                await client.close()
                return self.async_create_entry(
                    title=f"ORVIBO ({user_input[CONF_USERNAME]})",
                    data=user_input,
                )
            await client.close()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )
