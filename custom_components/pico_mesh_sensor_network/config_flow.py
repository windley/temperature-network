"""Config flow for the Manifold Sensor Network companion."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers.selector import (
    ConfigEntrySelector,
    ConfigEntrySelectorConfig,
)

from custom_components.pico_mesh.hub import async_get_config_entries

from .const import CONF_PICO_MESH_ENTRY_ID, DOMAIN


class SensorNetworkConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Link Sensor Network to an existing Manifold hub integration."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick the Manifold hub this companion extends."""
        hub_entries = async_get_config_entries(self.hass)
        if not hub_entries:
            return self.async_abort(reason="pico_mesh_required")

        if len(hub_entries) == 1:
            return await self._create_entry(hub_entries[0].entry_id, hub_entries[0].title)

        if user_input is not None:
            hub_entry_id = user_input[CONF_PICO_MESH_ENTRY_ID]
            hub_entry = self.hass.config_entries.async_get_entry(hub_entry_id)
            title = hub_entry.title if hub_entry is not None else "Sensor Network"
            return await self._create_entry(hub_entry_id, title)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PICO_MESH_ENTRY_ID): ConfigEntrySelector(
                        ConfigEntrySelectorConfig(integration="pico_mesh")
                    ),
                }
            ),
        )

    async def _create_entry(
        self, hub_entry_id: str, hub_title: str
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(hub_entry_id)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=f"Sensor Network ({hub_title})",
            data={CONF_PICO_MESH_ENTRY_ID: hub_entry_id},
        )
