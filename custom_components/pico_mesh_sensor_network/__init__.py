"""The Manifold Sensor Network companion integration."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from custom_components.pico_mesh.hub import async_get_coordinator

from .const import CONF_PICO_MESH_ENTRY_ID, DOMAIN
from .coordinator import SensorNetworkCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Sensor Network entities for one linked Manifold hub."""
    hub_entry_id = entry.data[CONF_PICO_MESH_ENTRY_ID]
    hub_coordinator = async_get_coordinator(hass, hub_entry_id)
    if hub_coordinator is None:
        _LOGGER.error("Linked Manifold hub %s is not loaded", hub_entry_id)
        return False

    coordinator = SensorNetworkCoordinator(hass, hub_coordinator)
    await coordinator.async_refresh()

    entry.async_on_unload(coordinator.async_shutdown)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload Sensor Network platforms."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
