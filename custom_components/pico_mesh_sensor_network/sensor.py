"""Sensor entities for Manifold sensor-network router rulesets."""

from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from custom_components.pico_mesh.hub import ManifoldThing, ManifoldThingEntity, PicoMeshCoordinator

from .const import DOMAIN
from .coordinator import SensorNetworkCoordinator
from .drivers.lht65 import LHT65_SENSOR_QUERIES, parse_lht65_reading

_DEVICE_CLASS = {
    "temperature": SensorDeviceClass.TEMPERATURE,
    "humidity": SensorDeviceClass.HUMIDITY,
    "timestamp": SensorDeviceClass.TIMESTAMP,
}

_STATE_CLASS = {
    "measurement": SensorStateClass.MEASUREMENT,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensor router entities for things on the linked Manifold mesh."""
    coordinator: SensorNetworkCoordinator = hass.data[DOMAIN][entry.entry_id]
    hub: PicoMeshCoordinator = coordinator.hub
    known: set[str] = set()

    @callback
    def _sync_entities() -> None:
        new_entities: list[SensorEntity] = []
        for thing in hub.data.things.values():
            new_entities.extend(_lht65_entities(coordinator, hub, thing, known))
        if new_entities:
            async_add_entities(new_entities)

    _sync_entities()
    coordinator.async_add_listener(_sync_entities)


def _lht65_entities(
    coordinator: SensorNetworkCoordinator,
    hub: PicoMeshCoordinator,
    thing: ManifoldThing,
    known: set[str],
) -> list[SensorEntity]:
    state = coordinator.states.get(thing.pico_id)
    if state is None or not state.lht65_installed:
        return []

    entities: list[SensorEntity] = []
    for query_name, spec in LHT65_SENSOR_QUERIES.items():
        suffix = f"lht65_{spec['key']}"
        unique_id = f"thing_{thing.pico_id}_{suffix}"
        if unique_id in known:
            continue
        known.add(unique_id)
        entities.append(
            Lht65Sensor(
                coordinator,
                hub,
                thing,
                query_name=query_name,
                spec=spec,
            )
        )
    return entities


class Lht65Sensor(ManifoldThingEntity, SensorEntity):
    """One reading from an LHT65 sensor thing."""

    def __init__(
        self,
        sensor_coordinator: SensorNetworkCoordinator,
        hub_coordinator: PicoMeshCoordinator,
        thing: ManifoldThing,
        *,
        query_name: str,
        spec: dict[str, str | None],
    ) -> None:
        super().__init__(
            hub_coordinator,
            thing,
            unique_id_suffix=f"lht65_{spec['key']}",
        )
        self._sensor_coordinator = sensor_coordinator
        self._query_name = query_name
        self._attr_name = str(spec["name"])
        device_class = spec.get("device_class")
        if isinstance(device_class, str):
            self._attr_device_class = _DEVICE_CLASS.get(device_class)
        state_class = spec.get("state_class")
        if isinstance(state_class, str):
            self._attr_state_class = _STATE_CLASS.get(state_class)
        unit = spec.get("unit")
        if isinstance(unit, str):
            self._attr_native_unit_of_measurement = unit

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            self._sensor_coordinator.async_add_listener(
                self._handle_sensor_coordinator_update
            )
        )
        self._handle_sensor_coordinator_update()

    @callback
    def _handle_coordinator_update(self) -> None:
        self._sync_tx_eci()
        self._handle_sensor_coordinator_update()

    @callback
    def _handle_sensor_coordinator_update(self) -> None:
        state = self._sensor_coordinator.states.get(self._thing_id)
        raw = state.lht65_readings.get(self._query_name) if state else None
        self._attr_native_value = parse_lht65_reading(self._query_name, raw)
        self.async_write_ha_state()
