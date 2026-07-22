"""LHT65 sensor-network router driver."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

LHT65_ROUTER_RULESET = "io.picolabs.lht65.router"

LHT65_SENSOR_QUERIES: dict[str, dict[str, str | None]] = {
    "lastInternalTemp": {
        "key": "temperature",
        "name": "Temperature",
        "device_class": "temperature",
        "state_class": "measurement",
        "unit": "°F",
    },
    "lastHumidity": {
        "key": "humidity",
        "name": "Humidity",
        "device_class": "humidity",
        "state_class": "measurement",
        "unit": "%",
    },
    "lastProbeTemp": {
        "key": "probe_temperature",
        "name": "Probe temperature",
        "device_class": "temperature",
        "state_class": "measurement",
        "unit": "°F",
    },
    "lastHeartbeat": {
        "key": "last_reading",
        "name": "Last reading",
        "device_class": "timestamp",
        "state_class": None,
        "unit": None,
    },
}


def parse_lht65_reading(query_name: str, raw: Any) -> Any:
    """Normalize one LHT65 query result for Home Assistant state."""
    if query_name == "lastHeartbeat":
        return parse_heartbeat_timestamp(raw)
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return raw
    return None


def parse_heartbeat_timestamp(raw: Any) -> datetime | None:
    """Extract reported_at from the router's lastHeartbeat entity."""
    if not isinstance(raw, dict):
        return None
    reported_at = raw.get("reported_at")
    if isinstance(reported_at, (int, float)):
        return datetime.fromtimestamp(reported_at / 1000, tz=UTC)
    return None
