# Changelog

All notable changes to sensor-network rulesets and the Home Assistant companion.

## [1.0.0] - 2026-07-22

First release of the **Manifold Sensor Network** HA companion alongside existing KRL rulesets.

### Added

- **`custom_components/pico_mesh_sensor_network/`** — Home Assistant companion integration (depends on [Manifold hub](https://github.com/Picolab/manifold-home-assistant) `pico_mesh`).
- **LHT65 driver** — temperature, humidity, probe temperature, and last-reading timestamp entities on Manifold thing devices.
- **`hacs.json`** — HACS metadata for the companion.
- **README** — Home Assistant companion install and Docker mount instructions.

### Notes

- Sensor entities require both **Manifold** and **Manifold Sensor Network** integrations in HA.
- Community devices (e.g. Temperature Network) remain on the Manifold hub; the companion adds sensor entities on things only.

[1.0.0]: https://github.com/picolab/sensor-network/releases/tag/v1.0.0
