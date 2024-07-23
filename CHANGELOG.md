# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- ## [Unreleased] -->

## [0.2.0](https://github.com/unioslo/zabbix-auto-config/releases/tag/zac-v0.2.0)

### Added

- Zabbix 7 compatibility
- Configuration options for each process.
  - `[zac.process.garbage_collector]`
    - `enabled`: Enable automatic garbage collection.
    - `delete_empty_maintenance`: Delete maintenances that only contain disabled hosts.
    - `update_interval`: Update interval in seconds.
  - `[zac.process.host_updater]`
    - `update_interval`: Update interval in seconds.
  - `[zac.process.hostgroup_updater]`
    - `update_interval`: Update interval in seconds.
  - `[zac.process.template_updater]`
    - `update_interval`: Update interval in seconds.
  - `[zac.process.source_merger]`
    - `update_interval`: Update interval in seconds.
- Automatic garbage collection of maintenances and triggers
  - Can be enabled under `zac.process.garbage_collector.enabled`
  - Optionally also delete maintenances that only contain disabled hosts with `zac.process.garbage_collector.delete_empty_maintenance`.

### Changed

- API internals rewritten to use Pydantic models.
  - Borrows API code from Zabbix-cli v3.
- Dry run mode now guarantees no changes are made to Zabbix by preventing all write operations via the API.

### Removed

- Zabbix 5 support.
  - Should in most cases work with Zabbix 5, but it will not be actively supported going forward.

## 0.1.0

First version
