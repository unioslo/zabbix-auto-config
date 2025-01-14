# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Default value for source collector config `source_collectors.<name>.error_duration` is now computed from `round(error_tolerance * update_interval + (update_interval*0.9))`
- New failure handling strategies for source collectors, which can be set using `disable_duration` for each source collector.
  - `disable_duration == 0` (default): Use exponential backoff to increase the update interval on error. The update interval is reset to the original value on success.
  - `disable_duration > 0`: Disable the source collector for a set duration.
  - `disable_duration < 0`: Never disable, never increase the update interval.
  - `exit_on_error` takes precedence over `disable_duration`. If `exit_on_error` is set to `true`, the source collector will exit on error regardless of the `disable_duration` setting.

### Changed

- The default value of `exit_on_error` for source collectors is now `false`.
- The default value of `disable_duration` for source collectors is now `0`. This means that the source collector will use exponential backoff to increase the update interval on error.

## [0.2.0](https://github.com/unioslo/zabbix-auto-config/releases/tag/zac-v0.2.0)

### Added

- Zabbix 7 compatibility
- Configuration option for setting group prefix separator.
  - `[zabbix]`
    - `prefix_separator`: Separator for group prefixes. Default is `-`.
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
- Automatic garbage collection of maintenances (and more in the future.)
  - Removes disabled hosts from maintenances.
  - This feature is disabled by default, and must be opted into with `zac.process.garbage_collector.enabled`
  - Optionally also delete maintenances that only contain disabled hosts with `zac.process.garbage_collector.delete_empty_maintenance`.
  - If you have a large number of disabled hosts, it's recommended to set a long `update_interval` to avoid unnecessary load on the Zabbix server. The default is 300 seconds.
- Automatic creation of required host groups.
  - Creates the groups configured by the following options:
    - `zabbix.hostgroup_all`
    - `zabbix.hostgroup_disabled`
- Utility functions for serializing source collector outputs:
  - `zabbix_auto_config.models.hosts_to_json`
  - `zabbix_auto_config.models.print_hosts`
- `py.typed` marker file.

### Changed

- API internals rewritten to use Pydantic models.
  - Borrows API code from Zabbix-cli v3.
- Dry run mode now guarantees no changes are made to Zabbix by preventing all write operations via the API.

### Deprecated

- Zabbix 5 support.
  - Should in most cases work with Zabbix 5, but it will not be actively supported going forward.

## 0.1.0

First version
