
## 0.2.0

### Added

- Zabbix 7 compatibility
- Config options
  - `[zac.process.garbage_collector]` table
  - `[zac.process.host_updater]` table
  - `[zac.process.hostgroup_updater]` table
  - `[zac.process.template_updater]` table
  - `[zac.process.source_merger]` table
- Automatic garbage collection of maintenances and triggers
  - Can be enabled under `zac.process.garbage_collector.enabled`
  - Optionally also delete maintenances that only contain disabled hosts with `zac.process.garbage_collector.delete_empty_maintenance`.

### Changed

- API internals rewritten to use Pydantic models.
  - Borrows API code from Zabbix-cli v3.

### Removed

- Zabbix 5 support.
  - Should in most cases work with Zabbix 5, but it will not be actively supported going forward.

## 0.1.0

First version
