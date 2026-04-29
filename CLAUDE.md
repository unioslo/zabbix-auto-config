# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

Zabbix-auto-config (ZAC) is a long-running service that automatically creates and updates hosts, host groups, templates, tags, inventory, and proxies in [Zabbix](https://www.zabbix.com/) by pulling host data from external sources. It bridges arbitrary data sources (APIs, files, databases) and Zabbix via a PostgreSQL intermediate database.

## Commands

```bash
# Install dependencies (dev + test)
uv sync

# Run the application
zac

# Run tests
pytest

# Run a single test file or test
pytest tests/test_models.py
pytest tests/test_models.py::test_foo

# Update inline snapshots
pytest --inline-snapshot=review

# Lint
ruff check

# Format
ruff format

# Pre-commit hooks (uses prek, not pre-commit)
prek run
prek run --all-files
```

## Architecture

ZAC is a multi-process Python application. The entry point is `zabbix_auto_config/__init__.py` (`main()`), installed as the `zac` CLI via `pyproject.toml`. It spawns a set of `multiprocessing.Process` subclasses (all defined in `processing.py`) and monitors them in a loop. If any child process dies, the whole application exits.

### Data flow

```
[Source collectors] → queue → [Source handler] → DB(hosts_source)
                                                         ↓
                                              [Source merger + host modifiers]
                                                         ↓
                                                    DB(hosts)
                                                         ↓
                              [ZabbixHostUpdater, ZabbixHostgroupUpdater, ZabbixTemplateUpdater]
                                                         ↓
                                                    Zabbix API
```

### Processes (all in `processing.py`)

| Class | Name | Role |
|---|---|---|
| `SourceCollectorProcess` | one per source | Calls `collect()` on a source module, puts results onto a per-source `multiprocessing.Queue` |
| `SourceHandlerProcess` | `source-handler` | Drains all queues and writes raw hosts into the `hosts_source` DB table |
| `SourceMergerProcess` | `source-merger` | Reads `hosts_source`, merges multi-source hosts, applies host modifiers, writes to `hosts` table |
| `ZabbixHostUpdater` | `zabbix-host-updater` | Enables/disables hosts in Zabbix; syncs proxy, interfaces, tags, inventory |
| `ZabbixHostgroupUpdater` | `zabbix-hostgroup-updater` | Syncs host groups and template groups derived from mapping files |
| `ZabbixTemplateUpdater` | `zabbix-template-updater` | Syncs template links derived from the property→template mapping file |
| `ZabbixGarbageCollector` | `zabbix-garbage-collector` | (Optional) Removes disabled hosts from maintenances; deletes hosts past retention |

`BaseProcess` provides the run loop, error handling, stop-event signalling, and DB connection helpers. All Zabbix-touching processes extend `ZabbixUpdater`, which holds the `ZabbixAPI` client and the three mapping-file dicts.

### Two distinct `Host` models

There are two unrelated `Host` types — do not confuse them:

- `zabbix_auto_config.models.Host` — a ZAC-internal host collected from sources and stored in PostgreSQL. It has fields like `hostname`, `properties`, `siteadmins`, `tags`, `interfaces`, `proxy_pattern`, `inventory`.
- `zabbix_auto_config.pyzabbix.types.Host` — a Pydantic model representing a Zabbix API host object, used only when reading from / writing to the Zabbix API.

### Key modules

- `config.py` — Pydantic settings models loaded from `config.toml`. `Settings` is the root; `ZabbixSettings` holds Zabbix-connection config; `SourceCollectorSettings` holds per-collector config. All config models inherit from `ConfigBaseModel` which warns on unknown fields.
- `models.py` — `models.Host` and `models.Interface`; also `HostPendingDeletion` used by the GC.
- `pyzabbix/client.py` — internal Zabbix API client (forked from pyzabbix), built on `httpx`. Use `ZabbixAPI` for all Zabbix API calls.
- `sourcecollectors.py` — `CollectorConfig` base class for typed source-collector configuration.
- `db.py` — DB init and connection helpers (psycopg2).
- `failsafe.py` — checks whether the number of hosts to add/remove exceeds `zabbix.failsafe`.
- `health.py` / `state.py` — process health tracking written to a JSON health file.
- `cron.py` — thin wrapper around `croniter` used by the garbage collector.
- `compat.py` — Zabbix version compatibility helpers (e.g., template group support).

### Extensibility points

**Source collectors** are Python modules placed in `source_collector_dir` with a `collect(**kwargs) -> list[models.Host]` function. They are referenced by name in `[source_collectors.<name>]` config sections.

**Host modifiers** are Python modules placed in `host_modifier_dir` with a `modify(host: Host) -> Host` function. All `.py` files in the directory are loaded automatically.

**Mapping files** (in `zabbix.map_dir`) are plain-text files mapping properties/siteadmins to templates or host groups:
- `property_template_map.txt`
- `property_hostgroup_map.txt`
- `siteadmin_hostgroup_map.txt`

### Code conventions

- All files must have `from __future__ import annotations` as the first import (enforced by ruff `TID252` + `required-imports`).
- Use absolute imports only.
- Use `structlog.stdlib.get_logger(__name__)` for logging.
- Pydantic v2 throughout — use `model_dump_json()`, `model_validate()`, `model_copy()` etc.
- The `zabbix.dryrun` flag must be checked before any mutating Zabbix API call (pattern: `if self.zabbix_config.dryrun: log.info("DRYRUN: ..."); return`).
