# Zabbix-auto-config

Zabbix-auto-config is a utility that aims to automatically configure hosts, host groups, host inventories, template groups and templates in the monitoring software [Zabbix](https://www.zabbix.com/).

Note: Primarily tested with Zabbix 7.0 and 6.4, but should work with 6.0 and 5.2.

<!-- ToC created with `markdown-toc -i README.md --maxdepth 3` -->

<!-- toc -->

- [Features](#features)
- [Requirements](#requirements)
  - [Environment](#environment)
  - [Zabbix](#zabbix)
  - [Database](#database)
- [Installation](#installation)
  - [uv (recommended)](#uv-recommended)
  - [pip](#pip)
- [Configuration](#configuration)
  - [Logging](#logging)
- [Running](#running)
  - [Mock environment](#mock-environment)
  - [Systemd unit](#systemd-unit)
- [Concepts](#concepts)
  - [Source collectors](#source-collectors)
  - [Host modifiers](#host-modifiers)
  - [Host inventory](#host-inventory)
  - [Garbage Collection](#garbage-collection)
- [Development](#development)
  - [Testing](#testing)
  - [Pre-commit](#pre-commit)

<!-- tocstop -->

## Features

- Create and update hosts from various data sources
- Link templates and add hosts to groups using mapping files
- Manage host inventories, tags, and proxy assignments
- Handle host lifecycle (disable inactive hosts)
- Maintain and clean up host maintenance schedules

## Requirements

- Python >=3.9
- pip >=21.3 or [uv](https://docs.astral.sh/uv/getting-started/installation/) >= 0.5.0
- Zabbix >=6.4

### Environment

A Zabbix environment with the following components is required:

- Zabbix server
- Zabbix web interface
- PostgreSQL database

Instructions on how to set up a development environment can be found in the [Development](#development) section.

### Zabbix

The following host groups are created in Zabbix if they do not exist:

- All-hosts
- All-auto-disabled-hosts

The name of these groups can be configured in the config file to match your Zabbix environment:

```toml
[zabbix]
hostgroup_all = "All-hosts"
hostgroup_disabled = "All-auto-disabled-hosts"
```

These groups contain enabled and disabled hosts respectively.

For automatic linking in templates you could create the templates:

- Template-barry
- Template-pizza

### Database

The application requires a PostgreSQL database to store the state of the collected hosts. The database and tables are created automatically the first time the application runs, provided that the database connection is configured in the config file:

```toml
[zac.db]
user = "zabbix"
password = "secret"
dbname = "zac"
host = "localhost"
port = 5432
connect_timeout = 2

# Extra kwargs are passed to psycopg2.connect.
# See: https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS
# passfile = "/path/to/.pgpass" # Use a password file for authentication
# sslmode = "require" # Require SSL connection
# etc.

[zac.db.init]
db = true
tables = true

[zac.db.tables]
hosts = "hosts"
hosts_source = "hosts_source"
```

> [!TIP]
> See [Configuration](#configuration) for more info on the config file.

Creation of the `zac` database requires superuser privileges. If the configured ZAC user does not have superuser privileges, the `zac` database must be created manually before running the application, and the `zac.db.init.db` option must be set to `false` in the configuration file.

## Installation

Clone the repository:

```bash
git clone https://github.com/unioslo/zabbix-auto-config.git
```

Thereafter, the application can be installed with `uv` or `pip`

### uv (recommended)

In order to get the exact dependencies from the lock file, it's recommended to install the application with `uv sync`:

```bash
uv sync --no-dev
```

### pip

```bash
pip install -e .
```

When installing from source, installing in editable mode is recommended, as it allows for pulling in changes from git without having to reinstall the package.

## Configuration

ZAC tries to load a config file on startup in the following order:

1. `./config.toml`
2. `$XDG_CONFIG_HOME` or `~/.config/zabbix-auto-config/config.toml`

A sample configuration file is provided in the repository: [config.sample.toml](./config.sample.toml). Move this file to one of the locations above and modify it to suit your environment.

### Logging

ZAC provides structured logging via the [structlog](https://www.structlog.org/en/stable/) library. The logs can be rendered as JSON or plain text, depending on the configuration. By default, plain logs are rendered to the console, while JSON logs are rendered to a file.

The logging configuration can be adjusted in the config file:

```toml

[zac.logging]
# Global log level for the application.
# This is the default log level used if sub-configs do not specify a log level.
level = "INFO"

# Activate multiprocessing_logging handler.
# It is unclear whether or not this is needed by default.
# Depending on your system and configuration, this might be necessary to enable,
# so that log messages from different processes are handled correctly.
use_mp_handler = false

[zac.logging.console]
enabled = true
level = "INFO"
format = "text"

[zac.logging.file]
enabled = true
level = "INFO"
format = "json"
# If not set, defaults to $XDG_STATE_HOME/zabbix-auto-config/logs/app.log
path = "/path/to/log/file.log"
rotate = true
max_size_mb = 50
max_logs = 5
```

#### JSON log format

With the default configuration, each line of the log file is a JSON object containing the following fields:

- `event`: The log event (message).
- `level`: The log level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).
- `logger`: The name of the logger that generated the log entry.
- `process_name`: The name of the process that generated the log entry.
- `timestamp`: The time the log entry was created in ISO 8601 format.

Other fields may be present depending on the context of the log entry, such as `host`, `source`, etc.

In the event of an exception, the log entry will also contain an `exception` field with a dict-like structure containing exception information:

<details>
<summary>Example log entry with exception</summary>

The following is a log entry from a source collector that raises an exception, formatted for readability:

```json
{
    "error": "Failed to collect from source 'faultysource': Source collector error!",
    "event": "Work exception",
    "level": "error",
    "timestamp": "2025-09-16T10:13:25.931268Z",
    "process_name": "faultysource",
    "exception": [
        {
            "exc_type": "ZACException",
            "exc_value": "Failed to collect from source 'faultysource': Source collector error!",
            "exc_notes": [],
            "syntax_error": null,
            "is_cause": false,
            "frames": [
                {
                    "filename": "/workspaces/zabbix-auto-config/zabbix_auto_config/processing.py",
                    "lineno": 108,
                    "name": "run",
                    "locals": {
                        "self": "<SourceCollectorProcess name='faultysource' parent=21759 started>",
                        "parent_process": "<_ParentProcess name='MainProcess' parent=None unknown>",
                        "start_time": "datetime.datetime(2025, 9, 16, 10, 13, 25, 712298)",
                        "e": "ZACException(\"Failed to collect from source 'faultysource': Source collector error!\")",
                        "log": "<BoundLogger(context={'error': \"Failed to collect from source 'faultysource': Source collector error!\"}, processors=[<function add_log_level at 0xffff9b000680>, <structlog.stdlib.PositionalArgumentsFormatter object at 0xffff9874ced0>, <structlog.processors.TimeStamper object at 0xffff991865c0>, <structlog.processors.CallsiteParameterAdder object at 0xffff9874d0c0>, <structlog.processors.StackInfoRenderer object at 0xffff99172ef0>, <structlog.processors.UnicodeDecoder object at 0xffff9874d290>, <function _serialize_sets at 0xffff99180860>, <function ProcessorFormatter.wrap_for_formatter at 0xffff9abbec00>])>",
                        "work_duration": "datetime.timedelta(microseconds=594460)"
                    }
                },
                {
                    "filename": "/workspaces/zabbix-auto-config/zabbix_auto_config/processing.py",
                    "lineno": 244,
                    "name": "work",
                    "locals": {
                        "self": "<SourceCollectorProcess name='faultysource' parent=21759 started>"
                    }
                },
                {
                    "filename": "/workspaces/zabbix-auto-config/zabbix_auto_config/processing.py",
                    "lineno": 308,
                    "name": "handle_error",
                    "locals": {
                        "self": "<SourceCollectorProcess name='faultysource' parent=21759 started>",
                        "e": "SourceCollectorError(RuntimeError('Source collector error!'))",
                        "strat_handlers": "{\n    <FailureStrategy.BACKOFF: 'backoff'>: <bound method SourceCollectorProcess.increase_update_interval of <SourceCollectorProcess name='faultysource' parent=21759 started>>,\n    <FailureStrategy.EXIT: 'exit'>: <bound method BaseProcess.stop of <SourceCollectorProcess name='faultysource' parent=21759 started>>,\n    <FailureStrategy.DISABLE: 'disable'>: <bound method SourceCollectorProcess.disable of <SourceCollectorProcess name='faultysource' parent=21759 started>>\n}",
                        "strat": "<FailureStrategy.BACKOFF: 'backoff'>",
                        "handler": "<bound method SourceCollectorProcess.increase_update_interval of <SourceCollectorProcess name='faultysource' parent=21759 started>>"
                    }
                }
            ],
            "is_group": false,
            "exceptions": []
        },
        {
            "exc_type": "SourceCollectorError",
            "exc_value": "Source collector error!",
            "exc_notes": [],
            "syntax_error": null,
            "is_cause": true,
            "frames": [
                {
                    "filename": "/workspaces/zabbix-auto-config/zabbix_auto_config/processing.py",
                    "lineno": 239,
                    "name": "work",
                    "locals": {
                        "self": "<SourceCollectorProcess name='faultysource' parent=21759 started>"
                    }
                },
                {
                    "filename": "/workspaces/zabbix-auto-config/zabbix_auto_config/processing.py",
                    "lineno": 330,
                    "name": "collect",
                    "locals": {
                        "self": "<SourceCollectorProcess name='faultysource' parent=21759 started>",
                        "start_time": "1758017605.7387369"
                    }
                }
            ],
            "is_group": false,
            "exceptions": []
        },
        {
            "exc_type": "RuntimeError",
            "exc_value": "Source collector error!",
            "exc_notes": [],
            "syntax_error": null,
            "is_cause": true,
            "frames": [
                {
                    "filename": "/workspaces/zabbix-auto-config/zabbix_auto_config/processing.py",
                    "lineno": 327,
                    "name": "collect",
                    "locals": {
                        "self": "<SourceCollectorProcess name='faultysource' parent=21759 started>",
                        "start_time": "1758017605.7387369"
                    }
                },
                {
                    "filename": "/workspaces/zabbix-auto-config/path/to/source_collector_dir/faultysource.py",
                    "lineno": 16,
                    "name": "collect",
                    "locals": {
                        "args": "()",
                        "kwargs": "{}"
                    }
                }
            ],
            "is_group": false,
            "exceptions": []
        }
    ]
}
```

</details>

#### Monitor log file in real-time

In order to monitor the log file in real-time, you can use the `tail` command together with `jq` to follow the file and pretty-print the JSON output:

```bash
tail -fn +1 /path/to/log/file | jq .
```

#### Location

By default, the log file is created in `$XDG_STATE_HOME/zabbix-auto-config/logs/app.log`. The application displays the path to the log file on startup if file logging is enabled and the level is set to `DEBUG`:

```
2025-09-16T10:15:21.043038Z [debug    ] Logging to file                file=/home/vscode/.local/state/zabbix-auto-config/log/app.log process_name=MainProcess
```

## Running

Installing the application adds the `zac` command to your path. After activating your virtual environment, you can run the application with:

```bash
zac
```

### Mock environment

A ZAC environment with a set of mock source collectors, host modifiers, and mapping files is included in the [examples](./examples) directory. The [sample config file](./config.sample.toml) comes pre-configured with these activated.

Rename the sample config file to `config.toml` (and optionally move it to the configuration directory) to use it:

```bash
mkdir -p ~/.config/zabbix-auto-config
mv config.sample.toml ~/.config/zabbix-auto-config/config.toml
```

### Systemd unit

To add automatic startup of the application with systemd, create a unit file in `/etc/systemd/system/zabbix-auto-config.service`:

```ini
[Unit]
Description=Zabbix auto config
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
User=zabbix
Group=zabbix
WorkingDirectory=/home/zabbix/zabbix-auto-config # replace with installation path
Environment=PATH=/home/zabbix/zabbix-auto-config/.venv/bin # ditto
ExecStart=/home/zabbix/zabbix-auto-config/.venv/bin/zac # ditto
TimeoutSec=300
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
systemctl enable zabbix-auto-config
systemctl start zabbix-auto-config
```

This will start the application on boot and restart it if it crashes.

## Concepts

### Source collectors

ZAC relies on "Source Collectors" to fetch host data from various sources.
A source can be anything: an API, a file, a database, etc. What matters is that
the source is able to return a list of `zabbix_auto_config.models.Host` objects. ZAC uses these objects to create or update hosts in Zabbix. If a host with the same hostname is collected from multiple different sources, its information is combined into a single logical host object before being used to create/update the host in Zabbix.

#### Writing a source collector

Source collectors are Python modules placed in a directory specified by the `source_collector_dir` option in the `[zac]` table of the configuration file. Zabbix-auto-config attempts to load all modules referenced by name in the configuration file from this directory. If any referenced modules cannot be found in the directory, they will be ignored.

A source collector module contains a function named `collect()` that returns a list of `Host` objects. These host objects are used by Zabbix-auto-config to create or update hosts in Zabbix.

Here's an example of a source collector module that reads hosts from a file:

```python
# example/source_collectors/jsonsource_basic.py

import json
from typing import Any

from zabbix_auto_config.models import Host

DEFAULT_FILE = "hosts.json"

def collect(*args: Any, **kwargs: Any) -> list[Host]:
    filename = kwargs.get("filename", DEFAULT_FILE)
    with open(filename, "r") as f:
        return [Host(**host) for host in json.load(f)]
```

A module is recognized by ZAC as a source collector if it contains a `collect()` function that accepts an arbitrary number of arguments and keyword arguments and returns a list of `Host` objects. Type annotations are optional but recommended.

#### Configuration

The configuration for loading a source collector module, like the `jsonsource_basic.py` module above, includes both required and optional fields:

```toml
[source_collectors.jsonsource]
# Required
module_name = "jsonsource_basic"
update_interval = 60

# Optional
error_tolerance = 5
error_duration = 360
exit_on_error = false
disable_duration = 3600

# Extra keyword arguments to pass to the collect() function
filename = "hosts.json"
```

Only the extra `filename` option is passed as a kwarg to the `collect()` function.

The following configurations options are available:

#### Required configuration

##### module_name

`module_name` is the name of the module to load. This is the name that will be used in the configuration file to reference the module. It must correspond with the name of the module file, without the `.py` extension.

##### update_interval

`update_interval` is the number of seconds between updates. This is the interval at which the `collect()` function will be called.

#### Optional configuration (error handling)

If `error_tolerance` number of errors occur within `error_duration` seconds, the collector is disabled for a given duration. This is an opt-in feature per source collector.

By default, source collectors are never disabled, and instead increase their update intervals using an exponential backoff strategy on each successive error. See the `disable_duration` option for more information.

##### error_tolerance

`error_tolerance` (default: 0) is the maximum number of errors tolerated within `error_duration` seconds.

##### error_duration

`error_duration` (default: 0) specifies the duration in seconds to track and log errors. This value should be at least equal to `error_tolerance * update_interval` to ensure correct error detection.

For instance, with an `error_tolerance` of 5 and an `update_interval` of 60, `error_duration` should be no less than 300 (5 * 60). However, it is advisable to choose a higher value to compensate for processing intervals between error occurrences and the subsequent error count checks, as well as any potential delays from the source collectors.

A useful guide is to set `error_duration` as `(error_tolerance + 1) * update_interval`, providing an additional buffer equivalent to one update interval.

If `error_tolerance` is set, but `error_duration` is not, the application will set an `error_duration` that is slightly longer than the minimum required to ensure correct error detection.

##### exit_on_error

`exit_on_error` (default: true) determines if the application should terminate, or disable the failing collector when number of errors exceed the tolerance. If set to `true`, the application will exit. Otherwise, the collector will be disabled for `disable_duration` seconds. For backwards compatibility with previous versions of Zabbix-auto-config, this option defaults to `true`. In a future major version, the default will be changed to `false`.

##### disable_duration

`disable_duration` (default: 3600) is the duration in seconds to disable collector for. The following disable modes are supported:

- `disable_duration` > 0: Hard disable for `disable_duration` seconds after `error_tolerance` failures
- `disable_duration` = 0: Increase collection interval using exponential backoff after each failure instead of disabling source.
- `disable_duration` < 0: No disable mechanism (always try at fixed interval)

They are described in more detail below:

###### Hard disable

When `disable_duration` is greater than 0, the collector is disabled for `disable_duration` seconds after `error_tolerance` failures within `error_duration` seconds. The collector will not be called during this period. After the `disable_duration` has passed, the collector will be re-enabled and the error count will be reset.

###### Exponential backoff

When `disable_duration` is set to 0, the collector will not be disabled, but the update interval will be increased by a factor of `backoff_factor` after each failure. The update interval will be reset to the original value after a successful collection. This mode is useful for sources that are expected to be temporarily unavailable at times.

###### No disable

When `disable_duration` is less than 0, the collector will not be disabled, and the update interval will not be increased. This mode is useful when using sources that are frequently unavailable, but are not critical to the operation of the application.

##### backoff_factor

`backoff_factor` (default: 1.5) is the factor by which the update interval is increased after each failure when `disable_duration` is set to 0. The update interval is reset to the original value after a successful collection.

#### Keyword arguments

Any extra config options specified in the configuration file will be passed to the `collect()` function as keyword arguments. In the example above, the `filename` option is passed to the `collect()` function, and then accessed via `kwargs["filename"]`.

#### Source collector config validation

One can choose to define a config class for a source collector's configuration to validate the config before running the collector. `zabbix_auto_config.sourcecollectors` defines a base class `CollectorConfig` that can be subclassed to define a config class for a source collector. The config class defines the class method `from_kwargs` that can be used to validate kwargs and instantiate a config object:

```py
# example/source_collectors/jsonsource_collectorconfig.py
from zabbix_auto_config.sourcecollectors import CollectorConfig

class JsonFileSourceConfig(CollectorConfig):
    __collector_name__ = "JSON file source"

    filename: Path
    opt_optional: Optional[str] = None
    opt_default: str = "default"


def collect(**kwargs):
    config = JsonFileSourceConfig.from_kwargs(kwargs)
    # ...
```

> [!NOTE]
> The collector config should _not_ validate `module_name` and `update_interval` as these are required fields and are validated by the application itself, and are not passed to the collector's `collect()` function.

In the example above, we stipulate that the collector config _must_ specify a `filename` value, and that it _may_ specify `opt_optional` and `opt_default` values. The collector config also specifies a name with `__collector_name__`, so that the collector can more easily be identified in error messages:

```plaintext
zabbix_auto_config.exceptions.ZACException: Invalid configuration for source collector 'JSON file source': 1 validation error for JsonFileSourceConfig
required_option
  Field required [type=missing, input_value={}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.10/v/missing
```

### Host modifiers

Host modifiers are Python modules (files) that are placed in a directory defined by the option `host_modifier_dir` in the `[zac]` table of the config file. A host modifier is a module that contains a function named `modify` that takes a `Host` object as its only argument, modifies it, and returns it. Zabbix-auto-config will attempt to load all modules in the given directory.

#### Running source collectors manually

> [!NOTE]
> Optional section - not required for basic operation

A collector can optionally also provide a `if __name__ == "__main__"` block to provide an interface for running the collector in a standalone fashion. This is useful if you want to test the collector module without running the entire application, debug it, or use it in a different context.

> [!IMPORTANT]
> Running collectors standalone requires passing configuration manually as keyword arguments to the `collect()` function.

```py
if __name__ == "__main__":
    # Print hosts as a JSON array when running standalone
    from zabbix_auto_config.models import print_hosts
    print_hosts(collect())
```

#### Collecting JSON output

> [!NOTE]
> Optional section - not required for basic operation

If you wish to collect just the JSON output from a source collector and write it to a file or otherwise manipulate it, you can import `zabbix_auto_config.models.hosts_to_json` and use it like this:

```py
if __name__ == "__main__":
    from zabbix_auto_config.models import hosts_to_json
    with open("output.json", "w") as f:
        f.write(hosts_to_json(collect()))
```

`hosts_to_json` takes a list of `Host` objects and returns a JSON string.

#### Writing a host modifier

A host modifier module that adds a given siteadmin to all hosts could look like this:

```py
# example/host_modifiers/add_siteadmin.py

from zabbix_auto_config.models import Host

SITEADMIN = "admin@example.com"

def modify(host: Host) -> Host:
    if host.hostname.endswith(".example.com"):
        host.siteadmins.add(SITEADMIN)
    return host
```

Any module that contains a function named `modify` which takes a `Host` and returns a `Host` is recognized as a host modifier module. Type annotations are optional, but recommended.

See the [`Host`](https://github.com/unioslo/zabbix-auto-config/blob/2b45f1cb7da0d46b8b218005ebbf751cb17f8793/zabbix_auto_config/models.py#L111-L123) class in `zabbix_auto_config/models.py` for the available fields that can be accessed and modified. One restriction applies: the `modify` function should _never_ modify the hostname of the host. Attempting to do so will result in an error.

### Host inventory

Zac manages only inventory properties configured as `managed_inventory` in `config.toml`. An inventory property will not be removed/blanked from Zabbix even if the inventory property is removed from `managed_inventory` list or from the host in the source e.g:

1. Add "location=x" to a host in a source and wait for sync
2. Remove the "location" property from the host in the source
3. "location=x" will remain in Zabbix

### Garbage Collection

ZAC provides an optional Zabbix garbage collection module that cleans up stale data from Zabbix that is not otherwise managed by ZAC, such as maintenances.

The garbage collector currently does the following:

- Removes disabled hosts from maintenances.
- Deletes maintenances that only contain disabled hosts.

Under normal usage, hosts are removed from maintenances when being disabled by ZAC, but if hosts are disabled outside of ZAC, they will not be removed from maintenances. The GC module will remove these hosts, and optionally delete the maintenance altogether if it only contains disabled hosts.

To enable garbage collection, add the following to your config:

```toml
[zac.process.garbage_collector]
enabled = true
delete_empty_maintenance = true
```

By default, the garbage collector runs every 24 hours. This can be adjusted with the `update_interval` option:

```toml
[zac.process.garbage_collector]
update_interval = 3600 # Run every hour
```

----

## Development

Zabbix-auto-config requires a Linux environment, as well as Zabbix and a PostgreSQL database. The easiest way to set up a development environment is to use the provided Visual Studio Code Development Container[^1][^2] configuration.
We use [uv](https://docs.astral.sh/uv/getting-started/installation/) to manage the development environment inside the container.

The dev container configuration starts up the following containers:

- Zabbix server
- Zabbix web server
- PostgreSQL database
- Development container with Zabbix-auto-config installed

[^1]: <https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers>
[^2]: <https://code.visualstudio.com/docs/devcontainers/containers>

The development environment can be started via the [Visual Studio Code Remote - Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension. The extension will automatically detect the `.devcontainer` directory and prompt you to open the project in a container.

The Zabbix version to target, as well as other settings, can be configured in the [`.env`](./.env) file.

#### Non-containerized development

If you are on a Linux machine and prefer not to develop inside a container, you can first manually start the required services with Docker/Podman Compose:

```bash
podman compose up -d
# or
docker compose up -d
```

Create a local virtual environment and install development dependencies:

```bash
uv sync
```

Activate the virtual environment:

```bash
. .venv/bin/activate
```

Activating the environment will add the `zac` command to your path. You can now run the application with:

```bash
zac
```

#### Visual Studio Code Debug Configuration

Add this configuration to your `.vscode/launch.json` to debug the application:

```json
{
    "name": "Python: Module",
    "type": "debugpy",
    "request": "launch",
    "module": "zabbix_auto_config.__init__",
    "justMyCode": true
}
```

### Testing

Run unit tests with:

```bash
pytest
```

In order to update snapshots, run:

```bash
pytest --inline-snapshot=review
```

### Pre-commit

We use [pre-commit](https://pre-commit.com/) to manage pre-commit hooks. Install the hooks with:

```bash
pre-commit install
```

This will install the hooks in the `.git/hooks` directory. The hooks will run automatically when you commit changes. If you want to run the hooks manually, you can do so with:

```bash
pre-commit run --all-files
```
