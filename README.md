# Zabbix-auto-config

## About

Zabbix-auto-config is a utility that aims to automatically configure hosts, host groups, host inventories, template groups and templates in the monitoring software [Zabbix](https://www.zabbix.com/).

Note: Primarily tested with Zabbix 7.0 and 6.4, but should work with 6.0 and 5.2.

## Requirements

* Python >=3.9
* pip >=21.3 or [uv](https://docs.astral.sh/uv/getting-started/installation/) >= 0.5.0
* Zabbix >=6.4

## Quick start

This is a crash course in how to quickly get this application up and running in a local test environment:

### Zabbix test instance

Setup a Zabbix test instance with [podman](https://podman.io/) and [podman-compose](https://github.com/containers/podman-compose/).

```bash
TAG=7.0-ubuntu-latest ZABBIX_PASSWORD=secret podman-compose up -d
```

### Zabbix prerequisites

The following host groups are created in Zabbix if they do not exist:

* All-auto-disabled-hosts
* All-hosts

The name of these groups can be configured in `config.toml`:

```toml
[zabbix]
hostgroup_all = "All-hosts"
hostgroup_disabled = "All-auto-disabled-hosts"
```

These groups contain enabled and disabled hosts respectively.

For automatic linking in templates you could create the templates:

* Template-barry
* Template-pizza

### Database

The application requires a PostgreSQL database to store the state of the collected hosts. The database can be created with the following command from your local machine:

```bash
PGPASSWORD=secret psql -h localhost -U postgres -p 5432 -U zabbix << EOF
CREATE DATABASE zac;
\c zac
CREATE TABLE hosts (
    data jsonb
);
CREATE TABLE hosts_source (
    data jsonb
);
EOF
```

If running from inside a dev container, replace the host (`-h`) with the container name of the database container (default: `db`).

This is a one-time procedure per environment.

### Application

#### Installation

Clone the repository:

```bash
git clone https://github.com/unioslo/zabbix-auto-config.git
```

#### uv

In order to get the exact dependencies from the lock file, it's recommended to install the application with `uv sync`:

```
uv sync --no-dev
```

#### pip

```
pip install -e .
```

When installing from source, installing in editable mode is recommended, as it allows for pulling in changes from git without having to reinstall the package.

#### Configuration (mock environment)

A ZAC environment with a set of mock source collectors, host modifiers, and mapping files can be set up with the following commands:

```bash
cp config.sample.toml config.toml
sed -i 's/^dryrun = true$/dryrun = false/g' config.toml
mkdir -p path/to/source_collector_dir/ path/to/host_modifier_dir/ path/to/map_dir/
cat > path/to/source_collector_dir/mysource.py << EOF
from typing import Any, List
from zabbix_auto_config.models import Host

HOSTS = [
    {
        "hostname": "foo.example.com",
    },
    {
        "hostname": "bar.example.com",
    },
]


def collect(*args: Any, **kwargs: Any) -> List[Host]:
    hosts = []
    for host in HOSTS:
        host["enabled"] = True
        host["siteadmins"] = ["bob@example.com"]
        host["properties"] = ["pizza"]
        source = kwargs.get("source")
        if source:
            host["properties"].append(source)
        hosts.append(Host(**host))

    return hosts


if __name__ == "__main__":
    # Print hosts as a JSON array when running standalone
    from zabbix_auto_config.models import print_hosts
    print_hosts(collect())
EOF
cat > path/to/host_modifier_dir/mod.py << EOF
from zabbix_auto_config.models import Host

def modify(host: Host) -> Host:
    if host.hostname == "bar.example.com":
        host.properties.add("barry")
    return host
EOF
cat > path/to/map_dir/property_template_map.txt << EOF
pizza:Template-pizza
barry:Template-barry
EOF
cat > path/to/map_dir/property_hostgroup_map.txt << EOF
other:Hostgroup-other-hosts
EOF
cat > path/to/map_dir/siteadmin_hostgroup_map.txt << EOF
bob@example.com:Hostgroup-bob-hosts
EOF
```

This will create a new config file, set up a source collector, and create mapping files for siteadmins and properties to host groups and templates.

#### Running

Installing the application adds the `zac` command to your path. After activating your virtual environment, you can run the application with:

```bash
zac
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

### Source collectors

ZAC relies on "Source Collectors" to fetch host data from various sources.
A source can be anything: an API, a file, a database, etc. What matters is that
the source is able to return a list of `zabbix_auto_config.models.Host` objects. ZAC uses these objects to create or update hosts in Zabbix. If a host with the same hostname is collected from multiple different sources, its information is combined into a single logical host object before being used to create/update the host in Zabbix.

#### Writing a source collector

Source collectors are Python modules placed in a directory specified by the `source_collector_dir` option in the `[zac]` table of the configuration file. Zabbix-auto-config attempts to load all modules referenced by name in the configuration file from this directory. If any referenced modules cannot be found in the directory, they will be ignored.

A source collector module contains a function named `collect()` that returns a list of `Host` objects. These host objects are used by Zabbix-auto-config to create or update hosts in Zabbix.

Here's an example of a source collector module that reads hosts from a file:

```python
# path/to/source_collector_dir/load_from_json.py

import json
from typing import Any, Dict, List

from zabbix_auto_config.models import Host

DEFAULT_FILE = "hosts.json"

def collect(*args: Any, **kwargs: Any) -> List[Host]:
    filename = kwargs.get("filename", DEFAULT_FILE)
    with open(filename, "r") as f:
        return [Host(**host) for host in json.load(f)]
```

A module is recognized as a source collector if it contains a `collect()` function that accepts an arbitrary number of arguments and keyword arguments and returns a list of `Host` objects. Type annotations are optional but recommended.

We can also provide a `if __name__ == "__main__"` block to run the collector standalone. This is useful for testing the collector module without running the entire application.

```py
if __name__ == "__main__":
    # Print hosts as a JSON array when running standalone
    from zabbix_auto_config.models import print_hosts
    print_hosts(collect())
```

If you wish to collect just the JSON output and write it to a file or otherwise manipulate it, you can import the `hosts_to_json` function from `zabbix_auto_config.models` and use it like this:

```py
if __name__ == "__main__":
    from zabbix_auto_config.models import hosts_to_json
    with open("output.json", "w") as f:
        f.write(hosts_to_json(collect()))
```

#### Configuration

The configuration entry for loading a source collector module, like the `load_from_json.py` module above, includes both mandatory and optional fields. Here's how it can be configured:

```toml
[source_collectors.load_from_json]
module_name = "load_from_json"
update_interval = 60
error_tolerance = 5
error_duration = 360
exit_on_error = false
disable_duration = 3600
# Extra keyword arguments to pass to the collect function:
filename = "hosts.json"
```

Only the extra `filename` option is passed in as a kwarg to the `collect()` function.

The following configurations options are available:

#### Mandatory configuration

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

* `disable_duration` > 0: Hard disable for `disable_duration` seconds after `error_tolerance` failures
* `disable_duration` = 0: Increase collection interval using exponential backoff after each failure instead of disabling source.
* `disable_duration` < 0: No disable mechanism (always try at fixed interval)

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

### Host modifiers

Host modifiers are Python modules (files) that are placed in a directory defined by the option `host_modifier_dir` in the `[zac]` table of the config file. A host modifier is a module that contains a function named `modify` that takes a `Host` object as its only argument, modifies it, and returns it. Zabbix-auto-config will attempt to load all modules in the given directory.

#### Writing a host modifier

A host modifier module that adds a given siteadmin to all hosts could look like this:

```py
# path/to/host_modifier_dir/add_siteadmin.py

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

* Removes disabled hosts from maintenances.
* Deletes maintenances that only contain disabled hosts.

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

### Development

We use [uv](https://docs.astral.sh/uv/getting-started/installation/) to manage the development environment. The following instructions assume that you have uv installed.

Install the development dependencies:

```bash
uv sync
```

Optionally also activate the virtual environment:

```bash
. .venv/bin/activate
```

#### Testing

Run unit tests with:

```bash
uv run pytest
```

In order to update snapshots, run:

```bash
uv run pytest --inline-snapshot=review
```

#### Pre-commit

We use [pre-commit](https://pre-commit.com/) to manage pre-commit hooks. Install the hooks with:

```bash
pre-commit install
```

This will install the hooks in the `.git/hooks` directory. The hooks will run automatically when you commit changes. If you want to run the hooks manually, you can do so with:

```bash
pre-commit run --all-files
```
