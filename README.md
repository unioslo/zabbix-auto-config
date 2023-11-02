# About

Zabbix-auto-config is an utility that aims to automatically configure hosts, host groups, host inventories and templates in the monitoring software [Zabbix](https://www.zabbix.com/).

Note: This is only tested with Zabbix 5.0 LTS.

# Quick start

This is a crash course in how to quickly get this application up and running in a local test environment:

## Zabbix test instance

Setup a Zabbix test instance with [podman](https://podman.io/) and [podman-compose](https://github.com/containers/podman-compose/).

```bash
TAG=alpine-5.0-latest ZABBIX_PASSWORD=secret podman-compose up -d
```

## Zabbix prerequisites

It is currently assumed that you have the following hostgroups in Zabbix. You should logon to Zabbix and create them:

* All-auto-disabled-hosts
* All-hosts

For automatic linking in templates you could create the templates:

* Template-barry
* Template-pizza

## Database

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

## Application

```bash
python3 -m venv venv
. venv/bin/activate
pip install -e .
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
    for host in collect():
        print(host.json())
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

Run the application:

```bash
zac
```

## Systemd unit

You could run this as a systemd service:

```ini
[Unit]
Description=Zabbix auto config
After=network.target

[Service]
User=zabbix
Group=zabbix
WorkingDirectory=/home/zabbix/zabbix-auto-config
Environment=PATH=/home/zabbix/zabbix-auto-config/venv/bin
ExecStart=/home/zabbix/zabbix-auto-config/venv/bin/zac
TimeoutSec=300

[Install]
WantedBy=multi-user.target
```

## Source collectors

Source collectors are Python modules placed in a directory specified by the `source_collector_dir` option in the `[zac]` table of the configuration file. Zabbix-auto-config attempts to load all modules referenced by name in the configuration file from this directory. If any referenced modules cannot be found in the directory, they will be ignored.

A source collector module contains a function named `collect` that returns a list of `Host` objects. These host objects are used by Zabbix-auto-config to create or update hosts in Zabbix.

Here's an example of a source collector module that reads hosts from a file:

```python
# path/to/source_collector_dir/load_from_json.py

from typing import Any, Dict, List
from zabbix_auto_config.models import Host

DEFAULT_FILE = "hosts.json" 

def collect(*args: Any, **kwargs: Any) -> List[Host]:
    filename = kwargs.get("filename", DEFAULT_FILE)
    with open(filename, "r") as f:
        return [Host(**host) for host in f.read()]
```

A module is recognized as a source collector if it contains a `collect` function that accepts an arbitrary number of arguments and keyword arguments and returns a list of `Host` objects. Type annotations are optional but recommended.

The configuration entry for loading a source collector module, like the `load_from_json.py` module above, includes both mandatory and optional fields. Here's how it can be configured:

```toml
[source_collectors.load_from_json]
module_name = "load_from_json"
update_interval = 60
error_tolerance = 5
error_duration = 360
exit_on_error = false
disable_duration = 3600
filename = "hosts.json"
```

The following configurations options are available:

### Mandatory configuration

#### module_name
`module_name` is the name of the module to load. This is the name that will be used in the configuration file to reference the module. It must correspond with the name of the module file, without the `.py` extension.

#### update_interval
`update_interval` is the number of seconds between updates. This is the interval at which the `collect` function will be called.

### Optional configuration (error handling)

If `error_tolerance` number of errors occur within `error_duration` seconds, the collector is disabled. Source collectors do not tolerate errors by default and must opt-in to this behavior by setting `error_tolerance` and `error_duration` to non-zero values. If `exit_on_error` is set to `true`, the application will exit. Otherwise, the collector will be disabled for `disable_duration` seconds.


#### error_tolerance

`error_tolerance` (default: 0) is the maximum number of errors tolerated within `error_duration` seconds. 

#### error_duration

`error_duration` (default: 0) specifies the duration in seconds to track and log errors. This value should be at least equal to `error_tolerance * update_interval` to ensure correct error detection. 

For instance, with an `error_tolerance` of 5 and an `update_interval` of 60, `error_duration` should be no less than 300 (5 * 60). However, it is advisable to choose a higher value to compensate for processing intervals between error occurrences and the subsequent error count checks, as well as any potential delays from the source collectors. 

A useful guide is to set `error_duration` as `(error_tolerance + 1) * update_interval`, providing an additional buffer equivalent to one update interval.

#### exit_on_error

`exit_on_error` (default: true) determines if the application should terminate, or disable the failing collector when number of errors exceed the tolerance. If set to `true`, the application will exit. Otherwise, the collector will be disabled for `disable_duration` seconds. For backwards compatibility with previous versions of Zabbix-auto-config, this option defaults to `true`. In a future major version, the default will be changed to `false`.

#### disable_duration

`disable_duration` (default: 3600) is the duration in seconds to disable collector for. If set to 0, the collector is disabled indefinitely, requiring a restart of the application to re-enable it.

### Keyword arguments

Any extra config options specified in the configuration file will be passed to the `collect` function as keyword arguments. In the example above, the `filename` option is passed to the `collect` function, and then accessed via `kwargs["filename"]`.


## Host modifiers

Host modifiers are Python modules (files) that are placed in a directory defined by the option `host_modifier_dir` in the `[zac]` table of the config file. A host modifier is a module that contains a function named `modify` that takes a `Host` object as its only argument, modifies it, and returns it. Zabbix-auto-config will attempt to load all modules in the given directory.

A host modifier module that adds a given siteadmin to all hosts could look like this:

```py
# path/to/host_modifier_dir/add_siteadmin.py

from zabbix_auto_config.models import Host

SITEADMIN = "admin@example.com"

def modify(host: Host) -> Host:
    host.siteadmins.add(SITEADMIN)
    return host
```

Any module that contains a function named `modify` which takes a `Host` and returns a `Host` is recognized as a host modifier module. Type annotations are optional, but recommended.

See the [`Host`](https://github.com/unioslo/zabbix-auto-config/blob/2b45f1cb7da0d46b8b218005ebbf751cb17f8793/zabbix_auto_config/models.py#L111-L123) class in `zabbix_auto_config/models.py` for the available fields that can be accessed and modified. One restriction applies: the `modify` function should _never_ modify the hostname of the host. Attempting to do so will result in an error. 

## Host inventory

ZAC manages only inventory properties configured as `managed_inventory` in `config.toml`. An inventory property will not be removed/blanked from Zabbix even if the inventory property is removed from `managed_inventory` list or from the host in the source e.g:

1. Add "location=x" to a host in a source and wait for sync
2. Remove the "location" property from the host in the source
3. "location=x" will remain in Zabbix

## Host property tagging

ZAC can automatically tag hosts with their source properties. Host Properties is metadata/annotations for a host assigned by source collectors. See `collect()` function from `mysource.py` in [Application](#application) and [Source collectors](#source-collectors) for more information on how to assign properties.

By default, property tagging is disabled, but can be enabled in the config file:

```toml
[zabbix.property_tagging]
enabled = true
tag = "property"
include_patterns = []
exclude_patterns = []
```

With this configuration, each of the host's properties are used to create a tag with the format `property:<property_name>`. For example, if a host has the property `is_dhcp_server`, it will be tagged with `property:is_dhcp_server`. Zabbix hosts can have multiple tags with the same name as long as their values are different. For a host with multiple properties, each property will create a tag named `property` with different values corresponding to the property names.

The name of the tag can be configured with the `tag` option, so if we, for example, want to change the tag format to `role:<property_name>`, we can do so by changing the value of `tag`:

```toml
tag = "role"
```

### Filtering

The properties used for tagging can be filtered using the options `include_patterns` & `exclude_patterns`, which are lists of regular expressions. If no patterns are included, all properties are used.

If a host has a property called `broken_server` and we want to exclude it from being used as a tag, we can add an exclude pattern:

```toml
exclude_patterns = ["broken_server"]
```

If we want to exclude all properties starting with `broken_`, we can add a wildcard pattern:

```toml
exclude_patterns = ["broken_.*"]
```

If we only want to include properties that follow the `is_<type>_server` pattern, we can use an include pattern:
```toml
include_patterns = ["is_.*_server"]
```

We can also combine include and exclude patterns to create more advanced filters:

```toml
include_patterns = ["is_.*_server"]
exclude_patterns = ["is_broken_server", "is_bad_server"]
```
