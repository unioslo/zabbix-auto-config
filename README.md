# About

Zabbix-auto-config is an utility that aims to automatically configure hosts, host groups and templates in the monitoring software [Zabbix](https://www.zabbix.com/).

# Quick start

## Database

```
CREATE TABLE hosts (
    data jsonb
);

CREATE TABLE hosts_source (
    data jsonb
);
```

## Systemd unit

```
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
