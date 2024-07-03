# blocklist-mirror

## Installation

1. Create a config file, `cfg.yaml` with the contents below:

```yaml
config_version: v1.0
crowdsec_config:
  lapi_key: ${API_KEY}
  lapi_url: http://127.0.0.1:8080/
  update_frequency: 10s
  include_scenarios_containing: []
  exclude_scenarios_containing: []
  only_include_decisions_from: []
  insecure_skip_verify: false

blocklists:
  - format: plain_text # Supported formats are either of "plain_text", "mikrotik"
    endpoint: /security/blocklist
    authentication:
      type: none # Supported types are either of "none", "ip_based", "basic"
      user:
      password:
      trusted_ips: # IP ranges, or IPs which don't require auth to access this blocklist
        - 127.0.0.1
        - ::1

listen_uri: 0.0.0.0:41412
tls:
  cert_file:
  key_file:

metrics:
  enabled: true
  endpoint: /metrics

log_media: stdout
log_level: info
```

Please find the full config reference below.

2. Set the `lapi_key` and `lapi_url`. The LAPI must be accessible from the docker container.

`lapi_key` can be obtained by running the following on the machine running LAPI:
```bash
sudo cscli -oraw bouncers add blocklistMirror
```

3. Modify the blocklists section as required.

Run the image with the config file mounted and port mapped as desired:
```bash
docker run \
-v $PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-blocklist-mirror.yaml \
-p 41412:41412 \
crowdsecurity/blocklist-mirror
```

4. If you want to enable TLS, then set `cert_file` and `key_file` config. While running the container mount these from host to the provided path.

## Configuration Reference

### `crowdsec_config`

| Parameter                      | Description                                                                                                     |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `lapi_url`                     | The URL of CrowdSec LAPI. It should be accessible from whichever network the bouncer has access.                |
| `lapi_key`                     | It can be obtained by running the following on the machine CrowdSec LAPI is deployed on.                        |
| `update_frequency`             | The bouncer will poll the CrowdSec every `update_frequency` interval.                                           |
| `include_scenarios_containing` | Ignore IPs banned for triggering scenarios not containing either of the provided words.                         |
| `exclude_scenarios_containing` | Ignore IPs banned for triggering scenarios containing either of the provided words.                             |
| `only_include_decisions_from`  | Only include IPs banned due to decisions originating from provided sources. e.g., value `["cscli", "crowdsec"]` |
| `insecure_skip_verify`         | Set to true to skip verifying the certificate.                                                                  |
| `listen_uri`                   | Location where the mirror will start the server.                                                                |

### `tls_config`

| Parameter   | Description                                             |
|-------------|---------------------------------------------------------|
| `cert_file` | Path to the certificate to use if TLS is to be enabled. |
| `key_file`  | Path to the certificate key file.                       |

### `metrics`

| Parameter  | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `enabled`  | Boolean (true/false). Set to true to enable serving and collecting metrics. |
| `endpoint` | Endpoint to serve the metrics on.                                           |

### `blocklists`

Each blocklist has the following configuration:

| Parameter        | Description                                                                         |
|------------------|-------------------------------------------------------------------------------------|
| `format`         | Format of the blocklist. Currently, only `plain_text` and `mikrotik` are supported. |
| `endpoint`       | Endpoint to serve the blocklist on.                                                 |
| `authentication` | Authentication related config. See the table below for `authentication` parameters. |

#### `authentication`

| Parameter     | Description                                                                                                                                              |
|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `type`        | Authentication type. Currently "basic" and "ip_based" authentication are supported. You can disable authentication completely by setting this to 'none'. |
| `user`        | Valid username if using `basic` authentication.                                                                                                          |
| `password`    | Password for the provided user when using `basic` authentication.                                                                                        |
| `trusted_ips` | List of valid IPv4 and IPv6 IPs and ranges which have access to blocklist. Only applicable when authentication `type` is `ip_based`.                     |

## Global RunTime Query Parameters

| Parameter  | Description                                                                                                       | Requires Value | Example Usage                                            |
|------------|-------------------------------------------------------------------------------------------------------------------|----------------|----------------------------------------------------------|
| `ipv4only` | Only return IPv4 addresses                                                                                        | No             | `http://localhost:41412/security/blocklist?ipv4only`     |
| `ipv6only` | Only return IPv6 addresses                                                                                        | No             | `http://localhost:41412/security/blocklist?ipv6only`     |
| `nosort`   | Do not sort IPs. Only use if you do not care about the sorting of the list; can result in average 1ms improvement | No             | `http://localhost:41412/security/blocklist?nosort`       |
| `origin`   | Only return IPs by origin                                                                                         | Yes            | `http://localhost:41412/security/blocklist?origin=cscli` |

## Formats

The bouncer can expose the blocklist in the following formats. You can configure the format of the blocklist by setting its `format` parameter to any of the supported formats described below.

### plain_text

Example:
```text
1.2.3.4
4.3.2.1
```

### mikrotik

Generates a MikroTik Script that the device can execute to populate the specified firewall address list.

#### MikroTik query parameters

| Parameter      | Description                                                              |
|----------------|--------------------------------------------------------------------------|
| `listname=foo` | Set the list name to `foo`. By default, `listname` is set to `CrowdSec`. |

Example output:
```bash
/ip/firewall/address-list/remove [ find where list="foo" ];
:global CrowdSecAddIP;
:set CrowdSecAddIP do={
    :do { /ip/firewall/address-list/add list=foo address=$1 comment="$2" timeout=$3; } on-error={ }
}
$CrowdSecAddIP 1.2.3.4 "crowdsecurity/ssh-bf" 152h40m24s
$CrowdSecAddIP 4.3.2.1 "crowdsecurity/postfix-spam" 166h40m25s
$CrowdSecAddIP 2001:470:1:c84::17 "crowdsecurity/ssh-bf" 165h13m42s
```

#### Example: MikroTik import script

Using on device [MikroTik scripting](https://help.mikrotik.com/docs/display/ROS/Scripting) following is a starting point to download and import the blocklist. Ensure to adjust the [global query parameters](#global-runtime-query-parameters) according to your needs! 

```bash
:local name "[crowdsec]"
:local url "http://<IP>:41412/security/blocklist?ipv4only&nosort"
:local fileName "blocklist.rsc"
:log info "$name fetch blocklist from $url"
/tool fetch url="$url" mode=http dst-path=$fileName
:if ([:len [/file find name=$fileName]] > 0) do={
    :log info "$name import;start"
    /import file-name=$fileName
    :log info "$name import:done"
} else={
    :log error "$name failed to fetch the blocklist"
}
```