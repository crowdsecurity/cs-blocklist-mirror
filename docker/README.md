# blocklist-mirror

## Installation

1. Create a config file, `cfg.yaml` with below contents

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
  - format: plain_text # Supported formats are either of "plain_text"
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

Please find full config reference below.

2. Set the `lapi_key` and `lapi_url`. The LAPI must be accessible from the docker container.

`lapi_key` can be obtained by running the following on machine running LAPI.
```bash
sudo cscli -oraw bouncers add blocklistMirror
```

3. Modify the blocklists section as required.

Run the image with config file mounted and port mapped as desired:
```bash
docker run \
-v $PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-blocklist-mirror.yaml \
-p 41412:41412 \
crowdsecurity/blocklist-mirror
```

4. If you want to enable TLS, then set `cert_file` and `key_file`  config. While running the container mount these from host to the provided path.


## Configuration Reference

### `crowdsec_config`

#### `lapi_url`:

The URL of CrowdSec LAPI. It should be accessible from whichever network the bouncer has access.

#### `lapi_key`:

It can be obtained by running the following on the machine CrowdSec LAPI is deployed on.
```bash

sudo cscli -oraw bouncers add blocklistMirror # -oraw flag can discarded for human friendly output.

```

#### `update_frequency`:

The bouncer will poll the CrowdSec every `update_frequency` interval.

#### `include_scenarios_containing`:

Ignore IPs banned for triggering scenarios not containing either of provided word.

#### `exclude_scenarios_containing`: 

Ignore IPs banned for triggering scenarios containing either of provided word.


#### `only_include_decisions_from`:

Only include IPs banned due to decisions orginating from provided sources. eg value ["cscli", "crowdsec"]

#### `insecure_skip_verify`:

Set to true to skip verifying certificate.


#### `listen_uri`: 

Location where the mirror will start server.

### `tls_config`

#### `cert_file`:

Path to certificate to use if TLS is to be enabled on the mirror server.

#### `key_file`:

Path to certificate key file.

### `metrics`:

#### `enabled`:

Boolean (true|false). Set to true to enable serving and collecting metrics. 

#### `endpoint`:

Endpoint to serve the metrics on.

### `blocklists`:

List of blocklists to serve. Each blocklist has the following configuration.

#### `format`:

Format of the blocklist. Currently only `plain_text` is supported.

#### `endpoint`:

Endpoint to serve the blocklist on.

### `authentication`:

Authentication related config.

#### `type`:

Currently "basic" and "ip_based" authentication is supported. You can disable authentication completely by setting this to 'none'.

- `basic`: It's Basic HTTP  Authentication. Only requests with valid `user` and `password` as specified in below config would pass through

- `ip_based`: Only requests originating from `trusted_ips` would be allowed. 

#### `user`:

Valid username if using `basic` authentication.

#### `password`:

Password for the provided user and using `basic` authentication.

#### `trusted_ips`:

List of valid IPv4 and IPv6 IPs and ranges which have access to blocklist. It's only applicable when authentication `type` is `ip_based`.

## Formats

The bouncer can expose the blocklist in the following formats. You can configure the format of the blocklist by setting it's `format` paramter to any of the supported formats described below.

### plain_text

Example:

```
1.2.3.4
4.3.2.1
```
