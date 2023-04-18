#!/bin/sh

set -eu

BOUNCER="crowdsec-blocklist-mirror"
BOUNCER_PREFIX="cs-blocklist-mirror"

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

API_KEY="<API_KEY>"

gen_apikey() {
    if command -v cscli >/dev/null; then
        msg succ "cscli found, generating bouncer api key."
        unique=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
        bouncer_id="$BOUNCER_PREFIX-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        echo "$bouncer_id" > "$CONFIG.id"
        msg info "API Key: $API_KEY"
        READY="yes"
    else
        msg warn "cscli not found, you will need to generate an api key."
        READY="no"
    fi
}

gen_config_file() {
    # shellcheck disable=SC2016
    API_KEY=${API_KEY} envsubst '$API_KEY' <"./config/$CONFIG_FILE" | \
        install -D -m 0600 /dev/stdin "$CONFIG"
}

install_bouncer() {
    if [ ! -f "$BIN_PATH" ]; then
        msg err "$BIN_PATH not found, exiting."
        exit 1
    fi
    if [ -e "$BIN_PATH_INSTALLED" ]; then
        msg warn "$BIN_PATH_INSTALLED is already installed. Exiting"
        exit 1
    fi
    msg info "Installing $BOUNCER"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
    install -D -m 0600 "./config/$CONFIG_FILE" "$CONFIG"
    # shellcheck disable=SC2016
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst '$CFG $BIN' <"./config/$SERVICE" >"$SYSTEMD_PATH_FILE"
    systemctl daemon-reload
    gen_apikey
    gen_config_file
    set_local_lapi_url 'CROWDSEC_LAPI_URL'
}

# --------------------------------- #

set_colors
install_bouncer

systemctl enable "$SERVICE"
if [ "$READY" = "yes" ]; then
    systemctl start "$SERVICE"
else
    msg warn "service not started. You need to get an API key and configure it in $CONFIG"
fi

msg succ "The $BOUNCER service has been installed!"
exit 0
