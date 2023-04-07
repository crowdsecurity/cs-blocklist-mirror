#!/bin/sh

set -eu

need_api_key() {
    before=$(cat "$CONFIG")
    # shellcheck disable=SC2016
    after=$(envsubst '$API_KEY' < "$CONFIG")

    if [ "$before" = "$after" ]; then
        exit 1
    fi
    exit 0
}

set_api_key() {
    # if we can't set the key, the user will take care of it
    API_KEY="<API_KEY>"
    ret=0

    if command -v cscli >/dev/null; then
        echo "cscli/crowdsec is present, generating API key" >&2
        unique=$(date +%s)
        bouncer_id="$BOUNCER_PREFIX-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        if [ $? -eq 1 ]; then
            echo "failed to create API key" >&2
            ret=1
        else
            echo "API Key successfully created" >&2
            echo "$bouncer_id" > "$CONFIG.id"
        fi
    else
        echo "cscli/crowdsec is not present, please set the API key manually" >&2
        ret=1
    fi

    (
        before=$(cat "$CONFIG")
        umask 077
        # shellcheck disable=SC2016
        echo "$before" | API_KEY="$API_KEY" envsubst '$API_KEY' > "$CONFIG"
    )

    exit "$ret"
}

set_local_port() {
    command -v cscli >/dev/null || return 0
    PORT=$(cscli config show --key "Config.API.Server.ListenURI" | cut -d ":" -f2)
    if [ "$PORT" != "" ]; then
        sed -i "s/localhost:8080/127.0.0.1:$PORT/g" "$CONFIG"
        sed -i "s/127.0.0.1:8080/127.0.0.1:$PORT/g" "$CONFIG"
    fi
}

set_local_lapi_url() {
    # VARNAME is the name of the variable to interpolate
    # in the config file with the URL of the LAPI server,
    # assuming it is running on the same host as the
    # bouncer.
    command -v cscli >/dev/null || return 0
    PORT=$(cscli config show --key "Config.API.Server.ListenURI" | cut -d ":" -f2 || true)
    if [ "$PORT" = "" ]; then
        PORT=8080
    fi
    (
        before=$(cat "$CONFIG")
        umask 077
        echo "$before" | env "$VARNAME=http://127.0.0.1:$PORT" envsubst "\$$VARNAME" > "$CONFIG"
    )
}

cmd=$1
shift
CONFIG=$1
if [ "$CONFIG" = "" ]; then
    echo "missing config file" >&2
    exit 1
fi
shift

case "$cmd" in
    need-api-key)
        need_api_key
        ;;
    set-api-key)
        BOUNCER_PREFIX=$1
        shift
        if [ "$BOUNCER_PREFIX" = "" ]; then
            echo "set-api-key: missing bouncer prefix" >&2
            exit 1
        fi
        set_api_key
        ;;
    set-local-lapi-url)
        VARNAME=$1
        shift
        if [ "$VARNAME" = "" ]; then
            echo "set-local-lapi-url: missing variable name" >&2
            exit 1
        fi
        set_local_lapi_url
        ;;
    set-local-port)
        set_local_port
        ;;
    *)
        echo "This script is not meant to be called directly." >&2
        exit 1 ;;
esac

exit 0
