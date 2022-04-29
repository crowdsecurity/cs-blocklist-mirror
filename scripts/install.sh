#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-blocklist-mirror"
BIN_PATH="./crowdsec-blocklist-mirror"
CONFIG_DIR="/etc/crowdsec/bouncers/"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-blocklist-mirror.service"
LAPI_KEY=""

gen_apikey() {
    which cscli > /dev/null
    if [[ $? == 0 ]]; then 
        echo "cscli found, generating bouncer api key."
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        LAPI_KEY=`cscli bouncers add crowdsec-blocklist-mirror-${SUFFIX} -o raw`
        READY="yes"
    else 
        echo "cscli not found, you will need to generate api key."
        READY="no"
    fi
}

gen_config_file() {
    LAPI_KEY=${LAPI_KEY} envsubst < ./config/crowdsec-blocklist-mirror.yaml > "${CONFIG_DIR}crowdsec-blocklist-mirror.yaml"
}


install_blocklist_mirror() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/crowdsec-blocklist-mirror.yaml" "${CONFIG_DIR}crowdsec-blocklist-mirror.yaml"
	CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/crowdsec-blocklist-mirror.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

start_service(){
    if [ "$READY" = "yes" ]; then
        systemctl start crowdsec-blocklist-mirror.service
    else
        echo "service not started. You need to get an API key and configure it in ${CONFIG_DIR}crowdsec-blocklist-mirror.yaml"
    fi
    echo "The crowdsec-blocklist-mirror service has been installed!"
}

install_mirror(){
    echo "Installing crowdsec-blocklist-mirror"
    install_blocklist_mirror
    gen_apikey

    gen_config_file
    systemctl enable crowdsec-blocklist-mirror.service
}


if ! [ $(id -u) = 0 ]; then
    echo "Please run the install script as root or with sudo"
    exit 1
fi

install_mirror
start_service