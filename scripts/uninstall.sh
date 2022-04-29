#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-blocklist-mirror"
CONFIG_DIR="/etc/crowdsec/crowdsec-blocklist-mirror/"
LOG_FILE="/var/log/crowdsec-blocklist-mirror.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-blocklist-mirror.service"

uninstall() {
	systemctl stop crowdsec-blocklist-mirror
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "crowdsec-blocklist-mirror uninstall successfully"