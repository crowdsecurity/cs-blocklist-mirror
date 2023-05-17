package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/cs-blocklist-mirror/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
