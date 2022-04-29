package main

import (
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var FormattersByName map[string]func([]*models.Decision) string = map[string]func([]*models.Decision) string{
	"fortinet": fortinetFormatter,
}


func fortinetFormatter(decisions []*models.Decision) string {
	ips := make([]string, len(decisions))
	for i, decision := range decisions {
		ips[i] = *decision.Value
	}
	return strings.Join(ips, "\n")
}
