package main

import (
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var FormattersByName map[string]func([]*models.Decision) string = map[string]func([]*models.Decision) string{
	"plain-text": plain-textFormatter,
}


func plain-textFormatter(decisions []*models.Decision) string {
	ips := make([]string, len(decisions))
	for i, decision := range decisions {
		ips[i] = *decision.Value
	}
	return strings.Join(ips, "\n")
}
