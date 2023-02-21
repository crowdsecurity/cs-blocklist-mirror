package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var FormattersByName map[string]func([]*models.Decision) string = map[string]func([]*models.Decision) string{
	"plain_text": PlainTextFormatter,
	"microtik":   MicroTikFormatter,
}

func PlainTextFormatter(decisions []*models.Decision) string {
	ips := make([]string, len(decisions))
	for i, decision := range decisions {
		ips[i] = *decision.Value
	}
	sort.Strings(ips)
	return strings.Join(ips, "\n")
}

func MicroTikFormatter(decisions []*models.Decision) string {
	ips := make([]string, len(decisions))
	for i, decision := range decisions {
		var ipType = "/ip"
		if strings.Contains(*decision.Value, ":") {
			ipType = "/ipv6"
		}
		ips[i] = fmt.Sprintf(
			"%s firewall address-list add list=CrowdSec address=%s comment=\"%s for %s\"",
			ipType,
			*decision.Value,
			*decision.Scenario,
			*decision.Duration,
		)
	}
	sort.Strings(ips)
	return "/ip firewall address-list remove [find list=CrowdSec]\n" +
		"/ipv6 firewall address-list remove [find list=CrowdSec]\n" +
		strings.Join(ips, "\n")
}
