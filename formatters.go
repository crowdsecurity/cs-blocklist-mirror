package main

import (
	"sort"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var FormattersByName map[string]func([]*models.Decision) string = map[string]func([]*models.Decision) string{
	"plain_text": PlainTextFormatter,
}

func PlainTextFormatter(decisions []*models.Decision) string {
	ips := make([]string, len(decisions))
	for i, decision := range decisions {
		ips[i] = *decision.Value
	}
	sort.Strings(ips)
	return strings.Join(ips, "\n")
}
