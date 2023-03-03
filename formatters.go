package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var FormattersByName map[string]func(w http.ResponseWriter, r *http.Request) = map[string]func(w http.ResponseWriter, r *http.Request){
	"plain_text": PlainTextFormatter,
	"microtik":   MicroTikFormatter,
}

func PlainTextFormatter(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value("decisions").([]*models.Decision)
	ips := make([]string, len(decisions))
	for i, decision := range decisions {
		ips[i] = *decision.Value
	}
	sort.Strings(ips)
	w.Write([]byte(strings.Join(ips, "\n")))
}

func MicroTikFormatter(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value("decisions").([]*models.Decision)
	ips := make([]string, len(decisions))
	listName := r.URL.Query().Get("listname")
	if listName == "" {
		listName = "CrowdSec"
	}
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
	w.Write([]byte(fmt.Sprintf("/ip firewall address-list remove [find list=%s]\n", listName) +
		fmt.Sprintf("/ipv6 firewall address-list remove [find list=%s]\n", listName) +
		strings.Join(ips, "\n")))
}
