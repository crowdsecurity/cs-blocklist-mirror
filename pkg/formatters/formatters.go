package formatters

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
)

var ByName = map[string]func(w http.ResponseWriter, r *http.Request){
	"plain_text": PlainText,
	"mikrotik":   MikroTik,
	"f5":         F5,
}

func PlainText(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)
	for _, decision := range decisions {
		fmt.Fprintf(w, "%s\n", *decision.Value)
	}
}

func MikroTik(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)
	listName := r.URL.Query().Get("listname")
	if listName == "" {
		listName = "CrowdSec"
	}
	if !r.URL.Query().Has("ipv6only") {
		fmt.Fprintf(w, "/ip firewall address-list remove [find list=%s]\n", listName)
	}
	if !r.URL.Query().Has("ipv4only") {
		fmt.Fprintf(w, "/ipv6 firewall address-list remove [find list=%s]\n", listName)
	}
	for _, decision := range decisions {
		var ipType = "/ip"
		if strings.Contains(*decision.Value, ":") {
			ipType = "/ipv6"
		}
		fmt.Fprintf(w,
			"%s firewall address-list add list=%s address=%s comment=\"%s for %s\"\n",
			ipType,
			listName,
			*decision.Value,
			*decision.Scenario,
			*decision.Duration,
		)
	}
}

func F5(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)
	for _, decision := range decisions {
		var category = *decision.Scenario
		if strings.Contains(*decision.Scenario, "/") {
			category = strings.Split(*decision.Scenario, "/")[1]
		}
		switch strings.ToLower(*decision.Scope) {
		case "ip":
			mask := 32
			if strings.Contains(*decision.Value, ":") {
				mask = 64
			}
			fmt.Fprintf(w,
				"%s,%d,bl,%s\n",
				*decision.Value,
				mask,
				category,
			)
		case "range":
			sep := strings.Split(*decision.Value, "/")
			fmt.Fprintf(w,
				"%s,%s,bl,%s\n",
				sep[0],
				sep[1],
				category,
			)
		default:
		}
	}
}
