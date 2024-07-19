package formatters

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/formatters/mikrotik"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
)

var ByName = map[string]func(w http.ResponseWriter, r *http.Request){
	"plain_text": PlainText,
	"mikrotik":   mikrotik.Format,
	"f5":         F5,
	"juniper":    Juniper,
}

func PlainText(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)
	for _, decision := range decisions {
		fmt.Fprintf(w, "%s\n", *decision.Value)
	}
}

func F5(w http.ResponseWriter, r *http.Request) {
	decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)
	for _, decision := range decisions {
		category := *decision.Scenario
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

func Juniper(w http.ResponseWriter, r *http.Request) {
    decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)
    for _, decision := range decisions {
        switch strings.ToLower(*decision.Scope) {
        case "ip":
            mask := "/32"
            if strings.Contains(*decision.Value, ":") {
                mask = "/128"
            }
            fmt.Fprintf(w, "%s%s\n", *decision.Value, mask)
        case "range":
            fmt.Fprintf(w, "%s\n", *decision.Value)
        default:
        }
    }
}
