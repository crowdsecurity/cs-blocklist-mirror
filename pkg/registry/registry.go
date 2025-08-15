package registry

import (
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var activeDecisionCount prometheus.Gauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "active_decision_count",
	Help: "Total number of decisions served by any blocklist",
})

type Key int

type DecisionRegistry struct {
	ActiveDecisionsByValue map[string]*models.Decision
	Key                    Key
	SupportedDecisionTypes []string
}

func (dr *DecisionRegistry) AddDecisions(decisions []*models.Decision) {
	for _, decision := range decisions {
		if _, ok := dr.ActiveDecisionsByValue[*decision.Value]; !ok {
			activeDecisionCount.Inc()
		}

		dr.ActiveDecisionsByValue[*decision.Value] = decision
	}
}

func (dr *DecisionRegistry) GetActiveDecisions(filter url.Values) []*models.Decision {
	ret := make([]*models.Decision, 0, len(dr.ActiveDecisionsByValue))

	// determine allowed types: per-request override or registry default
	allowedTypes := make([]string, 0)
	if filter.Has("supported_decisions_types") {
		for _, v := range filter["supported_decisions_types"] {
			for _, t := range strings.Split(v, ",") {
				tt := strings.TrimSpace(strings.ToLower(t))
				if tt == "" {
					continue
				}
				allowedTypes = append(allowedTypes, tt)
			}
		}
	} else {
		for _, t := range dr.SupportedDecisionTypes {
			tt := strings.TrimSpace(strings.ToLower(t))
			if tt == "" {
				continue
			}
			allowedTypes = append(allowedTypes, tt)
		}
	}

	for _, v := range dr.ActiveDecisionsByValue {
		// filter by type if allowedTypes is non-empty
		if len(allowedTypes) > 0 {
			dType := ""
			if v.Type != nil {
				dType = strings.ToLower(*v.Type)
			}
			if !slices.Contains(allowedTypes, dType) {
				continue
			}
		}
		if filter.Has("ipv6only") && strings.Contains(*v.Value, ".") {
			continue
		}

		if filter.Has("ipv4only") && strings.Contains(*v.Value, ":") {
			continue
		}

		if filter.Has("origin") && !strings.EqualFold(*v.Origin, filter.Get("origin")) {
			continue
		}

		ret = append(ret, v)
	}

	if !filter.Has("nosort") {
		sort.SliceStable(ret, func(i, j int) bool {
			return *ret[i].Value < *ret[j].Value
		})
	}

	return ret
}

func (dr *DecisionRegistry) DeleteDecisions(decisions []*models.Decision) {
	for _, decision := range decisions {
		if _, ok := dr.ActiveDecisionsByValue[*decision.Value]; ok {
			delete(dr.ActiveDecisionsByValue, *decision.Value)
			activeDecisionCount.Dec()
		}
	}
}

var GlobalDecisionRegistry = DecisionRegistry{
	ActiveDecisionsByValue: make(map[string]*models.Decision),
}
