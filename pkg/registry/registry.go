package registry

import (
	"net/url"
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
	if !filter.Has("ipv4only") {
		dr.GetActiveIPV6Decisions(&ret)
	}
	if !filter.Has("ipv6only") {
		dr.GetActiveIPV4Decisions(&ret)
	}
	if !filter.Has("nosort") {
		sort.SliceStable(ret, func(i, j int) bool {
			return *ret[i].Value < *ret[j].Value
		})
	}
	return ret
}

func (dr *DecisionRegistry) GetActiveIPV4Decisions(ret *[]*models.Decision) {
	for _, v := range dr.ActiveDecisionsByValue {
		if strings.Contains(*v.Value, ":") {
			continue
		}
		*ret = append(*ret, v)
	}
}

func (dr *DecisionRegistry) GetActiveIPV6Decisions(ret *[]*models.Decision) {
	for _, v := range dr.ActiveDecisionsByValue {
		if strings.Contains(*v.Value, ".") {
			continue
		}
		*ret = append(*ret, v)
	}
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
