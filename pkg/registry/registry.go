package registry

import (
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/aggregate"
)

var activeDecisionCount prometheus.Gauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "active_decision_count",
	Help: "Total number of decisions served by any blocklist",
})

type Key int

type DecisionRegistry struct {
	ActiveDecisionsByValue map[string]*models.Decision
	AggregatedDecisions    []*models.Decision
	Key                    Key
	SupportedDecisionTypes []string
	aggregationEnabled     bool
	mu                     sync.RWMutex
}

// EnableAggregation enables the computation and storage of aggregated decisions.
func (dr *DecisionRegistry) EnableAggregation() {
	dr.mu.Lock()
	defer dr.mu.Unlock()
	dr.aggregationEnabled = true
}

func (dr *DecisionRegistry) AddDecisions(decisions []*models.Decision) {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	for _, decision := range decisions {
		if decision == nil || decision.Value == nil {
			continue
		}

		if _, ok := dr.ActiveDecisionsByValue[*decision.Value]; !ok {
			activeDecisionCount.Inc()
		}

		dr.ActiveDecisionsByValue[*decision.Value] = decision
	}

	dr.recomputeAggregated()
}

func (dr *DecisionRegistry) GetSupportedDecisionTypesWithFilter(filter url.Values) []string {
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

	return allowedTypes
}

func (dr *DecisionRegistry) GetActiveDecisions(filter url.Values, aggregated bool) []*models.Decision {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	var source []*models.Decision
	if aggregated {
		source = dr.AggregatedDecisions
	} else {
		source = make([]*models.Decision, 0, len(dr.ActiveDecisionsByValue))
		for _, v := range dr.ActiveDecisionsByValue {
			source = append(source, v)
		}
	}

	ret := make([]*models.Decision, 0, len(source))

	// Type and origin filters only apply to non-aggregated results.
	// Aggregated ranges may contain IPs from multiple origins/types,
	// so these filters cannot work correctly. Only ipv4only/ipv6only apply.
	var allowedTypes []string
	if !aggregated {
		allowedTypes = dr.GetSupportedDecisionTypesWithFilter(filter)
	}

	for _, v := range source {
		// filter by type if allowedTypes is non-empty (non-aggregated only)
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

		// origin filter only applies to non-aggregated results
		if !aggregated && filter.Has("origin") && v.Origin != nil && !strings.EqualFold(*v.Origin, filter.Get("origin")) {
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

// recomputeAggregated rebuilds the aggregated decisions view.
// Must be called with dr.mu held. Does nothing if aggregation is not enabled.
func (dr *DecisionRegistry) recomputeAggregated() {
	if !dr.aggregationEnabled {
		return
	}

	all := make([]*models.Decision, 0, len(dr.ActiveDecisionsByValue))
	for _, decision := range dr.ActiveDecisionsByValue {
		all = append(all, decision)
	}

	dr.AggregatedDecisions = aggregate.Aggregate(all)
}

func (dr *DecisionRegistry) DeleteDecisions(decisions []*models.Decision) {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	for _, decision := range decisions {
		if decision == nil || decision.Value == nil {
			continue
		}

		if _, ok := dr.ActiveDecisionsByValue[*decision.Value]; ok {
			delete(dr.ActiveDecisionsByValue, *decision.Value)
			activeDecisionCount.Dec()
		}
	}

	dr.recomputeAggregated()
}

var GlobalDecisionRegistry = DecisionRegistry{
	ActiveDecisionsByValue: make(map[string]*models.Decision),
}
