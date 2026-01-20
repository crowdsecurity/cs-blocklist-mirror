package registry

import (
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// PaginatedResult holds paginated decisions with metadata
type PaginatedResult struct {
	Decisions  []*models.Decision
	Total      int
	Page       int
	PerPage    int
	TotalPages int
}

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

func (dr *DecisionRegistry) GetActiveDecisions(filter url.Values) []*models.Decision {
	ret := make([]*models.Decision, 0, len(dr.ActiveDecisionsByValue))

	allowedTypes := dr.GetSupportedDecisionTypesWithFilter(filter)

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

// GetActiveDecisionsPaginated returns paginated decisions with metadata.
// Query params: page (default 1), per_page (default 0 = all)
func (dr *DecisionRegistry) GetActiveDecisionsPaginated(filter url.Values) PaginatedResult {
	// Get all filtered and sorted decisions first
	allDecisions := dr.GetActiveDecisions(filter)
	total := len(allDecisions)

	// Parse pagination params
	page := 1
	perPage := 0 // 0 means no pagination (return all)

	if filter.Has("page") {
		if p, err := strconv.Atoi(filter.Get("page")); err == nil && p > 0 {
			page = p
		}
	}

	if filter.Has("per_page") {
		if pp, err := strconv.Atoi(filter.Get("per_page")); err == nil && pp > 0 {
			perPage = pp
		}
	}

	// If no pagination requested, return all results
	if perPage == 0 {
		return PaginatedResult{
			Decisions:  allDecisions,
			Total:      total,
			Page:       1,
			PerPage:    total,
			TotalPages: 1,
		}
	}

	// Calculate pagination
	totalPages := (total + perPage - 1) / perPage // ceiling division
	if totalPages == 0 {
		totalPages = 1
	}

	// Clamp page to valid range
	if page > totalPages {
		page = totalPages
	}

	// Calculate slice bounds
	start := (page - 1) * perPage
	end := start + perPage
	if end > total {
		end = total
	}
	if start > total {
		start = total
	}

	return PaginatedResult{
		Decisions:  allDecisions[start:end],
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
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
