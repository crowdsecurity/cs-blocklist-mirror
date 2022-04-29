package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var apiCountersByFormatName map[string]prometheus.Counter = map[string]prometheus.Counter{
	"fortinet": promauto.NewCounter(prometheus.CounterOpts{
		Name: "total_api_calls_for_fortinet",
		Help: "Total number of times blocklist in fortinet format was requested",
	}),
}
var totalActiveDecisions prometheus.Gauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "total_active_decisions",
	Help: "Total number of decisions served by any blocklist",
})

type DecisionRegistry struct {
	ActiveDecisionsByValue map[string]*models.Decision
}

func (dr *DecisionRegistry) AddDecisions(decisions []*models.Decision) {
	for _, decision := range decisions {
		dr.ActiveDecisionsByValue[*decision.Value] = decision
		totalActiveDecisions.Inc()
	}
}

func (dr *DecisionRegistry) GetActiveDecisions() []*models.Decision {
	ret := make([]*models.Decision, len(dr.ActiveDecisionsByValue))
	i := 0
	for _, v := range dr.ActiveDecisionsByValue {
		ret[i] = v
		i++
	}
	return ret
}

func (dr *DecisionRegistry) DeleteDecisions(decisions []*models.Decision) {
	for _, decision := range decisions {
		if _, ok := dr.ActiveDecisionsByValue[*decision.Value]; ok {
			delete(dr.ActiveDecisionsByValue, *decision.Value)
			totalActiveDecisions.Dec()
		}
	}
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func satisfiesBasicAuth(r *http.Request, user, password string) bool {
	if _, ok := r.Header[http.CanonicalHeaderKey("Authorization")]; !ok {
		return false
	}
	expectedVal := fmt.Sprintf("Basic %s", basicAuth(user, password))
	foundVal := r.Header[http.CanonicalHeaderKey("Authorization")][0]
	return expectedVal == foundVal
}

func getHandlerForBlockList(blockListCfg BlockListConfig) func(http.ResponseWriter, *http.Request) {
	f := func(w http.ResponseWriter, r *http.Request) {
		apiCountersByFormatName[blockListCfg.Format].Inc()
		if strings.EqualFold(blockListCfg.Authentication.Type, "basic") {
			if !satisfiesBasicAuth(r, blockListCfg.Authentication.User, blockListCfg.Authentication.Password) {
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
		}
		w.Write(
			[]byte(FormattersByName[blockListCfg.Format](globalDecisionRegistry.GetActiveDecisions())),
		)
	}
	return f
}
