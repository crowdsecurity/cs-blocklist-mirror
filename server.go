package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

var RouteHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "blocklist_requests_total",
		Help: "Number of calls to each blocklist",
	},
	[]string{"route"},
)

//	var apiCountersByFormatName map[string]prometheus. = map[string]prometheus.Counter{
//		"plain_text": promauto.NewCounter(prometheus.CounterOpts{
//			Name: "total_api_calls_for_plain_text",
//			Help: "Total number of times blocklist in plain_text format was requested",
//		}),
//	}
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
	ret := make([]*models.Decision, 0)
	if filter.Has("ipv4only") {
		dr.GetActiveIPV4Decisions(&ret)
	} else if filter.Has("ipv6only") {
		dr.GetActiveIPV6Decisions(&ret)
	} else {
		ret = make([]*models.Decision, 0, len(dr.ActiveDecisionsByValue))
		for _, v := range dr.ActiveDecisionsByValue {
			ret = append(ret, v)
		}
	}
	sort.SliceStable(ret, func(i, j int) bool {
		return *ret[i].Value < *ret[j].Value
	})
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
	log.WithFields(log.Fields{
		"expected": expectedVal,
		"found":    foundVal,
	}).Debug("checking basic auth")
	return expectedVal == foundVal
}

func toValidCIDR(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}

	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

func getTrustedIPs(ips []string) ([]net.IPNet, error) {
	trustedIPs := make([]net.IPNet, 0)
	for _, ip := range ips {
		cidr := toValidCIDR(ip)
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		trustedIPs = append(trustedIPs, *ipNet)
	}
	return trustedIPs, nil
}

func networksContainIP(networks []net.IPNet, ip string) bool {
	parsedIP := net.ParseIP(ip)
	for _, network := range networks {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func metricsMiddleware(blockListCfg *BlockListConfig, next http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		RouteHits.WithLabelValues(
			blockListCfg.Endpoint,
		).Inc()
		next.ServeHTTP(w, r)
	}
}

func decisionMiddleware(next http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decisions := globalDecisionRegistry.GetActiveDecisions(r.URL.Query())
		if len(decisions) == 0 {
			http.Error(w, "no decisions available", http.StatusNotFound)
			return
		}
		ctx := context.WithValue(r.Context(), globalDecisionRegistry.Key, decisions)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func authMiddleware(blockListCfg *BlockListConfig, next http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Errorf("error while spliting hostport for %s: %v", r.RemoteAddr, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		trustedIPs, err := getTrustedIPs(blockListCfg.Authentication.TrustedIPs)
		if err != nil {
			log.Errorf("error while parsing trusted IPs: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		switch strings.ToLower(blockListCfg.Authentication.Type) {
		case "ip_based":
			if !networksContainIP(trustedIPs, ip) {
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
		case "basic":
			if !satisfiesBasicAuth(r, blockListCfg.Authentication.User, blockListCfg.Authentication.Password) {
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
		case "", "none":
		}
		next.ServeHTTP(w, r)
	}
}

func getHandlerForBlockList(blockListCfg *BlockListConfig) (func(w http.ResponseWriter, r *http.Request), error) {
	if _, ok := FormattersByName[blockListCfg.Format]; !ok {
		return nil, fmt.Errorf("unknown format %s", blockListCfg.Format)
	}
	return authMiddleware(blockListCfg, metricsMiddleware(blockListCfg, decisionMiddleware(FormattersByName[blockListCfg.Format]))), nil
}
