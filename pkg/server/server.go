package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/cfg"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/formatters"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
)

var BlocklistMirrorAccessLogFilePath = "crowdsec-blocklist-mirror_access.log"

func RunServer(ctx context.Context, g *errgroup.Group, config cfg.Config) error {
	for _, blockListCFG := range config.Blocklists {
		f, err := getHandlerForBlockList(blockListCFG)
		if err != nil {
			return err
		}

		http.HandleFunc(blockListCFG.Endpoint, globalMiddleware(config, f))
		log.Infof("serving blocklist in format %s at endpoint %s", blockListCFG.Format, blockListCFG.Endpoint)
	}

	if config.Metrics.Enabled {
		prometheus.MustRegister(RouteHits)
		log.Infof("Enabling metrics at endpoint '%s' ", config.Metrics.Endpoint)
		http.Handle(config.Metrics.Endpoint, promhttp.Handler())
	}

	var logHandler http.Handler

	if config.EnableAccessLogs {
		logger, err := config.Logging.LoggerForFile(BlocklistMirrorAccessLogFilePath)
		if err != nil {
			return err
		}

		logHandler = CombinedLoggingHandler(logger, http.DefaultServeMux)
	}

	server := &http.Server{
		Handler: logHandler,
	}

	g.Go(func() error {
		if config.ListenSocket != "" {
			log.Info("listening on unix socket: ", config.ListenSocket)
			listener, err := net.Listen("unix", config.ListenSocket)
			if err != nil {
				return err
			}
			defer listener.Close()
			if err := listenAndServe(server, listener, config); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		}
		return nil
	})

	g.Go(func() error {
		if config.ListenURI != "" {
			log.Info("listening on tcp server: ", config.ListenURI)
			listener, err := net.Listen("tcp", config.ListenURI)
			if err != nil {
				return err
			}
			defer listener.Close()

			if err := listenAndServe(server, listener, config); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		}
		return nil
	})

	<-ctx.Done()

	serverCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(serverCtx) //nolint: contextcheck

	return nil
}

/*
Global middlewares are middlewares that are applied to all routes and are not specific to a blocklist.
*/
func globalMiddleware(config cfg.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//Parsed unix socket request
		if r.RemoteAddr == "@" {
			r.RemoteAddr = "127.0.0.1:65535"
		}
		//Trusted proxies
		header := r.Header.Get(config.TrustedHeader)
		// If there is no header then we don't need to do anything
		if header != "" {
			headerSplit := strings.Split(header, ",")
			ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
			if err != nil {
				log.Errorf("error while spliting hostport for %s: %v", r.RemoteAddr, err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			//Loop over the parsed trusted proxies
			for _, trustedProxy := range config.ParsedTrustedProxies {
				//check if the remote address is in the trusted proxies
				if trustedProxy.Contains(net.ParseIP(ip)) {
					// Loop over the header values in reverse order
					for i := len(headerSplit) - 1; i >= 0; i-- {
						ipStr := strings.TrimSpace(headerSplit[i])
						ip := net.ParseIP(ipStr)
						if ip == nil {
							break
						}
						// If the IP is not in the trusted proxies, set the remote address to the IP
						if (i == 0) || (!trustedProxy.Contains(ip)) {
							r.RemoteAddr = ipStr
							break
						}
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	}
}

func listenAndServe(server *http.Server, listener net.Listener, config cfg.Config) error {
	if config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
		return server.ServeTLS(listener, config.TLS.CertFile, config.TLS.KeyFile)
	}

	return server.Serve(listener)
}

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

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func satisfiesBasicAuth(r *http.Request, user, password string) bool {
	if _, ok := r.Header[http.CanonicalHeaderKey("Authorization")]; !ok {
		return false
	}

	expectedVal := "Basic " + basicAuth(user, password)
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
	trustedIPs := make([]net.IPNet, 0, len(ips))

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

func metricsMiddleware(blockListCfg *cfg.BlockListConfig, next http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		RouteHits.WithLabelValues(
			blockListCfg.Endpoint,
		).Inc()
		next.ServeHTTP(w, r)
	}
}

func decisionMiddleware(next http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decisions := registry.GlobalDecisionRegistry.GetActiveDecisions(r.URL.Query())
		if len(decisions) == 0 {
			http.Error(w, "no decisions available", http.StatusNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), registry.GlobalDecisionRegistry.Key, decisions)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func authMiddleware(blockListCfg *cfg.BlockListConfig, next http.HandlerFunc) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authType := strings.ToLower(blockListCfg.Authentication.Type)

		// If auth != none then we implement checks if not bypass them to the next handler
		if authType != "none" {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			// If we can't parse the IP, we use the remote address as is as it most likely been set by the trusted proxies middleware
			if err != nil {
				ip = r.RemoteAddr
			}

			trustedIPs, err := getTrustedIPs(blockListCfg.Authentication.TrustedIPs)
			if err != nil {
				log.Errorf("error while parsing trusted IPs: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)

				return
			}

			switch authType {
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
			}
		}
		next.ServeHTTP(w, r)
	}
}

func getHandlerForBlockList(blockListCfg *cfg.BlockListConfig) (func(w http.ResponseWriter, r *http.Request), error) {
	if _, ok := formatters.ByName[blockListCfg.Format]; !ok {
		return nil, fmt.Errorf("unknown format %s", blockListCfg.Format)
	}

	return authMiddleware(blockListCfg, metricsMiddleware(blockListCfg, decisionMiddleware(formatters.ByName[blockListCfg.Format]))), nil
}
