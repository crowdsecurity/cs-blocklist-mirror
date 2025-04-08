package server

import (
	"compress/gzip"
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

		http.HandleFunc(blockListCFG.Endpoint, f)
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
		Addr:    config.ListenURI,
		Handler: logHandler,
	}

	g.Go(func() error {
		err := listenAndServe(server, config)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	<-ctx.Done()

	serverCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(serverCtx) //nolint: contextcheck

	return nil
}

func listenAndServe(server *http.Server, config cfg.Config) error {
	if config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
		log.Infof("Starting server with TLS at %s", config.ListenURI)
		return server.ListenAndServeTLS(config.TLS.CertFile, config.TLS.KeyFile)
	}

	log.Infof("Starting server at %s", config.ListenURI)

	return server.ListenAndServe()
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
	expectedVal := "Basic " + basicAuth(user, password)
	foundVal := r.Header.Get("Authorization")
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
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"crowdsec-blocklist-mirror\"")
				http.Error(w, "access denied", http.StatusUnauthorized)
				return
			}
			if !satisfiesBasicAuth(r, blockListCfg.Authentication.User, blockListCfg.Authentication.Password) {
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
		case "", "none":
		}

		next.ServeHTTP(w, r)
	}
}

// gzipResponseWriter wraps http.ResponseWriter and gzip.Writer
type gzipResponseWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.gz.Write(b)
}

// gzipMiddleware checks for gzip support and wraps the response if needed
func gzipMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if client accepts gzip encoding
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			// Set appropriate headers
			w.Header().Set("Content-Encoding", "gzip")

			// Create gzip writer
			gz := gzip.NewWriter(w)
			defer gz.Close()

			// Wrap the response writer
			grw := &gzipResponseWriter{
				ResponseWriter: w,
				gz:             gz,
			}

			next.ServeHTTP(grw, r)
			return
		}

		// Fall back to normal response writer
		next.ServeHTTP(w, r)
	}
}

func getHandlerForBlockList(blockListCfg *cfg.BlockListConfig) (func(w http.ResponseWriter, r *http.Request), error) {
	if _, ok := formatters.ByName[blockListCfg.Format]; !ok {
		return nil, fmt.Errorf("unknown format %s", blockListCfg.Format)
	}

	return gzipMiddleware(
		authMiddleware(blockListCfg,
			metricsMiddleware(blockListCfg,
				decisionMiddleware(formatters.ByName[blockListCfg.Format])))), nil
}
