package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/version"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var globalDecisionRegistry = DecisionRegistry{
	ActiveDecisionsByValue: make(map[string]*models.Decision),
}

func listenAndServe(server *http.Server, config Config) error {
	if config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
		log.Infof("Starting server with TLS at %s", config.ListenURI)
		return server.ListenAndServeTLS(config.TLS.CertFile, config.TLS.KeyFile)
	}
	log.Infof("Starting server at %s", config.ListenURI)
	return server.ListenAndServe()
}

func runServer(ctx context.Context, g *errgroup.Group, config Config) error {
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
		logHandler = CombinedLoggingHandler(config.getLoggerForFile(blocklistMirrorAccessLogFilePath), http.DefaultServeMux)
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

func main() {
	configPath := flag.String("c", "", "path to crowdsec-blocklist-mirror.yaml")
	bouncerVersion := flag.Bool("version", false, "display version and exit")
	traceMode := flag.Bool("trace", false, "set trace mode")
	debugMode := flag.Bool("debug", false, "set debug mode")
	testConfig := flag.Bool("t", false, "test config and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Printf("%s", version.ShowStr())
		os.Exit(0)
	}

	if configPath == nil || *configPath == "" {
		log.Fatalf("configuration file is required")
	}

	configBytes, err := mergedConfig(*configPath)
	if err != nil {
		log.Fatalf("unable to read config file: %s", err)
	}

	config, err := newConfig(bytes.NewReader(configBytes))
	if err != nil {
		log.Fatalf("unable to load configuration: %s", err)
	}

	if *testConfig {
		log.Info("config is valid")
		os.Exit(0)
	}

	if err := config.ValidateAndSetDefaults(); err != nil {
		log.Fatal(err)
	}

	if debugMode != nil && *debugMode {
		log.SetLevel(log.DebugLevel)
	}

	if traceMode != nil && *traceMode {
		log.SetLevel(log.TraceLevel)
	}

	decisionStreamer := csbouncer.StreamBouncer{
		APIKey:         config.CrowdsecConfig.LapiKey,
		APIUrl:         config.CrowdsecConfig.LapiURL,
		TickerInterval: config.CrowdsecConfig.UpdateFrequency,
		Opts: apiclient.DecisionsStreamOpts{
			ScenariosContaining:    strings.Join(config.CrowdsecConfig.IncludeScenariosContaining, ","),
			ScenariosNotContaining: strings.Join(config.CrowdsecConfig.ExcludeScenariosContaining, ","),
			Origins:                strings.Join(config.CrowdsecConfig.OnlyIncludeDecisionsFrom, ","),
		},
		UserAgent:          fmt.Sprintf("crowdsec-blocklist-mirror/%s", version.VersionStr()),
		CertPath:           config.CrowdsecConfig.CertPath,
		KeyPath:            config.CrowdsecConfig.KeyPath,
		CAPath:             config.CrowdsecConfig.CAPath,
		InsecureSkipVerify: types.BoolPtr(config.CrowdsecConfig.InsecureSkipVerify),
	}

	if err := decisionStreamer.Init(); err != nil {
		log.Fatal(err)
	}

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		decisionStreamer.Run(ctx)
		return fmt.Errorf("stream api init failed")
	})

	g.Go(func() error {
		err := runServer(ctx, g, config)
		if err != nil {
			return fmt.Errorf("blocklist server failed: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				log.Info("terminating bouncer process")
				return nil
			case decisions := <-decisionStreamer.Stream:
				if decisions == nil {
					continue
				}
				if len(decisions.New) > 0 {
					log.Infof("received %d new decisions", len(decisions.New))
					globalDecisionRegistry.AddDecisions(decisions.New)
				}
				if len(decisions.Deleted) > 0 {
					log.Infof("received %d expired decisions", len(decisions.Deleted))
					globalDecisionRegistry.DeleteDecisions(decisions.Deleted)
				}
			}
		}
	})

	if err := g.Wait(); err != nil {
		log.Fatalf("process return with error: %s", err)
	}
}
