package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/cs-blocklist-mirror/version"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var globalDecisionRegistry DecisionRegistry = DecisionRegistry{
	ActiveDecisionsByValue: make(map[string]*models.Decision),
}

func runServer(cfg BouncerConfig) {
	for _, blockListCFG := range cfg.Blocklists {
		f, err := getHandlerForBlockList(blockListCFG)
		if err != nil {
			log.Fatal(err)
		}
		http.HandleFunc(blockListCFG.Endpoint, f)
		log.Infof("serving blocklist in format %s at endpoint %s", blockListCFG.Format, blockListCFG.Endpoint)
	}

	if cfg.Metrics.Enabled {
		prometheus.MustRegister(RouteHits)
		log.Infof("Enabling metrics at endpoint '%s' ", cfg.Metrics.Endpoint)
		http.Handle(cfg.Metrics.Endpoint, promhttp.Handler())
	}

	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		log.Infof("Starting server with TLS at %s", cfg.ListenURI)
		log.Fatal(http.ListenAndServeTLS(cfg.ListenURI, cfg.TLS.CertFile, cfg.TLS.KeyFile, nil))
	} else {
		log.Infof("Starting server at %s", cfg.ListenURI)
		log.Fatal(http.ListenAndServe(cfg.ListenURI, nil))
	}
}

func main() {
	configPath := flag.String("c", "", "path to crowdsec-tbd-bouncer.yaml")
	bouncerVersion := flag.Bool("V", false, "display version and exit")
	traceMode := flag.Bool("trace", false, "set trace mode")
	debugMode := flag.Bool("debug", false, "set debug mode")

	flag.Parse()

	if *bouncerVersion {
		fmt.Printf("%s", version.ShowStr())
		os.Exit(0)
	}

	config, err := newConfig(*configPath)
	if err != nil {
		log.Fatalf("could not parse configuration: %s", err)
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
		InsecureSkipVerify: types.BoolPtr(config.CrowdsecConfig.InsecureSkipVerify),
	}

	if err := decisionStreamer.Init(); err != nil {
		log.Fatal(err)
	}

	go func() {
		decisionStreamer.Run()
		log.Fatal("can't access LAPI")
	}()
	go runServer(config.BouncerConfig)

	for decisions := range decisionStreamer.Stream {
		if len(decisions.New) > 0 {
			log.Infof("received %d new decisions", len(decisions.New))
		}
		if len(decisions.Deleted) > 0 {
			log.Infof("received %d expired decisions", len(decisions.Deleted))
		}
		globalDecisionRegistry.AddDecisions(decisions.New)
		globalDecisionRegistry.DeleteDecisions(decisions.Deleted)
	}

}
