package cmd

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/cfg"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/server"
)

func Execute() error {
	configPath := flag.String("c", "", "path to crowdsec-blocklist-mirror.yaml")
	bouncerVersion := flag.Bool("version", false, "display version and exit")
	traceMode := flag.Bool("trace", false, "set trace mode")
	debugMode := flag.Bool("debug", false, "set debug mode")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Printf("%s", version.FullString())
		return nil
	}

	if configPath == nil || *configPath == "" {
		return fmt.Errorf("configuration file is required")
	}

	configBytes, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configBytes))
		return nil
	}

	config, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("unable to load configuration: %w", err)
	}

	if *testConfig {
		log.Info("config is valid")
		return nil
	}

	if err := config.ValidateAndSetDefaults(); err != nil {
		return err
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
		UserAgent:          fmt.Sprintf("crowdsec-blocklist-mirror/%s", version.String()),
		CertPath:           config.CrowdsecConfig.CertPath,
		KeyPath:            config.CrowdsecConfig.KeyPath,
		CAPath:             config.CrowdsecConfig.CAPath,
		InsecureSkipVerify: ptr.Of(config.CrowdsecConfig.InsecureSkipVerify),
	}

	if err := decisionStreamer.Init(); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		decisionStreamer.Run(ctx)
		return fmt.Errorf("bouncer stream halted")
	})

	g.Go(func() error {
		err := server.RunServer(ctx, g, config)
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
					registry.GlobalDecisionRegistry.AddDecisions(decisions.New)
				}
				if len(decisions.Deleted) > 0 {
					log.Infof("received %d expired decisions", len(decisions.Deleted))
					registry.GlobalDecisionRegistry.DeleteDecisions(decisions.Deleted)
				}
			}
		}
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("process terminated with error: %w", err)
	}

	return nil
}
