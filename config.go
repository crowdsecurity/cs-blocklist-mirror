package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

var blocklistMirrorLogFilePath string = "crowdsec-blocklist-mirror.log"
var blocklistMirrorAccessLogFilePath string = "crowdsec-blocklist-mirror_access.log"

type CrowdsecConfig struct {
	LapiKey                    string   `yaml:"lapi_key"`
	LapiURL                    string   `yaml:"lapi_url"`
	UpdateFrequency            string   `yaml:"update_frequency"`
	InsecureSkipVerify         bool     `yaml:"insecure_skip_verify"`
	IncludeScenariosContaining []string `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining []string `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom   []string `yaml:"only_include_decisions_from"`
}

type BlockListConfig struct {
	Format         string `yaml:"format"`
	Endpoint       string `yaml:"endpoint"`
	Authentication struct {
		Type       string   `yaml:"type"`
		User       string   `yaml:"user"`
		Password   string   `yaml:"password"`
		Token      string   `yaml:"token"`
		TrustedIPs []string `yaml:"trusted_ips"`
	} `yaml:"authentication"`
}

type MetricConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type Config struct {
	CrowdsecConfig   CrowdsecConfig    `yaml:"crowdsec_config"`
	Blocklists       []BlockListConfig `yaml:"blocklists"`
	ListenURI        string            `yaml:"listen_uri"`
	TLS              TLSConfig         `yaml:"tls"`
	Metrics          MetricConfig      `yaml:"metrics"`
	LogLevel         logrus.Level      `yaml:"log_level"`
	LogMedia         string            `yaml:"log_media"`
	LogDir           string            `yaml:"log_dir"`
	LogMaxSize       int               `yaml:"log_max_size"`
	LogMaxAge        int               `yaml:"log_max_age"`
	LogMaxFiles      int               `yaml:"log_max_backups"`
	CompressLogs     *bool             `yaml:"compress_logs"`
	ConfigVersion    string            `yaml:"config_version"`
	EnableAccessLogs bool              `yaml:"enable_access_logs"`
}

func (cfg *Config) getLoggerForFile(fileName string) io.Writer {

	if cfg.LogMedia != "file" {
		return os.Stdout
	}

	if cfg.LogDir == "" {
		cfg.LogDir = "/var/log/"
	}
	_maxsize := 40
	if cfg.LogMaxSize != 0 {
		_maxsize = cfg.LogMaxSize
	}
	_maxfiles := 3
	if cfg.LogMaxFiles != 0 {
		_maxfiles = cfg.LogMaxFiles
	}
	_maxage := 30
	if cfg.LogMaxAge != 0 {
		_maxage = cfg.LogMaxAge
	}
	_compress := true
	if cfg.CompressLogs != nil {
		_compress = *cfg.CompressLogs
	}
	logOutput := &lumberjack.Logger{
		Filename:   path.Join(cfg.LogDir, fileName),
		MaxSize:    _maxsize,
		MaxBackups: _maxfiles,
		MaxAge:     _maxage,
		Compress:   _compress,
	}
	return logOutput
}

func (cfg *Config) ValidateAndSetDefaults() error {
	if cfg.LogMedia == "" {
		cfg.LogMedia = "stdout"
	}
	if cfg.LogLevel == 0 {
		cfg.LogLevel = logrus.InfoLevel
	}
	if err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, cfg.LogLevel, cfg.LogMaxSize, cfg.LogMaxFiles, cfg.LogMaxAge, cfg.CompressLogs, false); err != nil {
		logrus.Fatal(err.Error())
	}
	if cfg.LogMedia == "file" {
		logrus.SetOutput(cfg.getLoggerForFile(blocklistMirrorLogFilePath))
		logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	}

	if cfg.CrowdsecConfig.LapiKey == "" {
		return fmt.Errorf("lapi_key is not specified")
	}
	if cfg.CrowdsecConfig.LapiURL == "" {
		return fmt.Errorf("lapi_url is not specified")
	}

	if !strings.HasSuffix(cfg.CrowdsecConfig.LapiURL, "/") {
		cfg.CrowdsecConfig.LapiURL = cfg.CrowdsecConfig.LapiURL + "/"
	}

	if cfg.CrowdsecConfig.UpdateFrequency == "" {
		logrus.Warn("update_frequency is not provided")
		cfg.CrowdsecConfig.UpdateFrequency = "10s"
	}

	if cfg.ConfigVersion == "" {
		logrus.Warn("config version is not provided; assuming v1.0")
		cfg.ConfigVersion = "v1.0"
	}

	if cfg.ListenURI == "" {
		logrus.Warn("listen_uri is not provided ; assuming 127.0.0.1:41412")
		cfg.ListenURI = "127.0.0.1:41412"
	}

	validAuthenticationTypes := []string{"basic", "ip_based", "none"}
	alreadyUsedEndpoint := make(map[string]struct{})
	validFormats := []string{}
	for format := range FormattersByName {
		validFormats = append(validFormats, format)
	}

	for _, blockList := range cfg.Blocklists {
		if _, ok := alreadyUsedEndpoint[blockList.Endpoint]; ok {
			return fmt.Errorf("%s endpoint used more than once", blockList.Endpoint)
		}
		alreadyUsedEndpoint[blockList.Endpoint] = struct{}{}
		if !contains(validFormats, blockList.Format) {
			return fmt.Errorf("%s format is not supported. Supported formats are '%s'", blockList.Format, strings.Join(validFormats, ","))
		}
		if !contains(validAuthenticationTypes, strings.ToLower(blockList.Authentication.Type)) && blockList.Authentication.Type != "" {
			return fmt.Errorf("%s authentication type is not supported. Supported authentication types are '%s'", blockList.Authentication.Type, strings.Join(validAuthenticationTypes, ","))
		}
	}

	if cfg.LogMedia == "" {
		cfg.LogMedia = "stdout"
	}

	if cfg.LogLevel == 0 {
		cfg.LogLevel = logrus.InfoLevel
	}

	if err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, cfg.LogLevel, cfg.LogMaxSize, cfg.LogMaxFiles, cfg.LogMaxAge, cfg.CompressLogs, false); err != nil {
		logrus.Fatal(err.Error())
	}

	if cfg.LogMedia == "file" {
		logrus.SetOutput(cfg.getLoggerForFile(blocklistMirrorLogFilePath))
		logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	}
	return nil
}

func newConfig(path string) (Config, error) {
	if data, err := os.ReadFile(path); err != nil {
		return Config{}, err
	} else {
		ret := Config{}
		if err := yaml.Unmarshal(data, &ret); err != nil {
			return Config{}, err
		}
		return ret, nil
	}
}

func contains(arr []string, item string) bool {
	for _, i := range arr {
		if i == item {
			return true
		}
	}
	return false
}
