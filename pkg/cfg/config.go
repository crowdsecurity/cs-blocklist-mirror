package cfg

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/yamlpatch"

	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/formatters"
)

var blocklistMirrorLogFilePath = "crowdsec-blocklist-mirror.log"

type CrowdsecConfig struct {
	LapiKey                    string   `yaml:"lapi_key"`
	LapiURL                    string   `yaml:"lapi_url"`
	UpdateFrequency            string   `yaml:"update_frequency"`
	InsecureSkipVerify         bool     `yaml:"insecure_skip_verify"`
	CertPath                   string   `yaml:"cert_path"`
	KeyPath                    string   `yaml:"key_path"`
	CAPath                     string   `yaml:"ca_cert_path"`
	IncludeScenariosContaining []string `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining []string `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom   []string `yaml:"only_include_decisions_from"`
	Scopes                     []string `yaml:"scopes,omitempty"`
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
	CrowdsecConfig       CrowdsecConfig     `yaml:"crowdsec_config"`
	Blocklists           []*BlockListConfig `yaml:"blocklists"`
	ListenURI            string             `yaml:"listen_uri"`
	ListenSocket         string             `yaml:"listen_socket"`
	TrustedProxies       []string           `yaml:"trusted_proxies"`
	ParsedTrustedProxies []*net.IPNet       `yaml:"-"`
	TrustedHeader        string             `yaml:"trusted_header"`
	TLS                  TLSConfig          `yaml:"tls"`
	Metrics              MetricConfig       `yaml:"metrics"`
	Logging              LoggingConfig      `yaml:",inline"`
	ConfigVersion        string             `yaml:"config_version"`
	EnableAccessLogs     bool               `yaml:"enable_access_logs"`
}

func (cfg *Config) ValidateAndSetDefaults() error {
	if cfg.CrowdsecConfig.LapiKey == "" && cfg.CrowdsecConfig.CertPath == "" {
		return errors.New("one of lapi_key or cert_path is required")
	}

	if cfg.CrowdsecConfig.LapiURL == "" {
		return errors.New("lapi_url is required")
	}

	if !strings.HasSuffix(cfg.CrowdsecConfig.LapiURL, "/") {
		cfg.CrowdsecConfig.LapiURL += "/"
	}

	if cfg.CrowdsecConfig.UpdateFrequency == "" {
		log.Warn("update_frequency is not provided")

		cfg.CrowdsecConfig.UpdateFrequency = "10s"
	}

	if cfg.ConfigVersion == "" {
		log.Warn("config version is not provided; assuming v1.0")

		cfg.ConfigVersion = "v1.0"
	}

	if cfg.ListenURI == "" && cfg.ListenSocket == "" {
		log.Warn("listen_uri is not provided ; assuming 127.0.0.1:41412")

		cfg.ListenURI = "127.0.0.1:41412"
	}

	validAuthenticationTypes := []string{"basic", "ip_based", "none"}
	alreadyUsedEndpoint := make(map[string]struct{})
	validFormats := []string{}

	for format := range formatters.ByName {
		validFormats = append(validFormats, format)
	}

	for _, blockList := range cfg.Blocklists {
		if _, ok := alreadyUsedEndpoint[blockList.Endpoint]; ok {
			return fmt.Errorf("%s endpoint used more than once", blockList.Endpoint)
		}

		alreadyUsedEndpoint[blockList.Endpoint] = struct{}{}

		if !slices.Contains(validFormats, blockList.Format) {
			return fmt.Errorf("%s format is not supported. Supported formats are '%s'", blockList.Format, strings.Join(validFormats, ","))
		}

		if !slices.Contains(validAuthenticationTypes, strings.ToLower(blockList.Authentication.Type)) && blockList.Authentication.Type != "" {
			return fmt.Errorf(
				"%s authentication type is not supported. Supported authentication types are '%s'",
				blockList.Authentication.Type,
				strings.Join(validAuthenticationTypes, ","),
			)
		}
	}

	cfg.ParsedTrustedProxies = make([]*net.IPNet, 0, len(cfg.TrustedProxies))
	for _, ip := range cfg.TrustedProxies {
		if !strings.Contains(ip, "/") {
			log.Debug("no CIDR provided attempting to add /32 or /128; ", ip)
			parsedIP := parseIP(ip)
			if parsedIP == nil {
				return fmt.Errorf("invalid IP address: %s", ip)
			}
			switch len(parsedIP) {
			case net.IPv4len:
				ip += "/32"
			case net.IPv6len:
				ip += "/128"
			}
			log.Debug("added CIDR to IP: ", ip)
		}
		_, ipNet, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}
		log.Info("adding trusted proxy: ", ip)
		cfg.ParsedTrustedProxies = append(cfg.ParsedTrustedProxies, ipNet)
	}

	if cfg.TrustedHeader == "" {
		log.Info("trusted_header is not provided; assuming X-Forwarded-For")
		cfg.TrustedHeader = "X-Forwarded-For"
	}

	if len(cfg.ParsedTrustedProxies) == 0 {
		log.Info("no trusted proxies provided so trusted_header is ignored")
	}

	return nil
}

func parseIP(ip string) net.IP {
	parsedIP := net.ParseIP(ip)
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		return ipv4
	}
	return parsedIP
}

func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")

	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}

	return data, nil
}

func NewConfig(reader io.Reader) (Config, error) {
	config := Config{}

	fcontent, err := io.ReadAll(reader)
	if err != nil {
		return config, err
	}

	configBuff := csstring.StrictExpand(string(fcontent), os.LookupEnv)

	err = yaml.Unmarshal([]byte(configBuff), &config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if err := config.Logging.setup(blocklistMirrorLogFilePath); err != nil {
		return config, err
	}

	return config, nil
}
