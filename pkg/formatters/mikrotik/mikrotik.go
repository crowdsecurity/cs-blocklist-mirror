package mikrotik

import (
	_ "embed"
	"net/http"
	"strconv"
	"strings"
	"text/template"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
)

type CustomFirewallDecisionData struct {
	IPAddress string
	Scenario  string
	Duration  string
	IsIPv6    bool
}

type CustomMikrotikData struct {
	ListName               string
	Decisions              []CustomFirewallDecisionData
	NameOfMikrotikFunction string
	IPv6Only               bool
	IPv4Only               bool
}

//go:embed mikrotik.tmpl
var MikrotikScriptTemplate string

func Format(w http.ResponseWriter, r *http.Request) {

	// Extract decisions from the context
	decisions := r.Context().Value(registry.GlobalDecisionRegistry.Key).([]*models.Decision)

	// Get query parameters
	query := r.URL.Query()

	// check if ipv6only or ipv4only is set
	ipv6only := query.Has("ipv6only")
	ipv4only := query.Has("ipv4only")

	listName := query.Get("listname")
	if listName == "" {
		listName = "CrowdSec"
	}
	// Prepare data for the template
	decisionData := make([]CustomFirewallDecisionData, 0, len(decisions))

	for _, decision := range decisions {
		decisionData = append(decisionData, CustomFirewallDecisionData{
			IPAddress: *decision.Value,
			Scenario:  *decision.Scenario,
			Duration:  *decision.Duration,
			IsIPv6:    strings.Contains(*decision.Value, ":"),
		})
	}

	data := CustomMikrotikData{
		ListName:               listName,
		Decisions:              decisionData,
		NameOfMikrotikFunction: "CrowdSecBlockIP",
		IPv6Only:               ipv6only,
		IPv4Only:               ipv4only,
	}

	// Parse the template
	parsedTemplate, err := template.New("script").Parse(MikrotikScriptTemplate)
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Execute the template
	var script strings.Builder
	err = parsedTemplate.Execute(&script, data)
	if err != nil {
		http.Error(w, "Error executing template "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Remove empty lines and trim leading/trailing white spaces from the script
	scriptString := strings.TrimSpace(strings.ReplaceAll(script.String(), "\n\n", "\n"))
	script.Reset()
	script.WriteString(scriptString)

	// Get the content length of the script
	contentLength := len(scriptString)

	// Set the Content-Length header
	w.Header().Set("Content-Length", strconv.Itoa(contentLength))

	// Write the script to the http.ResponseWriter
	_, err = w.Write([]byte(script.String()))
	if err != nil {
		w.Header().Del("Content-Length")
		http.Error(w, "Error writing response "+err.Error(), http.StatusInternalServerError)
	}
}
