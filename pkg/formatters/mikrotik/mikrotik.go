package mikrotik

import (
	"bytes"
	_ "embed"
	"net/http"
	"strings"
	"text/template"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
)

type CustomMikrotikData struct {
	ListName               string
	Decisions              []*models.Decision
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

	data := CustomMikrotikData{
		ListName:               listName,
		Decisions:              decisions,
		NameOfMikrotikFunction: "CrowdSecBlockIP",
		IPv6Only:               ipv6only,
		IPv4Only:               ipv4only,
	}

	// Parse the template
	parsedTemplate, err := template.New("script").Funcs(template.FuncMap{
		"contains": strings.Contains,
	}).Parse(MikrotikScriptTemplate)
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var buf = new(bytes.Buffer)
	// Execute the template
	err = parsedTemplate.Execute(buf, data)
	if err != nil {
		http.Error(w, "Error executing template "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}
