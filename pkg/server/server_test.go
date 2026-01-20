package server

import (
	"net/url"
	"strings"
	"testing"

	"github.com/crowdsecurity/cs-blocklist-mirror/pkg/registry"
)

func TestBuildLinkHeader_NoPagination(t *testing.T) {
	reqURL, _ := url.Parse("http://example.com/blocklist")

	// No pagination (per_page = 0)
	result := registry.PaginatedResult{
		Page:       1,
		PerPage:    0,
		TotalPages: 1,
	}

	link := buildLinkHeader(reqURL, result)
	if link != "" {
		t.Errorf("expected empty link header for no pagination, got: %s", link)
	}
}

func TestBuildLinkHeader_SinglePage(t *testing.T) {
	reqURL, _ := url.Parse("http://example.com/blocklist?per_page=100")

	result := registry.PaginatedResult{
		Page:       1,
		PerPage:    100,
		TotalPages: 1,
	}

	link := buildLinkHeader(reqURL, result)
	if link != "" {
		t.Errorf("expected empty link header for single page, got: %s", link)
	}
}

func TestBuildLinkHeader_FirstPage(t *testing.T) {
	reqURL, _ := url.Parse("http://example.com/blocklist?per_page=10")

	result := registry.PaginatedResult{
		Page:       1,
		PerPage:    10,
		TotalPages: 5,
	}

	link := buildLinkHeader(reqURL, result)

	// Should have first, last, and next (no prev on first page)
	if !strings.Contains(link, `rel="first"`) {
		t.Error("expected first link")
	}
	if !strings.Contains(link, `rel="last"`) {
		t.Error("expected last link")
	}
	if !strings.Contains(link, `rel="next"`) {
		t.Error("expected next link")
	}
	if strings.Contains(link, `rel="prev"`) {
		t.Error("should not have prev link on first page")
	}
	if !strings.Contains(link, "page=2") {
		t.Error("next link should point to page 2")
	}
	if !strings.Contains(link, "page=5") {
		t.Error("last link should point to page 5")
	}
}

func TestBuildLinkHeader_MiddlePage(t *testing.T) {
	reqURL, _ := url.Parse("http://example.com/blocklist?per_page=10&page=3")

	result := registry.PaginatedResult{
		Page:       3,
		PerPage:    10,
		TotalPages: 5,
	}

	link := buildLinkHeader(reqURL, result)

	// Should have all four links
	if !strings.Contains(link, `rel="first"`) {
		t.Error("expected first link")
	}
	if !strings.Contains(link, `rel="last"`) {
		t.Error("expected last link")
	}
	if !strings.Contains(link, `rel="prev"`) {
		t.Error("expected prev link")
	}
	if !strings.Contains(link, `rel="next"`) {
		t.Error("expected next link")
	}
}

func TestBuildLinkHeader_LastPage(t *testing.T) {
	reqURL, _ := url.Parse("http://example.com/blocklist?per_page=10&page=5")

	result := registry.PaginatedResult{
		Page:       5,
		PerPage:    10,
		TotalPages: 5,
	}

	link := buildLinkHeader(reqURL, result)

	// Should have first, last, and prev (no next on last page)
	if !strings.Contains(link, `rel="first"`) {
		t.Error("expected first link")
	}
	if !strings.Contains(link, `rel="last"`) {
		t.Error("expected last link")
	}
	if !strings.Contains(link, `rel="prev"`) {
		t.Error("expected prev link")
	}
	if strings.Contains(link, `rel="next"`) {
		t.Error("should not have next link on last page")
	}
	if !strings.Contains(link, "page=4") {
		t.Error("prev link should point to page 4")
	}
}

func TestBuildLinkHeader_PreservesOtherParams(t *testing.T) {
	reqURL, _ := url.Parse("http://example.com/blocklist?per_page=10&ipv4only=1&origin=crowdsec")

	result := registry.PaginatedResult{
		Page:       1,
		PerPage:    10,
		TotalPages: 3,
	}

	link := buildLinkHeader(reqURL, result)

	// Should preserve other query params
	if !strings.Contains(link, "ipv4only=1") {
		t.Error("expected ipv4only param to be preserved")
	}
	if !strings.Contains(link, "origin=crowdsec") {
		t.Error("expected origin param to be preserved")
	}
}
