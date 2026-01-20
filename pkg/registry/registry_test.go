package registry

import (
	"net/url"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func strPtr(s string) *string {
	return &s
}

func createTestDecisions(count int) []*models.Decision {
	decisions := make([]*models.Decision, count)
	for i := range count {
		val := "192.168.1." + string(rune('0'+i%10)) + string(rune('0'+i/10%10))
		decisions[i] = &models.Decision{
			Value:  strPtr(val),
			Type:   strPtr("ban"),
			Origin: strPtr("test"),
		}
	}
	return decisions
}

func TestGetActiveDecisionsPaginated_NoParams(t *testing.T) {
	dr := &DecisionRegistry{
		ActiveDecisionsByValue: make(map[string]*models.Decision),
	}

	// Add 25 test decisions
	decisions := createTestDecisions(25)
	dr.AddDecisions(decisions)

	// Without pagination params, should return all
	result := dr.GetActiveDecisionsPaginated(url.Values{})

	if result.Total != 25 {
		t.Errorf("expected total 25, got %d", result.Total)
	}
	if len(result.Decisions) != 25 {
		t.Errorf("expected 25 decisions, got %d", len(result.Decisions))
	}
	if result.Page != 1 {
		t.Errorf("expected page 1, got %d", result.Page)
	}
	if result.TotalPages != 1 {
		t.Errorf("expected 1 total page, got %d", result.TotalPages)
	}
}

func TestGetActiveDecisionsPaginated_WithPagination(t *testing.T) {
	dr := &DecisionRegistry{
		ActiveDecisionsByValue: make(map[string]*models.Decision),
	}

	// Add 25 test decisions
	decisions := createTestDecisions(25)
	dr.AddDecisions(decisions)

	// Request page 1 with 10 per page
	params := url.Values{}
	params.Set("page", "1")
	params.Set("per_page", "10")

	result := dr.GetActiveDecisionsPaginated(params)

	if result.Total != 25 {
		t.Errorf("expected total 25, got %d", result.Total)
	}
	if len(result.Decisions) != 10 {
		t.Errorf("expected 10 decisions, got %d", len(result.Decisions))
	}
	if result.Page != 1 {
		t.Errorf("expected page 1, got %d", result.Page)
	}
	if result.PerPage != 10 {
		t.Errorf("expected per_page 10, got %d", result.PerPage)
	}
	if result.TotalPages != 3 {
		t.Errorf("expected 3 total pages, got %d", result.TotalPages)
	}
}

func TestGetActiveDecisionsPaginated_LastPage(t *testing.T) {
	dr := &DecisionRegistry{
		ActiveDecisionsByValue: make(map[string]*models.Decision),
	}

	// Add 25 test decisions
	decisions := createTestDecisions(25)
	dr.AddDecisions(decisions)

	// Request page 3 (last page) with 10 per page
	params := url.Values{}
	params.Set("page", "3")
	params.Set("per_page", "10")

	result := dr.GetActiveDecisionsPaginated(params)

	if result.Total != 25 {
		t.Errorf("expected total 25, got %d", result.Total)
	}
	if len(result.Decisions) != 5 {
		t.Errorf("expected 5 decisions on last page, got %d", len(result.Decisions))
	}
	if result.Page != 3 {
		t.Errorf("expected page 3, got %d", result.Page)
	}
}

func TestGetActiveDecisionsPaginated_PageOutOfRange(t *testing.T) {
	dr := &DecisionRegistry{
		ActiveDecisionsByValue: make(map[string]*models.Decision),
	}

	// Add 25 test decisions
	decisions := createTestDecisions(25)
	dr.AddDecisions(decisions)

	// Request page 10 (beyond range) with 10 per page
	params := url.Values{}
	params.Set("page", "10")
	params.Set("per_page", "10")

	result := dr.GetActiveDecisionsPaginated(params)

	// Should clamp to last page
	if result.Page != 3 {
		t.Errorf("expected page to be clamped to 3, got %d", result.Page)
	}
	if len(result.Decisions) != 5 {
		t.Errorf("expected 5 decisions on last page, got %d", len(result.Decisions))
	}
}

func TestGetActiveDecisionsPaginated_SortingConsistency(t *testing.T) {
	dr := &DecisionRegistry{
		ActiveDecisionsByValue: make(map[string]*models.Decision),
	}

	// Add decisions in random order
	decisions := []*models.Decision{
		{Value: strPtr("192.168.1.30"), Type: strPtr("ban"), Origin: strPtr("test")},
		{Value: strPtr("192.168.1.10"), Type: strPtr("ban"), Origin: strPtr("test")},
		{Value: strPtr("192.168.1.20"), Type: strPtr("ban"), Origin: strPtr("test")},
		{Value: strPtr("192.168.1.40"), Type: strPtr("ban"), Origin: strPtr("test")},
		{Value: strPtr("192.168.1.50"), Type: strPtr("ban"), Origin: strPtr("test")},
	}
	dr.AddDecisions(decisions)

	// Get page 1 with 2 per page
	params := url.Values{}
	params.Set("page", "1")
	params.Set("per_page", "2")

	result1 := dr.GetActiveDecisionsPaginated(params)

	// Results should be sorted - first 2 should be .10 and .20
	if *result1.Decisions[0].Value != "192.168.1.10" {
		t.Errorf("expected first decision to be 192.168.1.10, got %s", *result1.Decisions[0].Value)
	}
	if *result1.Decisions[1].Value != "192.168.1.20" {
		t.Errorf("expected second decision to be 192.168.1.20, got %s", *result1.Decisions[1].Value)
	}

	// Get page 2 - should continue sorted order
	params.Set("page", "2")
	result2 := dr.GetActiveDecisionsPaginated(params)

	if *result2.Decisions[0].Value != "192.168.1.30" {
		t.Errorf("expected first decision on page 2 to be 192.168.1.30, got %s", *result2.Decisions[0].Value)
	}
}

func TestGetActiveDecisionsPaginated_EmptyRegistry(t *testing.T) {
	dr := &DecisionRegistry{
		ActiveDecisionsByValue: make(map[string]*models.Decision),
	}

	params := url.Values{}
	params.Set("page", "1")
	params.Set("per_page", "10")

	result := dr.GetActiveDecisionsPaginated(params)

	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
	if len(result.Decisions) != 0 {
		t.Errorf("expected 0 decisions, got %d", len(result.Decisions))
	}
	if result.TotalPages != 1 {
		t.Errorf("expected 1 total page (minimum), got %d", result.TotalPages)
	}
}

func TestGetActiveDecisionsPaginated_InvalidParams(t *testing.T) {
	dr := &DecisionRegistry{
		ActiveDecisionsByValue: make(map[string]*models.Decision),
	}

	decisions := createTestDecisions(10)
	dr.AddDecisions(decisions)

	// Invalid page (negative/zero should default to 1)
	params := url.Values{}
	params.Set("page", "-1")
	params.Set("per_page", "5")

	result := dr.GetActiveDecisionsPaginated(params)

	if result.Page != 1 {
		t.Errorf("expected page to default to 1 for invalid input, got %d", result.Page)
	}

	// Invalid per_page (negative should mean no pagination)
	params.Set("page", "1")
	params.Set("per_page", "-5")

	result = dr.GetActiveDecisionsPaginated(params)

	if len(result.Decisions) != 10 {
		t.Errorf("expected all 10 decisions for invalid per_page, got %d", len(result.Decisions))
	}
}
