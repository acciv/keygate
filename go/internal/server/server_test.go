package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acciv/keygate/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Addr:             ":0",
		MasterKey:        "test-key",
		AllowedProviders: "telegram,openai",
		AllowedScopes:    "read,send",
		MaxTTL:           100,
		DenyUnknown:      true,
		RatePerMinute:    100,
		Providers:        map[string]string{"telegram": "123:FAKE"},
	}
}

func TestResolveAllowed(t *testing.T) {
	handler := New(testConfig()).Routes()
	body := `{"provider":"telegram","scope":"send","ttl":60}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/resolve", strings.NewReader(body))
	req.Header.Set("X-KeyGate-Key", "test-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, ok := response["lease"]; !ok {
		t.Fatalf("no lease in response: %s", rec.Body.String())
	}
}

func TestResolveDenied(t *testing.T) {
	handler := New(testConfig()).Routes()
	body := `{"provider":"vk","scope":"send","ttl":60}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/resolve", strings.NewReader(body))
	req.Header.Set("X-KeyGate-Key", "test-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthRequired(t *testing.T) {
	handler := New(testConfig()).Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}
