package update

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckForUpdate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","body":"security fix"}`))
	}))
	defer ts.Close()

	latest, notes, newer, err := checkForUpdateURL("1.0.0", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !newer {
		t.Fatalf("expected update available")
	}
	if latest != "1.2.0" {
		t.Fatalf("unexpected latest version: %s", latest)
	}
	if notes != "security fix" {
		t.Fatalf("unexpected release notes: %s", notes)
	}
}

func TestCheckForUpdateNoUpdate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","body":""}`))
	}))
	defer ts.Close()

	_, _, newer, err := checkForUpdateURL("1.2.0", ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newer {
		t.Fatalf("did not expect update")
	}
}
