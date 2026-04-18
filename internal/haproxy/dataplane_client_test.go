package haproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	t.Run("valid http URL", func(t *testing.T) {
		c, err := NewClient(APIConfig{BaseURL: "http://localhost:5555/v3"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c == nil {
			t.Fatal("expected non-nil client")
		}
	})

	t.Run("https without certs requires error", func(t *testing.T) {
		_, err := NewClient(APIConfig{BaseURL: "https://haproxy:5555/v3"})
		if err == nil {
			t.Fatal("expected error for https without certs")
		}
	})

	t.Run("https with insecure skip", func(t *testing.T) {
		c, err := NewClient(APIConfig{
			BaseURL:  "https://haproxy:5555/v3",
			Insecure: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c == nil {
			t.Fatal("expected non-nil client")
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		_, err := NewClient(APIConfig{BaseURL: "://bad"})
		if err == nil {
			t.Fatal("expected error for invalid URL")
		}
	})
}

func TestNewClientWithTransport(t *testing.T) {
	c, err := NewClientWithTransport(
		APIConfig{BaseURL: "http://localhost:5555/v3"},
		http.DefaultTransport,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestValidateRawConfiguration(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v3/services/haproxy/configuration/version":
			json.NewEncoder(w).Encode(1)
		case r.URL.Path == "/v3/services/haproxy/configuration/raw":
			calls++
			if r.URL.Query().Get("only_validate") != "true" {
				t.Error("expected only_validate=true")
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
	if err != nil {
		t.Fatal(err)
	}

	err = c.ValidateRawConfiguration(context.Background(), "global\n  daemon\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 validation call, got %d", calls)
	}
}

func TestApplyRawConfigurationValidated(t *testing.T) {
	var applyCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v3/services/haproxy/configuration/version":
			json.NewEncoder(w).Encode(1)
		case r.URL.Path == "/v3/services/haproxy/configuration/raw":
			if r.URL.Query().Get("only_validate") == "true" {
				t.Error("ApplyRawConfigurationValidated should not call validate")
			}
			applyCalls++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
	if err != nil {
		t.Fatal(err)
	}

	err = c.ApplyRawConfigurationValidated(context.Background(), "global\n  daemon\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if applyCalls != 1 {
		t.Errorf("expected 1 apply call, got %d", applyCalls)
	}
}

func TestAPIError(t *testing.T) {
	e := &APIError{StatusCode: 422, Message: "invalid config"}
	if e.Error() != "dataplane api error (status 422): invalid config" {
		t.Errorf("unexpected error string: %s", e.Error())
	}
}

func TestIsNotFound(t *testing.T) {
	t.Run("404 is not found", func(t *testing.T) {
		if !isNotFound(&APIError{StatusCode: 404}) {
			t.Error("expected true for 404")
		}
	})
	t.Run("500 is not not-found", func(t *testing.T) {
		if isNotFound(&APIError{StatusCode: 500}) {
			t.Error("expected false for 500")
		}
	})
	t.Run("non-APIError is not not-found", func(t *testing.T) {
		if isNotFound(context.Canceled) {
			t.Error("expected false for non-APIError")
		}
	})
}
