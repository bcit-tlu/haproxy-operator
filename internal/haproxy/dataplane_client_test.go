package haproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestResolveURL(t *testing.T) {
	c, err := NewClient(APIConfig{BaseURL: "http://haproxy:5555/v3/"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"/services/haproxy/info":          "http://haproxy:5555/v3/services/haproxy/info",
		"services/haproxy/info":           "http://haproxy:5555/v3/services/haproxy/info",
		"/configuration/raw?version=3":    "http://haproxy:5555/v3/configuration/raw?version=3",
		"/raw?only_validate=true&version": "http://haproxy:5555/v3/raw?only_validate=true&version",
	}
	for in, want := range cases {
		if got := c.resolveURL(in); got != want {
			t.Errorf("resolveURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Both request wrappers must share URL resolution, auth, status handling and
// decoding; only the body encoding and Content-Type may differ.
func TestDoRequestVariantsSharePlumbing(t *testing.T) {
	type seen struct {
		path, query, contentType, auth, body string
	}
	var got seen
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = seen{r.URL.Path, r.URL.RawQuery, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), string(b)}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"version":"3.2"}`))
		} else {
			_, _ = w.Write([]byte("nope"))
		}
	}))
	defer srv.Close()

	c, err := NewClient(APIConfig{BaseURL: srv.URL + "/v3", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))

	t.Run("json", func(t *testing.T) {
		var out map[string]string
		if err := c.doRequest(context.Background(), http.MethodPost, "/x?a=1", map[string]int{"n": 1}, &out); err != nil {
			t.Fatal(err)
		}
		want := seen{"/v3/x", "a=1", "application/json", wantAuth, `{"n":1}`}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if out["version"] != "3.2" {
			t.Errorf("decode failed: %+v", out)
		}
	})

	t.Run("plain", func(t *testing.T) {
		var out map[string]string
		if err := c.doRequestPlain(context.Background(), http.MethodPost, "/x?a=1", "global\n", &out); err != nil {
			t.Fatal(err)
		}
		want := seen{"/v3/x", "a=1", "text/plain", wantAuth, "global\n"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if out["version"] != "3.2" {
			t.Errorf("decode failed: %+v", out)
		}
	})

	t.Run("non-2xx becomes APIError on both paths", func(t *testing.T) {
		status = http.StatusBadRequest
		for name, err := range map[string]error{
			"json":  c.doRequest(context.Background(), http.MethodGet, "/x", nil, nil),
			"plain": c.doRequestPlain(context.Background(), http.MethodGet, "/x", "", nil),
		} {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || apiErr.Message != "nope" {
				t.Errorf("%s: unexpected error %v", name, err)
			}
		}
	})
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("boom") }
func (failingBody) Close() error             { return nil }

func TestNewAPIErrorSurfacesBodyReadError(t *testing.T) {
	e := newAPIError(&http.Response{StatusCode: 500, Body: failingBody{}})
	if !strings.Contains(e.Message, "boom") {
		t.Errorf("expected read error in message, got %q", e.Message)
	}
}
