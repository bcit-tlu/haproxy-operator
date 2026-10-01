package haproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// testCertPEM returns a fresh self-signed certificate PEM for storage tests.
func testCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSyncSSLCertificate(t *testing.T) {
	pemBytes := testCertPEM(t, "test.ltc.bcit.ca")
	wantSerial, err := leafSerial(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	type recordedCall struct{ method, path, contentType, filename string }
	serve := func(remoteSerial string, remoteExists bool, calls *[]recordedCall) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/configuration/version"):
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, "1")
			case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/storage/ssl_certificates/star.pem"):
				if !remoteExists {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"serial": remoteSerial})
			case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/storage/ssl_certificates"):
				_, hdr, err := r.FormFile("file_upload")
				if err != nil {
					t.Errorf("multipart file_upload missing: %v", err)
				}
				*calls = append(*calls, recordedCall{r.Method, r.URL.Path, r.Header.Get("Content-Type"), hdr.Filename})
				w.WriteHeader(http.StatusCreated)
			case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/storage/ssl_certificates/star.pem"):
				*calls = append(*calls, recordedCall{r.Method, r.URL.Path, r.Header.Get("Content-Type"), ""})
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	}

	t.Run("creates via multipart when missing", func(t *testing.T) {
		var calls []recordedCall
		srv := serve("", false, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 1 || calls[0].method != http.MethodPost {
			t.Fatalf("expected one POST, got %+v", calls)
		}
		if calls[0].filename != "star.pem" {
			t.Errorf("multipart filename = %q, want star.pem (becomes storage name)", calls[0].filename)
		}
		if !strings.HasPrefix(calls[0].contentType, "multipart/form-data") {
			t.Errorf("content-type = %q", calls[0].contentType)
		}
	})

	t.Run("skips when serial matches", func(t *testing.T) {
		var calls []recordedCall
		srv := serve(wantSerial, true, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes)
		if err != nil || changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 0 {
			t.Errorf("expected no writes, got %+v", calls)
		}
	})

	t.Run("replaces via PUT when serial differs", func(t *testing.T) {
		var calls []recordedCall
		srv := serve("deadbeef", true, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 1 || calls[0].method != http.MethodPut || calls[0].contentType != "text/plain" {
			t.Fatalf("expected one PUT text/plain, got %+v", calls)
		}
	})

	t.Run("rejects garbage pem", func(t *testing.T) {
		var calls []recordedCall
		srv := serve("", false, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		if _, err := c.SyncSSLCertificate(context.Background(), "x.pem", []byte("not pem")); err == nil {
			t.Fatal("expected error for non-PEM input")
		}
	})
}
