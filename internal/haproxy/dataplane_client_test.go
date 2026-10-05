package haproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bcit-tlu/haproxy-operator/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// The server-cert expiry gauge must equal the NotAfter of the leaf the fake
// TLS server presents on the handshake (bcit-tlu/haproxy-operator#41).
func TestServerCertExpiryGauge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "1")
	}))
	defer srv.Close()

	old := ServerCertObserver
	ServerCertObserver = metrics.ObserveDataplaneServerCert
	defer func() { ServerCertObserver = old }()

	c, err := NewClient(APIConfig{BaseURL: srv.URL, Insecure: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}

	gateway := srv.Listener.Addr().(*net.TCPAddr).IP.String()
	want := float64(srv.Certificate().NotAfter.Unix())
	if got := testutil.ToFloat64(metrics.DataplaneServerCertExpiry.WithLabelValues(gateway)); got != want {
		t.Errorf("server cert gauge = %v, want %v", got, want)
	}
}

// The server-CA file must verify a gateway leaf on its own — a PEM holding
// ONLY the issuing CA (what the vaultPKI source renders from cert/ca), with
// no client-chain material (bcit-tlu/haproxy-operator#39).
func TestServerIssuerOnlyCAFile(t *testing.T) {
	// Issuing CA + a gateway leaf signed by it.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "pki-haproxy Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "gw.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "1")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	defer srv.Close()

	// CA file holds ONLY the issuer PEM — no leaf, no chain, no client CA.
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, _ := writeTestCertKeyPair(t, dir, 1)

	c, err := NewClient(APIConfig{
		BaseURL:        srv.URL,
		CACertPath:     caFile,
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping with server-issuer CA: %v", err)
	}

	// Rotate the file to a different CA (e.g. a dedicated client issuer
	// under vault#69): the SAME cached client must re-read it on the next
	// handshake — a static RootCAs pool would keep trusting the old issuer
	// (Devin Review #47). CloseClientConnections forces a fresh handshake.
	srv.CloseClientConnections()
	wrongCA := testCertPEM(t, "client issuer")
	if err := os.WriteFile(caFile, wrongCA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected ping to fail after the CA file rotated to the wrong issuer")
	}

	// Restoring the right CA verifies the cached client recovers too.
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.CloseClientConnections()
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping after CA restore: %v", err)
	}
}

// writeTestCertKeyPair generates a self-signed cert+key under dir and returns
// (certPath, keyPath, serial) — used for client-cert rotation tests.
func writeTestCertKeyPair(t *testing.T, dir string, serial int64) (string, string, *big.Int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialNo := big.NewInt(serial)
	tmpl := &x509.Certificate{
		SerialNumber:          serialNo,
		Subject:               pkix.Name{CommonName: "client.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, serialNo
}

// The client must re-read the mounted cert pair per handshake so a VSO
// in-place rotation is picked up by the cached client (Devin Review #45).
func TestClientCertReloadedOnHandshake(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, serial1 := writeTestCertKeyPair(t, dir, 1)

	c, err := NewClient(APIConfig{
		BaseURL:        "https://haproxy:5555/v3",
		Insecure:       true,
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	getCert := c.httpClient.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate
	if getCert == nil {
		t.Fatal("expected GetClientCertificate to be set")
	}

	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("first GetClientCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Cmp(serial1) != 0 {
		t.Fatalf("first cert serial = %v, want %v", leaf.SerialNumber, serial1)
	}

	_, _, serial2 := writeTestCertKeyPair(t, dir, 2)
	got, err = getCert(nil)
	if err != nil {
		t.Fatalf("second GetClientCertificate: %v", err)
	}
	leaf, err = x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Cmp(serial2) != 0 {
		t.Fatalf("rotated cert serial = %v, want %v", leaf.SerialNumber, serial2)
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
	serve := func(remote map[string]any, remoteExists bool, calls *[]recordedCall) *httptest.Server {
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
				json.NewEncoder(w).Encode(remote)
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
		srv := serve(nil, false, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes, true)
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
		srv := serve(map[string]any{"serial": wantSerial}, true, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes, true)
		if err != nil || changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 0 {
			t.Errorf("expected no writes, got %+v", calls)
		}
	})

	t.Run("skips when serial and size match", func(t *testing.T) {
		var calls []recordedCall
		srv := serve(map[string]any{"serial": wantSerial, "size": len(pemBytes)}, true, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes, true)
		if err != nil || changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 0 {
			t.Errorf("expected no writes, got %+v", calls)
		}
	})

	t.Run("replaces via PUT when serial matches but size differs", func(t *testing.T) {
		var calls []recordedCall
		srv := serve(map[string]any{"serial": wantSerial, "size": len(pemBytes) + 1}, true, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes, true)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 1 || calls[0].method != http.MethodPut || calls[0].contentType != "text/plain" {
			t.Fatalf("expected one PUT text/plain, got %+v", calls)
		}
	})

	t.Run("replaces via PUT when remote matches but bundle is new", func(t *testing.T) {
		// Same-length chain swap: remote metadata is indistinguishable,
		// so the last-synced hash is the only change signal.
		var calls []recordedCall
		srv := serve(map[string]any{"serial": wantSerial, "size": len(pemBytes)}, true, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes, false)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 1 || calls[0].method != http.MethodPut || calls[0].contentType != "text/plain" {
			t.Fatalf("expected one PUT text/plain, got %+v", calls)
		}
	})

	t.Run("replaces via PUT when serial differs", func(t *testing.T) {
		var calls []recordedCall
		srv := serve(map[string]any{"serial": "deadbeef", "size": len(pemBytes)}, true, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		changed, err := c.SyncSSLCertificate(context.Background(), "star.pem", pemBytes, true)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if len(calls) != 1 || calls[0].method != http.MethodPut || calls[0].contentType != "text/plain" {
			t.Fatalf("expected one PUT text/plain, got %+v", calls)
		}
	})

	t.Run("rejects garbage pem", func(t *testing.T) {
		var calls []recordedCall
		srv := serve(nil, false, &calls)
		defer srv.Close()
		c, _ := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
		if _, err := c.SyncSSLCertificate(context.Background(), "x.pem", []byte("not pem"), false); err == nil {
			t.Fatal("expected error for non-PEM input")
		}
	})
}

func TestGetRawConfiguration(t *testing.T) {
	const body = "global\n  daemon\n\ndefaults\n  mode http\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/services/haproxy/configuration/raw" || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, body)
	}))
	defer srv.Close()

	c, err := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.GetRawConfiguration(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != body {
		t.Errorf("raw = %q, want %q", raw, body)
	}
}

func TestGetRawConfigurationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c, err := NewClient(APIConfig{BaseURL: srv.URL + "/v3"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetRawConfiguration(context.Background()); err == nil {
		t.Fatal("expected error on non-2xx response, got nil")
	}
}
