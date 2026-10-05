package metrics

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// writeTestCert generates a self-signed leaf expiring at notAfter and writes
// its PEM to dir, returning the file path.
func writeTestCert(t *testing.T, dir string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "client.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestObserveClientCertFile(t *testing.T) {
	notAfter := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	path := writeTestCert(t, t.TempDir(), notAfter)

	if err := ObserveClientCertFile(path); err != nil {
		t.Fatalf("ObserveClientCertFile: %v", err)
	}
	if got := testutil.ToFloat64(DataplaneClientCertExpiry); got != float64(notAfter.Unix()) {
		t.Errorf("client cert gauge = %v, want %v", got, float64(notAfter.Unix()))
	}
}

func TestObserveClientCertFileErrors(t *testing.T) {
	if err := ObserveClientCertFile(filepath.Join(t.TempDir(), "missing.crt")); err == nil {
		t.Error("expected error for missing file")
	}

	bad := filepath.Join(t.TempDir(), "bad.crt")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ObserveClientCertFile(bad); err == nil {
		t.Error("expected error for non-PEM file")
	}
}

// The watcher must re-read the file so a VSO rotation (in-place rewrite)
// updates the gauge without a restart.
func TestStartClientCertWatcherUpdatesOnFileChange(t *testing.T) {
	dir := t.TempDir()
	first := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	second := time.Now().Add(96 * time.Hour).Truncate(time.Second)
	path := writeTestCert(t, dir, first)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go StartClientCertWatcher(ctx, path, 20*time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for got := testutil.ToFloat64(DataplaneClientCertExpiry); got != float64(first.Unix()); {
		if time.Now().After(deadline) {
			t.Fatalf("gauge never reached first NotAfter: got %v want %v", got, float64(first.Unix()))
		}
		time.Sleep(10 * time.Millisecond)
		got = testutil.ToFloat64(DataplaneClientCertExpiry)
	}

	writeTestCert(t, dir, second)
	deadline = time.Now().Add(5 * time.Second)
	for got := testutil.ToFloat64(DataplaneClientCertExpiry); got != float64(second.Unix()); {
		if time.Now().After(deadline) {
			t.Fatalf("gauge did not track rotated file: got %v want %v", got, float64(second.Unix()))
		}
		time.Sleep(10 * time.Millisecond)
		got = testutil.ToFloat64(DataplaneClientCertExpiry)
	}

	// An unreadable file surfaces as 0 (expired) rather than the last
	// healthy-looking value.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for got := testutil.ToFloat64(DataplaneClientCertExpiry); got != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("gauge did not zero on unreadable file: got %v", got)
		}
		time.Sleep(10 * time.Millisecond)
		got = testutil.ToFloat64(DataplaneClientCertExpiry)
	}
}

// The insecure gauge must be scrapeable the moment the flag is set — it is
// the alertable surface for "TLS verification is off" outside Helm.
func TestDataplaneInsecureGauge(t *testing.T) {
	DataplaneInsecure.Set(1)
	if got := testutil.ToFloat64(DataplaneInsecure); got != 1 {
		t.Fatalf("dataplane_insecure = %v, want 1", got)
	}
	DataplaneInsecure.Set(0)
}
