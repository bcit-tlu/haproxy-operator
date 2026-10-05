package metrics

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ObserveDataplaneServerCert records the NotAfter of the Dataplane API server
// leaf presented on the latest TLS handshake, keyed by gateway hostname.
// Wired via haproxy.ServerCertObserver in main.
func ObserveDataplaneServerCert(gateway string, notAfter time.Time) {
	DataplaneServerCertExpiry.WithLabelValues(gateway).Set(float64(notAfter.Unix()))
}

// ObserveDataplaneClientCert records the NotAfter of the operator's Dataplane
// client leaf parsed from the mounted certificate file.
func ObserveDataplaneClientCert(notAfter time.Time) {
	DataplaneClientCertExpiry.Set(float64(notAfter.Unix()))
}

// certFileNotAfter returns the NotAfter of the first CERTIFICATE block in the
// PEM file at path.
func certFileNotAfter(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	for rest := data; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			return time.Time{}, fmt.Errorf("no CERTIFICATE block found in %s", path)
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse certificate in %s: %w", path, err)
		}
		return cert.NotAfter, nil
	}
}

// ObserveClientCertFile parses the PEM certificate at path and records its
// NotAfter on the client-cert gauge.
func ObserveClientCertFile(path string) error {
	notAfter, err := certFileNotAfter(path)
	if err != nil {
		return err
	}
	ObserveDataplaneClientCert(notAfter)
	return nil
}

// StartClientCertWatcher observes the client certificate file immediately and
// then on every interval until ctx is done — VSO rotates the mounted file in
// place, so periodic re-reads keep the gauge on the material currently on
// disk. Intended to run as a goroutine.
func StartClientCertWatcher(ctx context.Context, path string, interval time.Duration) {
	logger := log.FromContext(ctx)
	if err := ObserveClientCertFile(path); err != nil {
		logger.Error(err, "observe dataplane client certificate", "path", path)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ObserveClientCertFile(path); err != nil {
				logger.Error(err, "observe dataplane client certificate", "path", path)
			}
		}
	}
}
