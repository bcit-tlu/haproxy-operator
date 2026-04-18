// Package spire provides SPIFFE/SPIRE Workload API integration for automatic
// mTLS between the operator and the HAProxy Dataplane API.
//
// When SPIRE is enabled, the operator obtains an X.509 SVID from the local
// SPIRE Agent via the Workload API and uses it as the client certificate for
// Dataplane API requests. Certificates are automatically rotated by the
// go-spiffe library.
//
// The HAProxy host must also run a SPIRE Agent that provisions an SVID for
// the dataplaneapi process. Both SVIDs are issued under the same SPIFFE trust
// domain, establishing mutual authentication without manual certificate
// distribution.
//
// Architecture:
//
//	┌─────────────────┐  Workload API   ┌─────────────────┐
//	│  SPIRE Agent    │◄───────────────│  Operator Pod    │
//	│  (K8s node)     │   X.509 SVID   │  (this code)     │
//	└─────────────────┘                 └────────┬─────────┘
//	                                             │ mTLS (SVIDs)
//	┌─────────────────┐  Workload API   ┌────────▼─────────┐
//	│  SPIRE Agent    │◄───────────────│  HAProxy LB       │
//	│  (LB host)      │   X.509 SVID   │  (Dataplane API)  │
//	└─────────────────┘                 └──────────────────┘
package spire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// TLSTransport returns an http.RoundTripper that uses SPIFFE X.509 SVIDs
// from the Workload API for mTLS. The returned transport automatically
// rotates certificates when the SPIRE Agent issues new SVIDs.
//
// Both client certificates (via GetClientCertificate) and trust bundle
// verification (via VerifyPeerCertificate) are resolved dynamically on
// each TLS handshake, so CA rotation is handled correctly.
//
// socketPath is the SPIRE Agent Workload API socket, typically:
//
//	unix:///run/spire/agent.sock
//
// The caller must close the returned X509Source when the operator shuts down.
func TLSTransport(ctx context.Context, socketPath string) (http.RoundTripper, *workloadapi.X509Source, error) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(
		workloadapi.WithAddr(socketPath),
	))
	if err != nil {
		return nil, nil, fmt.Errorf("create SPIRE x509 source: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				svid, err := source.GetX509SVID()
				if err != nil {
					return nil, fmt.Errorf("get X.509 SVID: %w", err)
				}
				cert := tls.Certificate{
					Certificate: make([][]byte, len(svid.Certificates)),
					PrivateKey:  svid.PrivateKey,
				}
				for i, c := range svid.Certificates {
					cert.Certificate[i] = c.Raw
				}
				return &cert, nil
			},
			// Skip the standard RootCAs verification — we handle it
			// dynamically in VerifyPeerCertificate below so that CA
			// rotation is picked up without restarting the operator.
			InsecureSkipVerify: true, //nolint:gosec // verified in VerifyPeerCertificate
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return verifyServerCert(source, rawCerts)
			},
		},
	}

	return transport, source, nil
}

// verifyServerCert dynamically verifies the server certificate against the
// current SPIFFE trust bundle from the X509Source. This ensures that trust
// bundle rotations are picked up on every TLS handshake.
func verifyServerCert(source *workloadapi.X509Source, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("server presented no certificates")
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("get SVID for trust domain: %w", err)
	}

	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return fmt.Errorf("get trust bundle: %w", err)
	}

	pool := x509.NewCertPool()
	for _, ca := range bundle.X509Authorities() {
		pool.AddCert(ca)
	}

	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse server leaf certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		intermediates.AddCert(cert)
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
	})
	if err != nil {
		return fmt.Errorf("server certificate verification failed: %w", err)
	}

	return nil
}
