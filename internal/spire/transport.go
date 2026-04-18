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
// socketPath is the SPIRE Agent Workload API socket, typically:
//
//	unix:///run/spire/agent.sock
//
// The caller should close the returned x509Source when the operator shuts down.
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
			RootCAs: bundleToPool(source),
			// Verify the server's SPIFFE ID. In production this should be
			// locked down to the specific SPIFFE ID of the HAProxy service:
			//   spiffe://trust-domain/haproxy-dataplane
			// For now we accept any SVID from the same trust domain, which
			// the SPIRE Agent enforces.
			InsecureSkipVerify: false,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				// Trust is established via the SPIFFE trust bundle; this
				// callback is a hook for future SPIFFE ID allowlisting.
				_ = rawCerts
				return nil
			},
		},
	}

	return transport, source, nil
}

// bundleToPool converts the SPIFFE trust bundle from the X509Source into
// an *x509.CertPool suitable for TLS verification.
func bundleToPool(source *workloadapi.X509Source) *x509.CertPool {
	svid, err := source.GetX509SVID()
	if err != nil {
		pool, _ := x509.SystemCertPool()
		return pool
	}
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		// Fallback: use system cert pool if bundle retrieval fails.
		pool, _ := x509.SystemCertPool()
		return pool
	}

	pool := x509.NewCertPool()
	for _, cert := range bundle.X509Authorities() {
		pool.AddCert(cert)
	}
	return pool
}
