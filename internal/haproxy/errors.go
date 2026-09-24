package haproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrorClass buckets Dataplane API failures so the reconciler can decide
// whether the desired bytes are deterministically rejected (safe to suppress
// until the config changes) or transient (must be retried with backoff).
type ErrorClass string

const (
	// ClassConfigRejected is a deterministic configuration rejection — the
	// Dataplane API examined the payload and refused it (HTTP 400/422).
	// Retrying the same bytes cannot succeed.
	ClassConfigRejected ErrorClass = "ConfigRejected"
	// ClassAuth covers HTTP 401/403 — wrong or missing Basic Auth / client
	// certificate identity. Transient in the sense that credentials may be
	// rotated, but the same bytes must be retried once they are.
	ClassAuth ErrorClass = "AuthError"
	// ClassTLS covers TLS handshake/client-certificate failures detected
	// before any HTTP exchange (x509 verification, bad cert, etc.).
	ClassTLS ErrorClass = "TLSConnectionError"
	// ClassConnection covers DNS, TCP, and other transport failures where no
	// HTTP response was received.
	ClassConnection ErrorClass = "ConnectionError"
	// ClassConflict covers HTTP 409 — the Dataplane API refused a write that
	// raced another writer (e.g. a stale transaction version).
	ClassConflict ErrorClass = "ConflictError"
	// ClassRateLimited covers HTTP 429.
	ClassRateLimited ErrorClass = "RateLimited"
	// ClassServer covers HTTP 5xx — the Dataplane API itself is unhealthy.
	ClassServer ErrorClass = "DataplaneServerError"
	// ClassUnknown is anything not otherwise classified; treated as transient.
	ClassUnknown ErrorClass = "UnknownError"
)

// Transient reports whether the desired config bytes should be retried —
// everything except a deterministic ConfigRejected.
func (c ErrorClass) Transient() bool {
	return c != ClassConfigRejected
}

// StatusValue returns the Secret status-annotation value for the class.
func (c ErrorClass) StatusValue() string {
	return string(c)
}

// classifyHTTPStatus maps an HTTP status code to an ErrorClass.
func classifyHTTPStatus(code int) ErrorClass {
	switch {
	case code == http.StatusBadRequest || code == http.StatusUnprocessableEntity:
		return ClassConfigRejected
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return ClassAuth
	case code == http.StatusConflict:
		return ClassConflict
	case code == http.StatusTooManyRequests:
		return ClassRateLimited
	case code >= 500 && code < 600:
		return ClassServer
	default:
		return ClassUnknown
	}
}

// isTLSError reports whether err was raised by the TLS stack (certificate
// verification, handshake, or client-auth failures) rather than plain
// transport plumbing.
func isTLSError(err error) bool {
	var (
		tlsRecordErr   tls.RecordHeaderError
		certInvalidErr x509.CertificateInvalidError
		hostErr        x509.HostnameError
		unknownAuthErr x509.UnknownAuthorityError
		sysErr         x509.SystemRootsError
	)
	if errors.As(err, &tlsRecordErr) || errors.As(err, &certInvalidErr) ||
		errors.As(err, &hostErr) || errors.As(err, &unknownAuthErr) ||
		errors.As(err, &sysErr) {
		return true
	}
	// Handshake failures surface as *tls.AlertError (unexported) or as
	// opaque text on some Go versions — match the stable prefix.
	if strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:") {
		return true
	}
	return false
}

// ErrLocalRejection marks a deterministic rejection decided locally, before
// any bytes reach the Dataplane API (e.g. an empty configuration). Retrying
// the same payload cannot succeed — same semantics as an API-side 400/422.
var ErrLocalRejection = errors.New("configuration rejected locally")

// VersionCheckError wraps a failure of the configuration-version GET that
// precedes a raw-config POST. A non-2xx response there says nothing about the
// candidate configuration, so it must never classify as ConfigRejected —
// otherwise a transient API hiccup would suppress unsubmitted config bytes
// until they change.
type VersionCheckError struct{ Err error }

func (e *VersionCheckError) Error() string { return fmt.Sprintf("config version check: %v", e.Err) }
func (e *VersionCheckError) Unwrap() error { return e.Err }

// Classify assigns an ErrorClass to an error returned by the Dataplane
// client or its transport.
func Classify(err error) ErrorClass {
	if err == nil {
		return ""
	}

	if errors.Is(err, ErrLocalRejection) {
		return ClassConfigRejected
	}

	var vce *VersionCheckError
	if errors.As(err, &vce) {
		inner := Classify(vce.Err)
		if inner == ClassConfigRejected {
			// A 400/422 on the version read is an API-level fault, not a
			// verdict on the pending config — treat it as transient.
			return ClassUnknown
		}
		return inner
	}

	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return classifyHTTPStatus(apiErr.StatusCode)
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		if isTLSError(urlErr.Err) {
			return ClassTLS
		}
		if isTimeout(urlErr.Err) || isConnRefused(urlErr.Err) || isDNSError(urlErr.Err) {
			return ClassConnection
		}
	}

	if isTLSError(err) {
		return ClassTLS
	}
	if isTimeout(err) || isConnRefused(err) || isDNSError(err) {
		return ClassConnection
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return ClassConnection
	}

	return ClassUnknown
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func isConnRefused(err error) bool {
	return strings.Contains(err.Error(), "connection refused")
}

func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
