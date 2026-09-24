package haproxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestClassifyHTTPStatus(t *testing.T) {
	cases := []struct {
		code int
		want ErrorClass
	}{
		{http.StatusBadRequest, ClassConfigRejected},
		{http.StatusUnprocessableEntity, ClassConfigRejected},
		{http.StatusUnauthorized, ClassAuth},
		{http.StatusForbidden, ClassAuth},
		{http.StatusConflict, ClassConflict},
		{http.StatusTooManyRequests, ClassRateLimited},
		{http.StatusInternalServerError, ClassServer},
		{http.StatusBadGateway, ClassServer},
		{http.StatusServiceUnavailable, ClassServer},
		{http.StatusNotFound, ClassUnknown},
		{http.StatusMethodNotAllowed, ClassUnknown},
	}
	for _, tc := range cases {
		if got := classifyHTTPStatus(tc.code); got != tc.want {
			t.Errorf("classifyHTTPStatus(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestClassify(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if got := Classify(nil); got != "" {
			t.Errorf("Classify(nil) = %q, want empty", got)
		}
	})

	t.Run("APIError 400 rejected", func(t *testing.T) {
		err := &APIError{StatusCode: http.StatusBadRequest, Message: "bad config"}
		if got := Classify(err); got != ClassConfigRejected {
			t.Errorf("got %q, want %q", got, ClassConfigRejected)
		}
	})

	t.Run("APIError 401 auth", func(t *testing.T) {
		err := fmt.Errorf("wrap: %w", &APIError{StatusCode: http.StatusUnauthorized})
		if got := Classify(err); got != ClassAuth {
			t.Errorf("got %q, want %q", got, ClassAuth)
		}
	})

	t.Run("APIError 5xx server", func(t *testing.T) {
		err := &APIError{StatusCode: http.StatusServiceUnavailable}
		if got := Classify(err); got != ClassServer {
			t.Errorf("got %q, want %q", got, ClassServer)
		}
	})

	t.Run("url.Error TLS", func(t *testing.T) {
		err := &url.Error{Op: "Get", URL: "https://x", Err: x509.UnknownAuthorityError{}}
		if got := Classify(err); got != ClassTLS {
			t.Errorf("got %q, want %q", got, ClassTLS)
		}
	})

	t.Run("url.Error hostname", func(t *testing.T) {
		err := &url.Error{Op: "Get", URL: "https://x", Err: x509.HostnameError{Host: "gate-01.ltc.bcit.ca"}}
		if got := Classify(err); got != ClassTLS {
			t.Errorf("got %q, want %q", got, ClassTLS)
		}
	})

	t.Run("url.Error connection refused", func(t *testing.T) {
		err := &url.Error{Op: "Get", URL: "https://x", Err: errors.New("dial tcp: connection refused")}
		if got := Classify(err); got != ClassConnection {
			t.Errorf("got %q, want %q", got, ClassConnection)
		}
	})

	t.Run("url.Error DNS", func(t *testing.T) {
		err := &url.Error{Op: "Get", URL: "https://x", Err: &net.DNSError{IsNotFound: true}}
		if got := Classify(err); got != ClassConnection {
			t.Errorf("got %q, want %q", got, ClassConnection)
		}
	})

	t.Run("context deadline", func(t *testing.T) {
		if got := Classify(context.DeadlineExceeded); got != ClassConnection {
			t.Errorf("got %q, want %q", got, ClassConnection)
		}
	})

	t.Run("plain error unknown", func(t *testing.T) {
		if got := Classify(errors.New("something odd")); got != ClassUnknown {
			t.Errorf("got %q, want %q", got, ClassUnknown)
		}
	})
}

func TestErrorClassTransient(t *testing.T) {
	if ClassConfigRejected.Transient() {
		t.Error("ConfigRejected must not be transient")
	}
	for _, c := range []ErrorClass{ClassAuth, ClassTLS, ClassConnection, ClassConflict, ClassRateLimited, ClassServer, ClassUnknown} {
		if !c.Transient() {
			t.Errorf("%s should be transient", c)
		}
	}
}

func TestNewAPIErrorBoundsBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(&infiniteReader{}),
	}
	err := newAPIError(resp)
	if len(err.Message) > maxAPIErrorBody {
		t.Errorf("message length %d exceeds bound %d", len(err.Message), maxAPIErrorBody)
	}
}

type infiniteReader struct{}

func (r *infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
