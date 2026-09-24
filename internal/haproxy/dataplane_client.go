package haproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// APIConfig holds HAProxy Dataplane API connection details.
type APIConfig struct {
	BaseURL        string // e.g. https://haproxy:5555/v3
	Insecure       bool   // skip TLS verification (not recommended)
	CACertPath     string // path to CA bundle for server verification
	ClientCertPath string // path to client certificate (mTLS)
	ClientKeyPath  string // path to client private key (mTLS)
	Username       string // basic auth username (optional)
	Password       string // basic auth password (optional)
}

// Client wraps HTTP communication with the HAProxy Data Plane API.
type Client struct {
	config     APIConfig
	httpClient *http.Client
	baseURL    *url.URL
}

// NewClient builds a Data Plane API client. When the base URL uses https,
// mTLS paths (CA, cert, key) are required unless Insecure is set.
func NewClient(cfg APIConfig) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("dataplane url must use http or https scheme, got %q", u.Scheme)
	}

	requiresTLS := u.Scheme == "https"
	if requiresTLS && !cfg.Insecure {
		if cfg.CACertPath == "" || cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" {
			return nil, fmt.Errorf("mTLS is required for https dataplane url; set CA, client cert, and client key paths")
		}
	}

	useTLS := requiresTLS || cfg.CACertPath != "" || cfg.ClientCertPath != "" || cfg.ClientKeyPath != "" || cfg.Insecure
	var transport http.RoundTripper = http.DefaultTransport

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // user opt-in
		}

		if cfg.CACertPath != "" {
			caPEM, err := os.ReadFile(cfg.CACertPath)
			if err != nil {
				return nil, fmt.Errorf("read dataplane CA: %w", err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("append dataplane CA: failed to parse PEM")
			}
			tlsConfig.RootCAs = caPool
		}

		if cfg.ClientCertPath != "" || cfg.ClientKeyPath != "" {
			cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
			if err != nil {
				return nil, fmt.Errorf("load dataplane client cert/key: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return &Client{
		config:  cfg,
		baseURL: u,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

// NewClientWithTransport builds a client with a caller-supplied transport.
// This is used by the SPIRE integration to supply an x509source-backed transport.
func NewClientWithTransport(cfg APIConfig, transport http.RoundTripper) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		config:  cfg,
		baseURL: u,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

// waitForReady polls the Data Plane API until it responds (or times out).
func (c *Client) waitForReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		_, err := c.getConfigVersion(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dataplane api not ready")
	}
	return lastErr
}

// ApplyRawConfiguration validates then pushes raw haproxy.cfg content.
func (c *Client) ApplyRawConfiguration(ctx context.Context, raw string) error {
	if err := c.waitForReady(ctx, 10*time.Second); err != nil {
		return fmt.Errorf("dataplane api not ready: %w", err)
	}
	if err := c.ValidateRawConfiguration(ctx, raw); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return c.applyRaw(ctx, raw)
}

// ApplyRawConfigurationValidated pushes raw haproxy.cfg content that has
// already been validated by the caller. This avoids a redundant validation
// round-trip when the reconciler has already called ValidateRawConfiguration.
func (c *Client) ApplyRawConfigurationValidated(ctx context.Context, raw string) error {
	if err := c.waitForReady(ctx, 10*time.Second); err != nil {
		return fmt.Errorf("dataplane api not ready: %w", err)
	}
	return c.applyRaw(ctx, raw)
}

func (c *Client) applyRaw(ctx context.Context, raw string) error {
	ver, err := c.getConfigVersion(ctx)
	if err != nil {
		return err
	}
	endpoint := addOrReplaceQuery("/services/haproxy/configuration/raw", "version", fmt.Sprintf("%d", ver))
	return c.doRequestPlain(ctx, http.MethodPost, endpoint, raw, nil)
}

// ValidateRawConfiguration validates raw haproxy.cfg via the Dataplane API
// only_validate endpoint without applying it.
func (c *Client) ValidateRawConfiguration(ctx context.Context, raw string) error {
	ver, err := c.getConfigVersion(ctx)
	if err != nil {
		return err
	}
	endpoint := addOrReplaceQuery("/services/haproxy/configuration/raw", "version", fmt.Sprintf("%d", ver))
	endpoint = addOrReplaceQuery(endpoint, "only_validate", "true")
	return c.doRequestPlain(ctx, http.MethodPost, endpoint, raw, nil)
}

func (c *Client) getConfigVersion(ctx context.Context) (int, error) {
	var n int
	if err := c.doRequest(ctx, http.MethodGet, "/services/haproxy/configuration/version", nil, &n); err != nil {
		return 0, err
	}
	return n, nil
}

// --- HTTP plumbing ---

// Ping performs a lightweight authenticated probe (configuration version)
// without mutating anything — used by the readiness check to prove the
// credentials and endpoint are working before the pod is marked ready.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.getConfigVersion(ctx)
	return err
}

// Info returns the running HAProxy version string reported by the Dataplane
// API. A safe read used for connectivity verification and logging.
func (c *Client) Info(ctx context.Context) (string, error) {
	var out map[string]any
	if err := c.doRequest(ctx, http.MethodGet, "/services/haproxy/info", nil, &out); err != nil {
		return "", err
	}
	if v, ok := out["version"].(string); ok {
		return v, nil
	}
	return "", nil
}

func (c *Client) doRequest(ctx context.Context, method, p string, body any, result any) error {
	ref := *c.baseURL
	ref.Path = path.Join(strings.TrimSuffix(c.baseURL.Path, "/"), strings.TrimPrefix(p, "/"))
	ref.RawQuery = ""
	if strings.Contains(p, "?") {
		parts := strings.SplitN(p, "?", 2)
		ref.Path = path.Join(strings.TrimSuffix(c.baseURL.Path, "/"), strings.TrimPrefix(parts[0], "/"))
		ref.RawQuery = parts[1]
	}

	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, ref.String(), r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.config.Username != "" {
		req.SetBasicAuth(c.config.Username, c.config.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(resp)
	}

	if result != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func (c *Client) doRequestPlain(ctx context.Context, method, p string, body string, result any) error {
	ref := *c.baseURL
	ref.Path = path.Join(strings.TrimSuffix(c.baseURL.Path, "/"), strings.TrimPrefix(p, "/"))
	ref.RawQuery = ""
	if strings.Contains(p, "?") {
		parts := strings.SplitN(p, "?", 2)
		ref.Path = path.Join(strings.TrimSuffix(c.baseURL.Path, "/"), strings.TrimPrefix(parts[0], "/"))
		ref.RawQuery = parts[1]
	}

	var r io.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	}

	req, err := http.NewRequestWithContext(ctx, method, ref.String(), r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	if c.config.Username != "" {
		req.SetBasicAuth(c.config.Username, c.config.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(resp)
	}

	if result != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

// APIError represents an error response from the Data Plane API. Message is
// bounded to maxAPIErrorBody at capture time so it is always safe to surface
// in Events/annotations.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("dataplane api error (status %d): %s", e.StatusCode, e.Message)
}

// maxAPIErrorBody caps how much of an error response body is retained.
// Dataplane can echo the submitted haproxy.cfg in validation failures; an
// unbounded capture would flood Events, annotations, and logs.
const maxAPIErrorBody = 4096

// newAPIError builds an APIError from an HTTP response, bounding the body.
func newAPIError(resp *http.Response) *APIError {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBody))
	return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
}

func addOrReplaceQuery(p, key, value string) string {
	base := p
	q := ""
	if strings.Contains(p, "?") {
		parts := strings.SplitN(p, "?", 2)
		base, q = parts[0], parts[1]
	}
	vals, _ := url.ParseQuery(q)
	vals.Set(key, value)
	return base + "?" + vals.Encode()
}
