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
		time.Sleep(250 * time.Millisecond)
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

// ApplyConfiguration pushes structured configuration (backends, frontends).
func (c *Client) ApplyConfiguration(ctx context.Context, cfg *Config) error {
	if err := c.waitForReady(ctx, 10*time.Second); err != nil {
		return fmt.Errorf("dataplane api not ready: %w", err)
	}
	for _, be := range cfg.Backends {
		if err := c.applyBackend(ctx, &be); err != nil {
			return err
		}
	}
	for _, fe := range cfg.Frontends {
		if err := c.applyFrontend(ctx, &fe); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) applyBackend(ctx context.Context, be *Backend) error {
	exists, err := c.backendExists(ctx, be.Name)
	if err != nil {
		return err
	}
	data := map[string]any{
		"name": be.Name,
		"mode": be.Mode,
		"balance": map[string]any{
			"algorithm": firstNonEmpty(be.Balance, "roundrobin"),
		},
	}
	if exists {
		if err := c.doRequestVersioned(ctx, http.MethodPut, fmt.Sprintf("/services/haproxy/configuration/backends/%s", url.PathEscape(be.Name)), data, nil); err != nil {
			return fmt.Errorf("update backend %s: %w", be.Name, err)
		}
	} else {
		if err := c.doRequestVersioned(ctx, http.MethodPost, "/services/haproxy/configuration/backends", data, nil); err != nil {
			return fmt.Errorf("create backend %s: %w", be.Name, err)
		}
	}

	for _, srv := range be.Servers {
		if err := c.applyServer(ctx, be.Name, &srv); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) applyServer(ctx context.Context, backendName string, srv *Server) error {
	exists, err := c.serverExists(ctx, backendName, srv.Name)
	if err != nil {
		return err
	}

	data := map[string]any{
		"name":    srv.Name,
		"address": srv.Address,
		"port":    srv.Port,
	}
	if srv.Check {
		data["check"] = "enabled"
	}
	if srv.SSL {
		data["ssl"] = "enabled"
		if srv.Verify != "" {
			data["verify"] = srv.Verify
		}
	}

	base := fmt.Sprintf("/services/haproxy/configuration/backends/%s/servers", url.PathEscape(backendName))

	if exists {
		endpoint := fmt.Sprintf("%s/%s", base, url.PathEscape(srv.Name))
		if err := c.doRequestVersioned(ctx, http.MethodPut, endpoint, data, nil); err != nil {
			return fmt.Errorf("update server %s/%s: %w", backendName, srv.Name, err)
		}
		return nil
	}

	if err := c.doRequestVersioned(ctx, http.MethodPost, base, data, nil); err != nil {
		return fmt.Errorf("create server %s/%s: %w", backendName, srv.Name, err)
	}
	return nil
}

func (c *Client) applyFrontend(ctx context.Context, fe *Frontend) error {
	exists, err := c.frontendExists(ctx, fe.Name)
	if err != nil {
		return err
	}
	data := map[string]any{
		"name": fe.Name,
		"mode": fe.Mode,
	}
	if fe.DefaultBackend != "" {
		data["default_backend"] = fe.DefaultBackend
	}
	if exists {
		if err := c.doRequestVersioned(ctx, http.MethodPut, fmt.Sprintf("/services/haproxy/configuration/frontends/%s", url.PathEscape(fe.Name)), data, nil); err != nil {
			return fmt.Errorf("update frontend %s: %w", fe.Name, err)
		}
	} else {
		if err := c.doRequestVersioned(ctx, http.MethodPost, "/services/haproxy/configuration/frontends", data, nil); err != nil {
			return fmt.Errorf("create frontend %s: %w", fe.Name, err)
		}
	}

	for i := range fe.Binds {
		b := fe.Binds[i]
		b.Name = firstNonEmpty(b.Name, fmt.Sprintf("%s-bind-%d", fe.Name, i))
		if err := c.applyBind(ctx, fe.Name, &b); err != nil {
			return err
		}
	}

	for i := range fe.UseBackends {
		r := fe.UseBackends[i]
		if err := c.applyBackendSwitchRule(ctx, fe.Name, i, &r); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) applyBind(ctx context.Context, frontendName string, b *Bind) error {
	exists, err := c.bindExists(ctx, frontendName, b.Name)
	if err != nil {
		return err
	}

	data := map[string]any{
		"name":    b.Name,
		"address": b.Address,
		"port":    b.Port,
	}

	if b.SSL {
		data["ssl"] = true
		if b.SSLCertificate != "" {
			data["ssl_certificate"] = b.SSLCertificate
		}
		if b.Verify != "" {
			data["verify"] = b.Verify
		}
	}
	if b.Alpn != "" {
		data["alpn"] = b.Alpn
	}

	base := fmt.Sprintf("/services/haproxy/configuration/frontends/%s/binds", url.PathEscape(frontendName))

	if exists {
		endpoint := fmt.Sprintf("%s/%s", base, url.PathEscape(b.Name))
		if err := c.doRequestVersioned(ctx, http.MethodPut, endpoint, data, nil); err != nil {
			return fmt.Errorf("update bind %s/%s: %w", frontendName, b.Name, err)
		}
		return nil
	}

	if err := c.doRequestVersioned(ctx, http.MethodPost, base, data, nil); err != nil {
		return fmt.Errorf("create bind %s/%s: %w", frontendName, b.Name, err)
	}
	return nil
}

func (c *Client) bindExists(ctx context.Context, frontendName, bindName string) (bool, error) {
	var out map[string]any
	endpoint := fmt.Sprintf(
		"/services/haproxy/configuration/frontends/%s/binds/%s",
		url.PathEscape(frontendName),
		url.PathEscape(bindName),
	)
	err := c.doRequest(ctx, http.MethodGet, endpoint, nil, &out)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *Client) applyBackendSwitchRule(ctx context.Context, frontendName string, index int, r *UseBackendRule) error {
	data := map[string]any{
		"index": index,
		"name":  r.Name,
	}
	if r.Condition != "" {
		data["cond"] = r.Condition
	}
	if r.CondTest != "" {
		data["cond_test"] = r.CondTest
	}

	fe := url.PathEscape(frontendName)
	nestedPut := fmt.Sprintf("/services/haproxy/configuration/frontends/%s/backend_switching_rules/%d", fe, index)
	nestedPost := fmt.Sprintf("/services/haproxy/configuration/frontends/%s/backend_switching_rules", fe)
	if err := c.doRequestVersioned(ctx, http.MethodPut, nestedPut, data, nil); err != nil {
		if err2 := c.doRequestVersioned(ctx, http.MethodPost, nestedPost, data, nil); err2 == nil {
			return nil
		}
		legacyPut := fmt.Sprintf("/services/haproxy/configuration/backend_switching_rules?frontend=%s&index=%d", url.QueryEscape(frontendName), index)
		if err3 := c.doRequestVersioned(ctx, http.MethodPut, legacyPut, data, nil); err3 != nil {
			legacyPost := fmt.Sprintf("/services/haproxy/configuration/backend_switching_rules?frontend=%s", url.QueryEscape(frontendName))
			if err4 := c.doRequestVersioned(ctx, http.MethodPost, legacyPost, data, nil); err4 != nil {
				return fmt.Errorf("apply backend_switching_rule %s[%d]: %w", frontendName, index, err4)
			}
		}
	}
	return nil
}

func (c *Client) getConfigVersion(ctx context.Context) (int, error) {
	var n int
	if err := c.doRequest(ctx, http.MethodGet, "/services/haproxy/configuration/version", nil, &n); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *Client) backendExists(ctx context.Context, name string) (bool, error) {
	var out map[string]any
	err := c.doRequest(ctx, http.MethodGet, fmt.Sprintf("/services/haproxy/configuration/backends/%s", url.PathEscape(name)), nil, &out)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *Client) serverExists(ctx context.Context, backendName, serverName string) (bool, error) {
	var out map[string]any
	endpoint := fmt.Sprintf(
		"/services/haproxy/configuration/backends/%s/servers/%s",
		url.PathEscape(backendName),
		url.PathEscape(serverName),
	)
	err := c.doRequest(ctx, http.MethodGet, endpoint, nil, &out)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *Client) frontendExists(ctx context.Context, name string) (bool, error) {
	var out map[string]any
	err := c.doRequest(ctx, http.MethodGet, fmt.Sprintf("/services/haproxy/configuration/frontends/%s", url.PathEscape(name)), nil, &out)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// --- HTTP plumbing ---

func (c *Client) doRequestVersioned(ctx context.Context, method, p string, body any, result any) error {
	ver, err := c.getConfigVersion(ctx)
	if err != nil {
		return err
	}
	withVersion := addOrReplaceQuery(p, "version", fmt.Sprintf("%d", ver))
	return c.doRequest(ctx, method, withVersion, body, result)
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
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
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
		b, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Message: string(b)}
	}

	if result != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

// APIError represents an error response from the Data Plane API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("dataplane api error (status %d): %s", e.StatusCode, e.Message)
}

func isNotFound(err error) bool {
	if e, ok := err.(*APIError); ok {
		return e.StatusCode == http.StatusNotFound
	}
	return false
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

func firstNonEmpty(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
