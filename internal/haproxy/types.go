package haproxy

import (
	"crypto/sha256"
	"encoding/hex"
)

// Config is the internal representation pushed via the HAProxy Data Plane API.
type Config struct {
	Frontends []Frontend
	Backends  []Backend
}

// Backend models an HAProxy backend section.
type Backend struct {
	Name    string
	Mode    string
	Balance string
	Servers []Server
}

// Server models a single server line inside a backend.
type Server struct {
	Name    string
	Address string
	Port    int
	Check   bool
	SSL     bool
	Verify  string
}

// Frontend models an HAProxy frontend section.
type Frontend struct {
	Name           string
	Mode           string
	Binds          []Bind
	DefaultBackend string
	UseBackends    []UseBackendRule
}

// Bind models a bind line inside a frontend.
type Bind struct {
	Name           string
	Address        string
	Port           int
	SSL            bool
	SSLCertificate string
	Alpn           string
	Verify         string
}

// UseBackendRule models a use_backend directive.
type UseBackendRule struct {
	Name      string
	Condition string // "if" / "unless"
	CondTest  string // the condition expression
}

// HashConfig returns a stable SHA256 hash of raw haproxy.cfg content.
func HashConfig(cfg string) string {
	sum := sha256.Sum256([]byte(cfg))
	return hex.EncodeToString(sum[:])
}
