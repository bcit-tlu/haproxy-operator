package config

import (
	"context"
	"fmt"

	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
)

// Validator pre-validates HAProxy configuration before applying it.
type Validator struct {
	client *haproxy.Client
}

// NewValidator creates a Validator backed by the Dataplane API.
func NewValidator(client *haproxy.Client) *Validator {
	return &Validator{client: client}
}

// Validate checks raw haproxy.cfg content using the Dataplane API
// only_validate=true endpoint. Returns nil if valid.
func (v *Validator) Validate(ctx context.Context, raw string) error {
	if raw == "" {
		// Deterministic local rejection: unchanged bytes can never validate,
		// so Classify must see ConfigRejected rather than an opaque error that
		// would retry forever.
		return fmt.Errorf("empty configuration (%w)", haproxy.ErrLocalRejection)
	}
	return v.client.ValidateRawConfiguration(ctx, raw)
}
