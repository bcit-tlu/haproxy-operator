package config

import (
	"context"
	"errors"
	"testing"

	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
)

func TestValidate_EmptyConfig(t *testing.T) {
	// NewValidator requires a non-nil client, but Validate should reject
	// empty configs before making any API calls — and the rejection must be
	// the typed local rejection so Classify returns ConfigRejected.
	v := NewValidator(nil)
	err := v.Validate(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	if !errors.Is(err, haproxy.ErrLocalRejection) {
		t.Errorf("expected ErrLocalRejection, got %v", err)
	}
	if got := haproxy.Classify(err); got != haproxy.ClassConfigRejected {
		t.Errorf("Classify = %q, want %q", got, haproxy.ClassConfigRejected)
	}
}
