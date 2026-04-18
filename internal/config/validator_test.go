package config

import (
	"context"
	"testing"
)

func TestValidate_EmptyConfig(t *testing.T) {
	// NewValidator requires a non-nil client, but Validate should reject
	// empty configs before making any API calls.
	v := NewValidator(nil)
	err := v.Validate(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	if err.Error() != "empty configuration" {
		t.Errorf("unexpected error: %v", err)
	}
}
