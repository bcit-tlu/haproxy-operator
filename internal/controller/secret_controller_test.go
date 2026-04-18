package controller

import (
	"testing"
)

func TestStripOperatorAnnotations(t *testing.T) {
	t.Run("removes operator annotations", func(t *testing.T) {
		in := map[string]string{
			"haproxy.operator/last-applied-hash": "abc123",
			"haproxy.operator/status":            "Applied",
			"app.kubernetes.io/name":             "haproxy-operator",
		}
		out := stripOperatorAnnotations(in)
		if len(out) != 1 {
			t.Errorf("expected 1 annotation, got %d", len(out))
		}
		if out["app.kubernetes.io/name"] != "haproxy-operator" {
			t.Errorf("unexpected value: %v", out)
		}
	})

	t.Run("returns nil for empty input", func(t *testing.T) {
		out := stripOperatorAnnotations(nil)
		if out != nil {
			t.Errorf("expected nil, got %v", out)
		}
	})

	t.Run("returns nil when all annotations are operator-owned", func(t *testing.T) {
		in := map[string]string{
			"haproxy.operator/status": "Applied",
		}
		out := stripOperatorAnnotations(in)
		if out != nil {
			t.Errorf("expected nil, got %v", out)
		}
	})
}

func TestIsRelevantUpdate(t *testing.T) {
	t.Run("nil old returns true", func(t *testing.T) {
		if !isRelevantUpdate(nil, nil) {
			t.Error("expected true for nil inputs")
		}
	})
}
