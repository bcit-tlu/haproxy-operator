package haproxy

import "testing"

func TestHashConfig(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		cfg := "global\n  daemon\n"
		h1 := HashConfig(cfg)
		h2 := HashConfig(cfg)
		if h1 != h2 {
			t.Errorf("hashes differ: %s != %s", h1, h2)
		}
	})

	t.Run("different configs different hashes", func(t *testing.T) {
		h1 := HashConfig("config-a")
		h2 := HashConfig("config-b")
		if h1 == h2 {
			t.Error("expected different hashes")
		}
	})

	t.Run("returns 64 char hex", func(t *testing.T) {
		h := HashConfig("test")
		if len(h) != 64 {
			t.Errorf("expected 64 chars, got %d", len(h))
		}
	})
}
