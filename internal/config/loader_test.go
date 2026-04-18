package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	t.Run("loads existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "haproxy.cfg")
		content := []byte("global\n  daemon\n")
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatal(err)
		}

		b, err := LoadFromFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(b) != string(content) {
			t.Errorf("got %q, want %q", string(b), string(content))
		}
	})

	t.Run("returns error for empty path", func(t *testing.T) {
		_, err := LoadFromFile("")
		if err == nil {
			t.Fatal("expected error for empty path")
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := LoadFromFile("/nonexistent/haproxy.cfg")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestHashBytes(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		data := []byte("global\n  daemon\n")
		h1 := HashBytes(data)
		h2 := HashBytes(data)
		if h1 != h2 {
			t.Errorf("hashes differ: %s != %s", h1, h2)
		}
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		h1 := HashBytes([]byte("config-a"))
		h2 := HashBytes([]byte("config-b"))
		if h1 == h2 {
			t.Error("expected different hashes for different inputs")
		}
	})

	t.Run("returns 64 char hex string", func(t *testing.T) {
		h := HashBytes([]byte("test"))
		if len(h) != 64 {
			t.Errorf("expected 64 char hash, got %d", len(h))
		}
	})

	t.Run("empty input is valid", func(t *testing.T) {
		h := HashBytes([]byte{})
		if h == "" {
			t.Error("expected non-empty hash for empty input")
		}
	})
}
