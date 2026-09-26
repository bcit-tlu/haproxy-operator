package local

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
)

func TestFileHash(t *testing.T) {
	// fileHash delegates to config.LoadFromFile + config.HashBytes;
	// verify it returns an error for a non-existent file.
	_, err := fileHash("/tmp/nonexistent-haproxy-operator-test-file")
	if err == nil {
		t.Error("fileHash: expected error for nonexistent file, got nil")
	}
}

func captureLogger(lines *[]string) logr.Logger {
	return funcr.New(func(prefix, args string) {
		*lines = append(*lines, args)
	}, funcr.Options{})
}

func TestAddWatches(t *testing.T) {
	t.Run("file and directory both watched", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "haproxy.cfg")
		if err := os.WriteFile(cfg, []byte("global\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()

		var lines []string
		r := &Runner{CfgPath: cfg}
		if err := r.addWatches(w, captureLogger(&lines)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(lines) != 0 {
			t.Errorf("expected no log output, got %v", lines)
		}
	})

	t.Run("missing file falls back to directory watch and logs", func(t *testing.T) {
		dir := t.TempDir()
		w, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()

		var lines []string
		r := &Runner{CfgPath: filepath.Join(dir, "missing.cfg")}
		if err := r.addWatches(w, captureLogger(&lines)); err != nil {
			t.Fatalf("expected directory fallback to succeed, got %v", err)
		}
		if len(lines) != 1 {
			t.Errorf("expected one logged watch failure, got %v", lines)
		}
	})

	t.Run("both watches failing is returned", func(t *testing.T) {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()

		var lines []string
		r := &Runner{CfgPath: "/nonexistent-haproxy-operator-dir/haproxy.cfg"}
		err = r.addWatches(w, captureLogger(&lines))
		if err == nil {
			t.Fatal("expected error when neither file nor directory can be watched")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected wrapped file watch error, got %v", err)
		}
		if len(lines) != 2 {
			t.Errorf("expected two logged watch failures, got %v", lines)
		}
	})
}
