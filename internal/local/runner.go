package local

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/bcit-tlu/haproxy-operator/internal/config"
	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
)

const (
	// defaultPollInterval is used when Runner.PollEvery is unset.
	defaultPollInterval = 5 * time.Second
	// maxApplyAttempts bounds retries of a single apply before giving up.
	maxApplyAttempts = 5
	// initialRetryBackoff is the first delay between apply attempts; it doubles
	// on each subsequent failure.
	initialRetryBackoff = 200 * time.Millisecond
	// debounceDelay lets editors finish writing before the file is re-read.
	debounceDelay = 150 * time.Millisecond
)

// Runner implements the local file-watching mode for development and testing.
// It watches a haproxy.cfg file on disk and pushes changes to the Dataplane API.
type Runner struct {
	CfgPath   string
	Client    *haproxy.Client
	PollEvery time.Duration
	Watch     bool
	// Log receives diagnostics for failed applies, unreadable files and watch
	// errors. Defaults to the controller-runtime logger named "local".
	Log logr.Logger
}

// Run starts the local runner. It applies the config once, then (if Watch is
// true) watches for file changes and re-applies on each detected change.
func (r *Runner) Run(ctx context.Context) error {
	if r.PollEvery <= 0 {
		r.PollEvery = defaultPollInterval
	}
	log := r.Log
	if log.GetSink() == nil {
		log = ctrl.Log.WithName("local")
	}
	log = log.WithValues("path", r.CfgPath)

	applyOnce := func() (string, error) {
		b, err := config.LoadFromFile(r.CfgPath)
		if err != nil {
			return "", err
		}
		h := config.HashBytes(b)
		if err := r.Client.ApplyRawConfiguration(ctx, string(b)); err != nil {
			return "", err
		}
		return h, nil
	}

	applyWithRetry := func() (string, error) {
		var lastErr error
		backoff := initialRetryBackoff
		for attempt := 1; attempt <= maxApplyAttempts; attempt++ {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			h, err := applyOnce()
			if err == nil {
				return h, nil
			}
			lastErr = err
			log.Error(err, "apply failed", "attempt", attempt, "maxAttempts", maxApplyAttempts)
			if attempt < maxApplyAttempts {
				time.Sleep(backoff)
				backoff *= 2
			}
		}
		return "", lastErr
	}

	h, err := applyWithRetry()
	if err != nil {
		return err
	}
	lastHash := h
	log.Info("configuration applied", "hash", lastHash)

	if !r.Watch {
		<-ctx.Done()
		return ctx.Err()
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	if err := r.addWatches(w, log); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-w.Events:
			if ev.Name != r.CfgPath {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			time.Sleep(debounceDelay)
			h, err := fileHash(r.CfgPath)
			if err != nil {
				log.Error(err, "failed to read changed configuration")
				continue
			}
			if h == lastHash {
				continue
			}
			newH, err := applyWithRetry()
			if err != nil {
				log.Error(err, "giving up applying changed configuration", "hash", h)
				continue
			}
			lastHash = newH
			log.Info("configuration applied", "hash", lastHash)
		case err := <-w.Errors:
			log.Error(err, "file watcher error")
		}
	}
}

// addWatches registers the config file and its directory. The directory watch
// is what catches atomic renames (vim, sed -i, etc.) since inotify tracks
// inodes, not paths. Failing to watch one of them is logged; failing both
// means no change could ever be detected, so it is returned as an error.
func (r *Runner) addWatches(w *fsnotify.Watcher, log logr.Logger) error {
	fileErr := w.Add(r.CfgPath)
	if fileErr != nil {
		log.Error(fileErr, "failed to watch configuration file; relying on directory watch")
	}
	dir := filepath.Dir(r.CfgPath)
	dirErr := w.Add(dir)
	if dirErr != nil {
		log.Error(dirErr, "failed to watch configuration directory; atomic renames will not be detected", "dir", dir)
	}
	if fileErr != nil && dirErr != nil {
		return fmt.Errorf("watch %s: %w (directory %s: %v)", r.CfgPath, fileErr, dir, dirErr)
	}
	return nil
}

func fileHash(p string) (string, error) {
	b, err := config.LoadFromFile(p)
	if err != nil {
		return "", err
	}
	return config.HashBytes(b), nil
}
