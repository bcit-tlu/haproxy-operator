package local

import (
	"context"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/bcit-tlu/haproxy-operator/internal/config"
	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
)

// Runner implements the local file-watching mode for development and testing.
// It watches a haproxy.cfg file on disk and pushes changes to the Dataplane API.
type Runner struct {
	CfgPath   string
	Client    *haproxy.Client
	PollEvery time.Duration
	Watch     bool
}

// Run starts the local runner. It applies the config once, then (if Watch is
// true) watches for file changes and re-applies on each detected change.
func (r *Runner) Run(ctx context.Context) error {
	if r.PollEvery <= 0 {
		r.PollEvery = 5 * time.Second
	}

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
		backoff := 200 * time.Millisecond
		for attempt := 0; attempt < 5; attempt++ {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if h, err := applyOnce(); err == nil {
				return h, nil
			} else {
				lastErr = err
				if attempt < 4 {
					time.Sleep(backoff)
					backoff *= 2
				}
			}
		}
		return "", lastErr
	}

	lastHash := ""
	h, err := applyWithRetry()
	if err != nil {
		return err
	}
	lastHash = h

	if !r.Watch {
		<-ctx.Done()
		return ctx.Err()
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	if err := w.Add(r.CfgPath); err != nil {
		_ = w.Add(dirOf(r.CfgPath))
	} else {
		// Also watch the directory so that atomic renames (vim, sed -i, etc.)
		// are detected — inotify tracks inodes, not paths.
		_ = w.Add(dirOf(r.CfgPath))
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
			time.Sleep(150 * time.Millisecond)
			h, err := fileHash(r.CfgPath)
			if err != nil {
				continue
			}
			if h == lastHash {
				continue
			}
			if newH, err := applyWithRetry(); err == nil {
				lastHash = newH
			}
		case <-w.Errors:
			// ignore
		}
	}
}

func dirOf(p string) string {
	idx := len(p) - 1
	for idx >= 0 && p[idx] != '/' {
		idx--
	}
	if idx <= 0 {
		return "/"
	}
	return p[:idx]
}

func fileHash(p string) (string, error) {
	b, err := config.LoadFromFile(p)
	if err != nil {
		return "", err
	}
	return config.HashBytes(b), nil
}
