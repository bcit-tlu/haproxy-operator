package status

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

func TestEmitEvent(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "haproxy-config",
			Namespace: "haproxy-operator",
		},
	}

	t.Run("nil recorder does not panic", func(t *testing.T) {
		EmitEvent(nil, secret, ValidationPassed, "ok")
	})

	t.Run("ValidationPassed emits Normal event", func(t *testing.T) {
		rec := record.NewFakeRecorder(10)
		EmitEvent(rec, secret, ValidationPassed, "config valid")
		ev := <-rec.Events
		if ev == "" {
			t.Fatal("expected event")
		}
		if !contains(ev, "Normal") {
			t.Errorf("expected Normal event, got: %s", ev)
		}
		if !contains(ev, "ValidationPassed") {
			t.Errorf("expected ValidationPassed reason, got: %s", ev)
		}
	})

	t.Run("ValidationFailed emits Warning event", func(t *testing.T) {
		rec := record.NewFakeRecorder(10)
		EmitEvent(rec, secret, ValidationFailed, "bad config")
		ev := <-rec.Events
		if !contains(ev, "Warning") {
			t.Errorf("expected Warning event, got: %s", ev)
		}
	})

	t.Run("ApplySucceeded emits Normal event", func(t *testing.T) {
		rec := record.NewFakeRecorder(10)
		EmitEvent(rec, secret, ApplySucceeded, "")
		ev := <-rec.Events
		if !contains(ev, "Normal") {
			t.Errorf("expected Normal event, got: %s", ev)
		}
		if !contains(ev, "ApplySucceeded") {
			t.Errorf("expected ApplySucceeded reason, got: %s", ev)
		}
	})

	t.Run("ApplyFailed emits Warning event", func(t *testing.T) {
		rec := record.NewFakeRecorder(10)
		EmitEvent(rec, secret, ApplyFailed, "connection refused")
		ev := <-rec.Events
		if !contains(ev, "Warning") {
			t.Errorf("expected Warning event, got: %s", ev)
		}
	})

	t.Run("empty message uses reason", func(t *testing.T) {
		rec := record.NewFakeRecorder(10)
		EmitEvent(rec, secret, ConfigUnchanged, "")
		ev := <-rec.Events
		if !contains(ev, "ConfigUnchanged") {
			t.Errorf("expected ConfigUnchanged in event, got: %s", ev)
		}
	})
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchIn(s, sub)
}

func searchIn(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
