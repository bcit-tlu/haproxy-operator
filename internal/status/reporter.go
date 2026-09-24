// Package status provides structured Kubernetes Event reporting for the
// haproxy-operator reconciliation lifecycle. Events are emitted on the
// haproxy-config Secret so operators can monitor accept/reject outcomes
// via kubectl describe secret or the Kubernetes Events API.
package status

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

// Reason constants for Kubernetes Events emitted by the operator.
const (
	ValidationPassed = "ValidationPassed"
	ValidationFailed = "ValidationFailed" // deprecated alias kept for dashboards; new code emits ConfigRejected
	ConfigRejected   = "ConfigRejected"
	ApplySucceeded   = "ApplySucceeded"
	ApplyFailed      = "ApplyFailed"
	AuthError        = "AuthError"
	TLSConnectionErr = "TLSConnectionError"
	ConnectionError  = "ConnectionError"
	ConflictError    = "ConflictError"
	TransientError   = "TransientError"
	ConfigUnchanged  = "ConfigUnchanged"
)

// warningReasons are emitted as Warning events; everything else is Normal.
var warningReasons = map[string]bool{
	ConfigRejected:   true,
	ValidationFailed: true,
	ApplyFailed:      true,
	AuthError:        true,
	TLSConnectionErr: true,
	ConnectionError:  true,
	ConflictError:    true,
	TransientError:   true,
}

// maxEventMessage bounds the message written into an Event. Dataplane
// validation errors can echo large chunks of the submitted config, so all
// messages are sanitized and truncated at this single choke point.
const maxEventMessage = 512

// SanitizeMessage makes an arbitrary error/message string safe for Events
// and annotations: strips control characters, collapses newlines into
// separators, and truncates to maxEventMessage.
func SanitizeMessage(msg string) string {
	var b strings.Builder
	b.Grow(len(msg))
	for _, r := range msg {
		switch {
		case r == '\n' || r == '\r':
			b.WriteString(" | ")
		case r < 0x20 || r == 0x7f:
			// drop other control characters entirely
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > maxEventMessage {
		out = out[:maxEventMessage] + "…"
	}
	return out
}

// EmitEvent records a Kubernetes Event on the given object.
func EmitEvent(recorder record.EventRecorder, obj *corev1.Secret, reason, message string) {
	if recorder == nil {
		return
	}

	eventType := corev1.EventTypeNormal
	if warningReasons[reason] {
		eventType = corev1.EventTypeWarning
	}

	if message == "" {
		message = reason
	}

	recorder.Eventf(obj, eventType, reason, "%s", SanitizeMessage(message))
}
