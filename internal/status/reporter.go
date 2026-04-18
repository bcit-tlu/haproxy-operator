// Package status provides structured Kubernetes Event reporting for the
// haproxy-operator reconciliation lifecycle. Events are emitted on the
// haproxy-config Secret so operators can monitor accept/reject outcomes
// via kubectl describe secret or the Kubernetes Events API.
package status

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

// Reason constants for Kubernetes Events emitted by the operator.
const (
	ValidationPassed  = "ValidationPassed"
	ValidationFailed  = "ValidationFailed"
	ApplySucceeded    = "ApplySucceeded"
	ApplyFailed       = "ApplyFailed"
	ConfigUnchanged   = "ConfigUnchanged"
)

// EmitEvent records a Kubernetes Event on the given object.
func EmitEvent(recorder record.EventRecorder, obj *corev1.Secret, reason, message string) {
	if recorder == nil {
		return
	}

	eventType := corev1.EventTypeNormal
	if reason == ValidationFailed || reason == ApplyFailed {
		eventType = corev1.EventTypeWarning
	}

	if message == "" {
		message = reason
	}

	recorder.Eventf(obj, eventType, reason, "%s", message)
}
