package controller

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/bcit-tlu/haproxy-operator/internal/config"
	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
	"github.com/bcit-tlu/haproxy-operator/internal/metrics"
	"github.com/bcit-tlu/haproxy-operator/internal/spire"
	"github.com/bcit-tlu/haproxy-operator/internal/status"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// LastAppliedHashAnnotation stores the SHA256 of the last successfully applied config.
	LastAppliedHashAnnotation = "haproxy.operator/last-applied-hash"

	// LastFailedHashAnnotation stores the SHA256 of the last config that was
	// deterministically rejected by the Dataplane API, so the reconciler
	// skips re-validation until the config changes. It is ONLY set for
	// ConfigRejected-class failures — transient errors never suppress the
	// desired bytes.
	LastFailedHashAnnotation = "haproxy.operator/last-failed-hash"

	// StatusAnnotation records the reconciliation status on the Secret.
	StatusAnnotation = "haproxy.operator/status"

	// StatusMessageAnnotation records a sanitized, bounded failure detail.
	StatusMessageAnnotation = "haproxy.operator/status-message"

	// LastUpdateTimeAnnotation records the last status transition.
	LastUpdateTimeAnnotation = "haproxy.operator/last-update-time"

	// LastAppliedTimeAnnotation records the last successful apply time.
	LastAppliedTimeAnnotation = "haproxy.operator/last-applied-time"

	// RequeueInterval is the default periodic reconciliation interval.
	RequeueInterval = 5 * time.Minute

	// baseRetryInterval is the floor for transient-failure backoff.
	baseRetryInterval = 30 * time.Second
	// maxRetryInterval bounds transient-failure backoff.
	maxRetryInterval = 5 * time.Minute
)

// backoffForFailure returns a bounded exponential delay for the Nth
// consecutive transient failure (0-based): 30s, 60s, 2m, 4m, then capped
// at maxRetryInterval. The wait itself is expressed as RequeueAfter so
// shutdown cancels it — no timer blocks a reconcile.
func backoffForFailure(failures int) time.Duration {
	if failures < 0 {
		failures = 0
	}
	if failures > 7 {
		return maxRetryInterval
	}
	d := baseRetryInterval << uint(failures)
	if d > maxRetryInterval {
		return maxRetryInterval
	}
	return d
}

// exportConfigHash records the desired hash under a state label and removes
// the previous series so the metric reflects only the latest outcome.
func (r *SecretReconciler) exportConfigHash(hash, state string) {
	if r.lastMetricHash != "" && (r.lastMetricHash != hash || r.lastMetricState != state) {
		metrics.ConfigHash.DeleteLabelValues(r.lastMetricHash, r.lastMetricState)
	}
	metrics.ConfigHash.WithLabelValues(hash, state).Set(1)
	r.lastMetricHash = hash
	r.lastMetricState = state
}

// eventReasonForClass maps a Dataplane error class to a K8s Event reason.
func eventReasonForClass(c haproxy.ErrorClass) string {
	switch c {
	case haproxy.ClassAuth:
		return status.AuthError
	case haproxy.ClassTLS:
		return status.TLSConnectionErr
	case haproxy.ClassConnection:
		return status.ConnectionError
	case haproxy.ClassConflict:
		return status.ConflictError
	default:
		return status.TransientError
	}
}

// SecretReconciler reconciles Secret objects containing HAProxy configuration.
// In the GitOps flow, FluxCD watches a private GitHub repo and syncs the
// haproxy.cfg into a Kubernetes Secret. This controller detects changes to
// that Secret, validates the config via the Dataplane API, and applies it
// to the HAProxy instance.
type SecretReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	SecretName      string
	SecretKey       string
	APIConfig       haproxy.APIConfig
	SpireSocketPath string
	Recorder        record.EventRecorder

	// haproxyClient is created lazily and reused across reconciliations.
	haproxyClient *haproxy.Client
	// spireSource holds the SPIRE X509Source for lifecycle management.
	// It is created once and closed on shutdown via the manager Runnable.
	spireSource *workloadapi.X509Source
	clientMu    sync.Mutex
	clientReady bool
	// transientFailures counts consecutive retryable failures to drive
	// bounded backoff. Reset on success, deterministic rejection, or when
	// the desired bytes change.
	transientFailures int
	lastDesiredHash   string
	// lastMetricHash/lastMetricState track the exported ConfigHash series so
	// stale series are deleted instead of accumulating.
	lastMetricHash  string
	lastMetricState string
}

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is the main reconciliation loop. It is triggered by Flux updating
// the haproxy-config Secret, or by the periodic requeue interval.
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx).WithValues("secret", req.NamespacedName)

	if r.SecretName != "" && req.Name != r.SecretName {
		return ctrl.Result{}, nil
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Secret not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch Secret")
		return ctrl.Result{}, err
	}

	if !r.shouldReconcile(secret) {
		return ctrl.Result{}, nil
	}

	configData, exists := secret.Data[r.SecretKey]
	if !exists {
		err := fmt.Errorf("key %s not found in Secret", r.SecretKey)
		log.Error(err, "configuration key missing")
		if uerr := r.failWithStatus(ctx, secret, "Error", err.Error()); uerr != nil {
			return ctrl.Result{}, uerr
		}
		return ctrl.Result{RequeueAfter: baseRetryInterval}, nil
	}

	rawConfig := string(configData)

	currentHash := config.HashBytes(configData)
	lastAppliedHash := secret.Annotations[LastAppliedHashAnnotation]

	if currentHash == lastAppliedHash {
		log.Info("configuration unchanged, skipping reconciliation")
		r.transientFailures = 0
		return ctrl.Result{RequeueAfter: RequeueInterval}, nil
	}

	// New desired bytes reset the transient-failure streak — they were never
	// given a chance to fail. This runs before client initialization so a
	// changed Secret does not inherit a prior init failure's backoff.
	if r.lastDesiredHash != currentHash {
		r.transientFailures = 0
		r.lastDesiredHash = currentHash
	}

	// Skip re-validation only for deterministically rejected configs — wait
	// for new desired bytes from the next Flux sync.
	if currentHash == secret.Annotations[LastFailedHashAnnotation] {
		log.Info("configuration previously rejected, skipping until changed")
		return ctrl.Result{RequeueAfter: RequeueInterval}, nil
	}

	haproxyClient, err := r.getOrCreateClient(ctx)
	if err != nil {
		log.Error(err, "failed to create dataplane client")
		class := haproxy.Classify(err)
		metrics.TransientErrors.WithLabelValues(string(class)).Inc()
		if uerr := r.failWithStatus(ctx, secret, class.StatusValue(), err.Error()); uerr != nil {
			return ctrl.Result{}, uerr
		}
		r.transientFailures++
		return ctrl.Result{RequeueAfter: backoffForFailure(r.transientFailures)}, nil
	}

	log.Info("configuration changed, validating",
		"currentHash", currentHash,
		"lastAppliedHash", lastAppliedHash)

	// Phase 1: Validate configuration before applying.
	metrics.ReconcileAttempts.WithLabelValues("validate").Inc()
	validator := config.NewValidator(haproxyClient)
	if err := validator.Validate(ctx, rawConfig); err != nil {
		class := haproxy.Classify(err)
		log.Error(err, "configuration validation failed", "class", string(class))
		metrics.ReconcileResults.WithLabelValues(string(class)).Inc()
		if class == haproxy.ClassConfigRejected {
			status.EmitEvent(r.Recorder, secret, status.ConfigRejected, err.Error())
			r.exportConfigHash(currentHash, "rejected")
			if uerr := r.failWithStatus(ctx, secret, string(haproxy.ClassConfigRejected), err.Error(), func(ann map[string]string) {
				ann[LastFailedHashAnnotation] = currentHash
			}); uerr != nil {
				return ctrl.Result{}, uerr
			}
			return ctrl.Result{RequeueAfter: RequeueInterval}, nil
		}
		// Transient — never suppress the desired hash; retry with backoff.
		metrics.TransientErrors.WithLabelValues(string(class)).Inc()
		status.EmitEvent(r.Recorder, secret, eventReasonForClass(class), err.Error())
		if uerr := r.failWithStatus(ctx, secret, class.StatusValue(), err.Error()); uerr != nil {
			return ctrl.Result{}, uerr
		}
		r.transientFailures++
		return ctrl.Result{RequeueAfter: backoffForFailure(r.transientFailures)}, nil
	}

	log.Info("configuration validated, applying to HAProxy")
	status.EmitEvent(r.Recorder, secret, status.ValidationPassed, "")

	// Phase 2: Apply already-validated configuration (skip redundant validation).
	metrics.ReconcileAttempts.WithLabelValues("apply").Inc()
	if err := haproxyClient.ApplyRawConfigurationValidated(ctx, rawConfig); err != nil {
		class := haproxy.Classify(err)
		log.Error(err, "failed to apply configuration to HAProxy", "class", string(class))
		metrics.ReconcileResults.WithLabelValues(string(class)).Inc()
		if class == haproxy.ClassConfigRejected {
			// Deterministic rejection at apply time (e.g. version race on
			// semantic checks) — suppress until bytes change, same as a
			// validate-time rejection.
			status.EmitEvent(r.Recorder, secret, status.ConfigRejected, err.Error())
			r.exportConfigHash(currentHash, "rejected")
			if uerr := r.failWithStatus(ctx, secret, string(haproxy.ClassConfigRejected), err.Error(), func(ann map[string]string) {
				ann[LastFailedHashAnnotation] = currentHash
			}); uerr != nil {
				return ctrl.Result{}, uerr
			}
			return ctrl.Result{RequeueAfter: RequeueInterval}, nil
		}
		metrics.TransientErrors.WithLabelValues(string(class)).Inc()
		status.EmitEvent(r.Recorder, secret, eventReasonForClass(class), err.Error())
		// Keep the failure stage AND its class in the status — consumers can
		// distinguish e.g. ApplyAuthError from a validate-time AuthError.
		if uerr := r.failWithStatus(ctx, secret, "Apply"+class.StatusValue(), err.Error()); uerr != nil {
			return ctrl.Result{}, uerr
		}
		r.transientFailures++
		return ctrl.Result{RequeueAfter: backoffForFailure(r.transientFailures)}, nil
	}

	log.Info("configuration successfully applied to HAProxy")
	status.EmitEvent(r.Recorder, secret, status.ApplySucceeded, "")
	metrics.ReconcileResults.WithLabelValues("applied").Inc()
	r.exportConfigHash(currentHash, "applied")
	metrics.LastSuccessfulApply.SetToCurrentTime()
	r.transientFailures = 0

	// Phase 3: Record the applied hash and clear stale failure state.
	if err := r.patchAnnotations(ctx, secret, func(ann map[string]string) {
		ann[LastAppliedHashAnnotation] = currentHash
		ann[StatusAnnotation] = "Applied"
		ann[LastAppliedTimeAnnotation] = time.Now().Format(time.RFC3339)
		delete(ann, LastFailedHashAnnotation)
		delete(ann, StatusMessageAnnotation)
	}); err != nil {
		log.Error(err, "failed to patch Secret annotations")
		if errors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: backoffForFailure(0)}, nil
		}
		return ctrl.Result{}, err
	}

	log.Info("reconciliation complete")
	return ctrl.Result{RequeueAfter: RequeueInterval}, nil
}

// getOrCreateClient lazily initializes the Dataplane API client and reuses it
// across all reconciliations. If initialization fails (e.g. SPIRE agent not
// yet ready), subsequent calls will retry rather than permanently caching
// the error.
func (r *SecretReconciler) getOrCreateClient(ctx context.Context) (*haproxy.Client, error) {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()

	if r.clientReady {
		return r.haproxyClient, nil
	}

	var (
		c   *haproxy.Client
		err error
	)

	if r.SpireSocketPath != "" {
		transport, source, tErr := spire.TLSTransport(ctx, r.SpireSocketPath)
		if tErr != nil {
			return nil, fmt.Errorf("SPIRE transport: %w", tErr)
		}
		c, err = haproxy.NewClientWithTransport(r.APIConfig, transport)
		if err != nil {
			source.Close()
			return nil, err
		}
		r.spireSource = source
	} else {
		c, err = haproxy.NewClient(r.APIConfig)
		if err != nil {
			return nil, err
		}
	}

	r.haproxyClient = c
	r.clientReady = true
	return r.haproxyClient, nil
}

// DataplaneReady is the readiness probe body: it proves the client can be
// built from the mounted credentials AND that an authenticated read
// (configuration version) succeeds — without touching configuration.
// Liveness stays process-local (healthz.Ping in main.go).
func (r *SecretReconciler) DataplaneReady(req *http.Request) error {
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()

	c, err := r.getOrCreateClient(ctx)
	if err != nil {
		return fmt.Errorf("dataplane client init: %w", err)
	}
	if err := c.Ping(ctx); err != nil {
		return fmt.Errorf("dataplane probe: %w", err)
	}
	return nil
}

// Close releases resources held by the reconciler (SPIRE X509Source).
// It is registered as a manager Runnable in SetupWithManager.
func (r *SecretReconciler) Close() error {
	if r.spireSource != nil {
		return r.spireSource.Close()
	}
	return nil
}

func isRelevantUpdate(oldSecret, newSecret *corev1.Secret) bool {
	if oldSecret == nil || newSecret == nil {
		return true
	}
	if !reflect.DeepEqual(oldSecret.Labels, newSecret.Labels) {
		return true
	}
	if !reflect.DeepEqual(oldSecret.Data, newSecret.Data) {
		return true
	}
	if !reflect.DeepEqual(stripOperatorAnnotations(oldSecret.Annotations), stripOperatorAnnotations(newSecret.Annotations)) {
		return true
	}
	return false
}

func stripOperatorAnnotations(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range in {
		if strings.HasPrefix(k, "haproxy.operator/") {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (r *SecretReconciler) shouldReconcile(secret *corev1.Secret) bool {
	if r.SecretName != "" {
		return secret.Name == r.SecretName
	}
	return true
}

// patchAnnotations applies a mutation to the Secret's annotations via a
// merge patch so only the operator's own keys are written — annotations
// owned by Flux or other actors are never clobbered, and a stale
// resourceVersion can't silently overwrite them.
func (r *SecretReconciler) patchAnnotations(ctx context.Context, secret *corev1.Secret, mutate func(map[string]string)) error {
	orig := secret.DeepCopy()
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	mutate(secret.Annotations)
	// Optimistic lock: the patch carries our read resourceVersion, so a
	// concurrent Secret write (e.g. Flux replacing data mid-apply) fails
	// with a conflict instead of stamping stale status on newer bytes.
	return r.Patch(ctx, secret, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
}

// failWithStatus records status/message annotations (patch-scoped to
// operator keys). The caller decides the requeue interval since a
// deterministic rejection and a transient error want different schedules.
// An optional extra mutation (e.g. recording the rejected hash) runs in the
// same patch. Kubernetes write conflicts map to a short requeue, not an error.
func (r *SecretReconciler) failWithStatus(ctx context.Context, secret *corev1.Secret, statusVal, message string, extra ...func(map[string]string)) error {
	err := r.patchAnnotations(ctx, secret, func(ann map[string]string) {
		ann[StatusAnnotation] = statusVal
		ann[StatusMessageAnnotation] = status.SanitizeMessage(message)
		ann[LastUpdateTimeAnnotation] = time.Now().Format(time.RFC3339)
		for _, m := range extra {
			m(ann)
		}
	})
	if errors.IsConflict(err) {
		return nil // caller's requeue covers the retry
	}
	return err
}

// spireSourceCloser implements manager.Runnable to close the SPIRE X509Source
// when the manager context is cancelled (operator shutdown).
type spireSourceCloser struct {
	reconciler *SecretReconciler
}

func (c *spireSourceCloser) Start(ctx context.Context) error {
	<-ctx.Done()
	return c.reconciler.Close()
}

// SetupWithManager registers the controller with the manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("haproxy-operator")
	}

	// Register a Runnable that closes the SPIRE source on shutdown.
	if err := mgr.Add(&spireSourceCloser{reconciler: r}); err != nil {
		return fmt.Errorf("register SPIRE source closer: %w", err)
	}

	// Readiness must prove the Dataplane credentials and endpoint actually
	// work — a mere process-alive check is the liveness probe's job.
	if err := mgr.AddReadyzCheck("dataplane", r.DataplaneReady); err != nil {
		return fmt.Errorf("register dataplane readiness check: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool { return true },
			UpdateFunc: func(e event.UpdateEvent) bool {
				oldSecret, okOld := e.ObjectOld.(*corev1.Secret)
				newSecret, okNew := e.ObjectNew.(*corev1.Secret)
				if !okOld || !okNew {
					return true
				}
				return isRelevantUpdate(oldSecret, newSecret)
			},
			DeleteFunc:  func(e event.DeleteEvent) bool { return false },
			GenericFunc: func(e event.GenericEvent) bool { return false },
		}).
		Complete(r)
}
