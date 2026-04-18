package controller

import (
	"context"
	"fmt"
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
	"github.com/bcit-tlu/haproxy-operator/internal/spire"
	"github.com/bcit-tlu/haproxy-operator/internal/status"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// LastAppliedHashAnnotation stores the SHA256 of the last successfully applied config.
	LastAppliedHashAnnotation = "haproxy.operator/last-applied-hash"

	// LastFailedHashAnnotation stores the SHA256 of the last config that failed
	// validation, so the reconciler skips re-validation until the config changes.
	LastFailedHashAnnotation = "haproxy.operator/last-failed-hash"

	// StatusAnnotation records the reconciliation status on the Secret.
	StatusAnnotation = "haproxy.operator/status"

	// RequeueInterval is the default periodic reconciliation interval.
	RequeueInterval = 5 * time.Minute
)

// SecretReconciler reconciles Secret objects containing HAProxy configuration.
// In the GitOps flow, FluxCD watches a private GitHub repo and syncs the
// haproxy.cfg into a Kubernetes Secret. This controller detects changes to
// that Secret, validates the config via the Dataplane API, and applies it
// to the production HAProxy instance.
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
		return r.updateStatus(ctx, secret, "Error", err.Error())
	}

	rawConfig := string(configData)

	haproxyClient, err := r.getOrCreateClient(ctx)
	if err != nil {
		log.Error(err, "failed to create dataplane client")
		return r.updateStatus(ctx, secret, "ConfigError", err.Error())
	}

	currentHash := config.HashBytes(configData)
	lastAppliedHash := secret.Annotations[LastAppliedHashAnnotation]

	if currentHash == lastAppliedHash {
		log.Info("configuration unchanged, skipping reconciliation")
		return ctrl.Result{RequeueAfter: RequeueInterval}, nil
	}

	// Skip re-validation for configs that already failed — wait for a new Flux sync.
	if currentHash == secret.Annotations[LastFailedHashAnnotation] {
		log.Info("configuration previously failed validation, skipping until changed")
		return ctrl.Result{RequeueAfter: RequeueInterval}, nil
	}

	log.Info("configuration changed, validating",
		"currentHash", currentHash,
		"lastAppliedHash", lastAppliedHash)

	// Phase 1: Validate configuration before applying.
	validator := config.NewValidator(haproxyClient)
	if err := validator.Validate(ctx, rawConfig); err != nil {
		log.Error(err, "configuration validation failed — rejecting")
		status.EmitEvent(r.Recorder, secret, status.ValidationFailed, err.Error())
		// Record the failed hash so we don't retry until the config changes.
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations[LastFailedHashAnnotation] = currentHash
		return r.updateStatus(ctx, secret, "ValidationFailed", err.Error())
	}

	log.Info("configuration validated, applying to HAProxy")
	status.EmitEvent(r.Recorder, secret, status.ValidationPassed, "")

	// Phase 2: Apply already-validated configuration (skip redundant validation).
	if err := haproxyClient.ApplyRawConfigurationValidated(ctx, rawConfig); err != nil {
		log.Error(err, "failed to apply configuration to HAProxy")
		status.EmitEvent(r.Recorder, secret, status.ApplyFailed, err.Error())
		return r.updateStatus(ctx, secret, "ApplyError", err.Error())
	}

	log.Info("configuration successfully applied to HAProxy")
	status.EmitEvent(r.Recorder, secret, status.ApplySucceeded, "")

	// Phase 3: Update annotations to record the applied hash.
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[LastAppliedHashAnnotation] = currentHash
	secret.Annotations[StatusAnnotation] = "Applied"
	secret.Annotations["haproxy.operator/last-applied-time"] = time.Now().Format(time.RFC3339)

	if err := r.Update(ctx, secret); err != nil {
		log.Error(err, "failed to update Secret annotations")
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

func (r *SecretReconciler) updateStatus(ctx context.Context, secret *corev1.Secret, statusVal, message string) (ctrl.Result, error) {
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[StatusAnnotation] = statusVal
	if message != "" {
		secret.Annotations["haproxy.operator/status-message"] = message
	}
	secret.Annotations["haproxy.operator/last-update-time"] = time.Now().Format(time.RFC3339)

	if err := r.Update(ctx, secret); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
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
