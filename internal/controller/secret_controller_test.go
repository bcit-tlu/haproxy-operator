package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/bcit-tlu/haproxy-operator/internal/config"
	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
	"github.com/bcit-tlu/haproxy-operator/internal/status"
)

func TestStripOperatorAnnotations(t *testing.T) {
	t.Run("removes operator annotations", func(t *testing.T) {
		in := map[string]string{
			"haproxy.operator/last-applied-hash": "abc123",
			"haproxy.operator/status":            "Applied",
			"app.kubernetes.io/name":             "haproxy-operator",
		}
		out := stripOperatorAnnotations(in)
		if len(out) != 1 {
			t.Errorf("expected 1 annotation, got %d", len(out))
		}
		if out["app.kubernetes.io/name"] != "haproxy-operator" {
			t.Errorf("unexpected value: %v", out)
		}
	})

	t.Run("returns nil for empty input", func(t *testing.T) {
		out := stripOperatorAnnotations(nil)
		if out != nil {
			t.Errorf("expected nil, got %v", out)
		}
	})

	t.Run("returns nil when all annotations are operator-owned", func(t *testing.T) {
		in := map[string]string{
			"haproxy.operator/status": "Applied",
		}
		out := stripOperatorAnnotations(in)
		if out != nil {
			t.Errorf("expected nil, got %v", out)
		}
	})
}

func TestIsRelevantUpdate(t *testing.T) {
	t.Run("nil old returns true", func(t *testing.T) {
		if !isRelevantUpdate(nil, nil) {
			t.Error("expected true for nil inputs")
		}
	})
}

func TestBackoffForFailure(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, 30 * time.Second},
		{1, 60 * time.Second},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 5 * time.Minute},
		{5, 5 * time.Minute},
		{100, 5 * time.Minute},
		{-1, 30 * time.Second},
	}
	for _, tc := range cases {
		if got := backoffForFailure(tc.failures); got != tc.want {
			t.Errorf("backoffForFailure(%d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

func TestEventReasonForClass(t *testing.T) {
	cases := map[haproxy.ErrorClass]string{
		haproxy.ClassAuth:        status.AuthError,
		haproxy.ClassTLS:         status.TLSConnectionErr,
		haproxy.ClassConnection:  status.ConnectionError,
		haproxy.ClassConflict:    status.ConflictError,
		haproxy.ClassRateLimited: status.TransientError,
		haproxy.ClassServer:      status.TransientError,
		haproxy.ClassUnknown:     status.TransientError,
	}
	for class, want := range cases {
		if got := eventReasonForClass(class); got != want {
			t.Errorf("eventReasonForClass(%s) = %q, want %q", class, got, want)
		}
	}
}

// fakeDataplane stands up an httptest server speaking just enough of the
// Dataplane API for reconcile tests.
type fakeDataplane struct {
	server        *httptest.Server
	validateCode  int
	applyCode     int
	validateCalls int
	applyCalls    int
}

func newFakeDataplane(t *testing.T, validateCode, applyCode int) *fakeDataplane {
	t.Helper()
	fd := &fakeDataplane{validateCode: validateCode, applyCode: applyCode}
	fd.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configuration/version"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "1")
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/configuration/raw"):
			if r.URL.Query().Get("only_validate") == "true" {
				fd.validateCalls++
				w.WriteHeader(fd.validateCode)
				if fd.validateCode >= 400 {
					fmt.Fprint(w, "validation error: config rejected")
				}
				return
			}
			fd.applyCalls++
			w.WriteHeader(fd.applyCode)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fd.server.Close)
	return fd
}

func newTestReconciler(t *testing.T, baseURL string, objs ...client.Object) (*SecretReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &SecretReconciler{
		Client:     c,
		Scheme:     scheme,
		SecretName: "haproxy-config",
		SecretKey:  "haproxy.cfg",
		APIConfig:  haproxy.APIConfig{BaseURL: baseURL},
		Recorder:   record.NewFakeRecorder(20),
	}, c
}

func configSecret(annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "haproxy-config",
			Namespace:   "haproxy-operator",
			Annotations: annotations,
		},
		Data: map[string][]byte{"haproxy.cfg": []byte("global\n    maxconn 1024\n")},
	}
}

func reconcileOnce(t *testing.T, r *SecretReconciler) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Namespace: "haproxy-operator", Name: "haproxy-config"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return res
}

func getSecret(t *testing.T, c client.Client) *corev1.Secret {
	t.Helper()
	s := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "haproxy-operator", Name: "haproxy-config"}, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReconcileDeterministicRejection(t *testing.T) {
	fd := newFakeDataplane(t, http.StatusBadRequest, 0)
	r, c := newTestReconciler(t, fd.server.URL+"/v3", configSecret(nil))

	res := reconcileOnce(t, r)
	if res.RequeueAfter != RequeueInterval {
		t.Errorf("expected RequeueInterval after rejection, got %v", res.RequeueAfter)
	}

	s := getSecret(t, c)
	wantHash := config.HashBytes(s.Data["haproxy.cfg"])
	if got := s.Annotations[LastFailedHashAnnotation]; got != wantHash {
		t.Errorf("last-failed-hash = %q, want %q", got, wantHash)
	}
	if got := s.Annotations[StatusAnnotation]; got != string(haproxy.ClassConfigRejected) {
		t.Errorf("status = %q, want %q", got, haproxy.ClassConfigRejected)
	}
	if fd.validateCalls != 1 {
		t.Errorf("expected 1 validate call, got %d", fd.validateCalls)
	}
	if fd.applyCalls != 0 {
		t.Errorf("apply must not run after rejection, got %d calls", fd.applyCalls)
	}

	// Second reconcile: suppressed — dataplane must not be hit again.
	res = reconcileOnce(t, r)
	if res.RequeueAfter != RequeueInterval {
		t.Errorf("suppressed reconcile should use RequeueInterval, got %v", res.RequeueAfter)
	}
	if fd.validateCalls != 1 {
		t.Errorf("rejected config must be cached — validate calls = %d", fd.validateCalls)
	}
}

func TestReconcileTransientFailureRetries(t *testing.T) {
	fd := newFakeDataplane(t, http.StatusServiceUnavailable, 0)
	r, c := newTestReconciler(t, fd.server.URL+"/v3", configSecret(nil))

	res := reconcileOnce(t, r)
	if res.RequeueAfter != backoffForFailure(1) {
		t.Errorf("expected backoff %v after first transient failure, got %v", backoffForFailure(1), res.RequeueAfter)
	}

	s := getSecret(t, c)
	if _, ok := s.Annotations[LastFailedHashAnnotation]; ok {
		t.Error("transient failure must NOT suppress the desired hash")
	}
	if got := s.Annotations[StatusAnnotation]; got != string(haproxy.ClassServer) {
		t.Errorf("status = %q, want %q", got, haproxy.ClassServer)
	}

	// Second reconcile retries the same bytes (not suppressed) and backs off further.
	res = reconcileOnce(t, r)
	if res.RequeueAfter != backoffForFailure(2) {
		t.Errorf("expected backoff %v after second transient failure, got %v", backoffForFailure(2), res.RequeueAfter)
	}
	if fd.validateCalls != 2 {
		t.Errorf("transient failure must retry — validate calls = %d", fd.validateCalls)
	}
}

func TestReconcileSuccessClearsStaleFailureState(t *testing.T) {
	fd := newFakeDataplane(t, http.StatusOK, http.StatusAccepted)
	s := configSecret(map[string]string{
		LastFailedHashAnnotation:  "deadbeef",
		StatusMessageAnnotation:   "previous failure",
		StatusAnnotation:          string(haproxy.ClassConfigRejected),
		"fluxcd.io/synced":        "kept",
		"unrelated.io/annotation": "also-kept",
	})
	r, c := newTestReconciler(t, fd.server.URL+"/v3", s)

	res := reconcileOnce(t, r)
	if res.RequeueAfter != RequeueInterval {
		t.Errorf("expected RequeueInterval after success, got %v", res.RequeueAfter)
	}

	out := getSecret(t, c)
	wantHash := config.HashBytes(out.Data["haproxy.cfg"])
	if got := out.Annotations[LastAppliedHashAnnotation]; got != wantHash {
		t.Errorf("last-applied-hash = %q, want %q", got, wantHash)
	}
	if got := out.Annotations[StatusAnnotation]; got != "Applied" {
		t.Errorf("status = %q, want Applied", got)
	}
	if _, ok := out.Annotations[LastFailedHashAnnotation]; ok {
		t.Error("last-failed-hash must be cleared after success")
	}
	if _, ok := out.Annotations[StatusMessageAnnotation]; ok {
		t.Error("status-message must be cleared after success")
	}
	// Patch must not clobber annotations owned by other actors.
	for _, k := range []string{"fluxcd.io/synced", "unrelated.io/annotation"} {
		if _, ok := out.Annotations[k]; !ok {
			t.Errorf("foreign annotation %q was lost", k)
		}
	}
	if fd.applyCalls != 1 {
		t.Errorf("expected 1 apply call, got %d", fd.applyCalls)
	}
}
