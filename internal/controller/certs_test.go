package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// testBundlePEM returns a fresh self-signed cert PEM and key PEM for tests.
func testBundlePEM(t *testing.T) (crt, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.ltc.bcit.ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func tlsSecret(name string, crt, key []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "haproxy-operator"},
		Data:       map[string][]byte{"tls.crt": crt, "tls.key": key},
	}
}

// storageDataplane stands up an httptest server speaking enough of the
// Dataplane API for cert tests: config version + raw validate/apply, plus the
// ssl_certificates storage surface, recording call order so tests can assert
// certs are pushed before validation runs.
type storageDataplane struct {
	server        *httptest.Server
	certStatus    int // code returned by storage PUT/POST (0 = 201/200)
	order         []string
	storage       map[string]string // storage object name → pushed leaf serial
	liveConfig    string            // served by GET /configuration/raw
	validateCalls int
	applyCalls    int
}

const storagePrefix = "/services/haproxy/storage/ssl_certificates"

func newStorageDataplane(t *testing.T) *storageDataplane {
	fd := &storageDataplane{storage: map[string]string{}}
	fd.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configuration/version"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "1")
		case strings.Contains(r.URL.Path, storagePrefix):
			fd.order = append(fd.order, "cert:"+r.Method)
			switch r.Method {
			case http.MethodGet:
				if serial, ok := fd.storage[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]; ok {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"serial":%q}`, serial)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			case http.MethodPost:
				if name, serial, err := multipartCert(r); err == nil {
					fd.storage[name] = serial
				}
				if fd.certStatus != 0 {
					w.WriteHeader(fd.certStatus)
					return
				}
				w.WriteHeader(http.StatusCreated)
			case http.MethodPut:
				if fd.certStatus != 0 {
					w.WriteHeader(fd.certStatus)
					return
				}
				w.WriteHeader(http.StatusOK)
			}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configuration/raw"):
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, fd.liveConfig)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/configuration/raw"):
			if r.URL.Query().Get("only_validate") == "true" {
				fd.order = append(fd.order, "validate")
				fd.validateCalls++
				w.WriteHeader(http.StatusOK)
				return
			}
			fd.order = append(fd.order, "apply")
			fd.applyCalls++
			b, _ := io.ReadAll(r.Body)
			fd.liveConfig = string(b)
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fd.server.Close)
	return fd
}

// multipartCert returns the uploaded file's storage name and leaf serial.
func multipartCert(r *http.Request) (name, serial string, err error) {
	f, hdr, err := r.FormFile("file_upload")
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", "", fmt.Errorf("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	return hdr.Filename, cert.SerialNumber.String(), nil
}

func TestCertPEMBundle(t *testing.T) {
	crt, key := testBundlePEM(t)

	t.Run("assembles crt then key", func(t *testing.T) {
		bundle, err := certPEMBundle(tlsSecret("star", crt, key))
		if err != nil {
			t.Fatal(err)
		}
		s := string(bundle)
		if strings.Index(s, "CERTIFICATE") > strings.Index(s, "PRIVATE KEY") {
			t.Error("key must follow the certificate chain")
		}
	})

	t.Run("requires both keys", func(t *testing.T) {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "empty"}}
		if _, err := certPEMBundle(s); err == nil {
			t.Fatal("expected error for missing tls data")
		}
	})
}

func TestReconcileConfigPushesCertsBeforeValidate(t *testing.T) {
	crt, key := testBundlePEM(t)
	fd := newStorageDataplane(t)
	r, _ := newTestReconciler(t, fd.server.URL+"/v3", configSecret(nil), tlsSecret("star-ltc", crt, key))
	r.CertsSecretNames = []string{"star-ltc"}

	res := reconcileOnce(t, r)
	if res.RequeueAfter != RequeueInterval {
		t.Fatalf("expected RequeueInterval, got %v", res.RequeueAfter)
	}
	// Storage GET (404) → POST create → validate → apply, in that order.
	want := []string{"cert:GET", "cert:POST", "validate", "apply"}
	if fmt.Sprint(fd.order) != fmt.Sprint(want) {
		t.Errorf("call order = %v, want %v", fd.order, want)
	}
	if fd.storage["star-ltc.pem"] == "" {
		t.Error("cert never reached storage")
	}
}

func TestReconcileCertSecretFallsThroughToConfig(t *testing.T) {
	crt, key := testBundlePEM(t)
	fd := newStorageDataplane(t)
	r, c := newTestReconciler(t, fd.server.URL+"/v3", configSecret(nil), tlsSecret("star-ltc", crt, key))
	r.CertsSecretNames = []string{"star-ltc"}

	// Reconcile the CERT secret — it must push, then drive the config reconcile.
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Namespace: "haproxy-operator", Name: "star-ltc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != RequeueInterval {
		t.Fatalf("expected RequeueInterval, got %v", res.RequeueAfter)
	}
	if fd.validateCalls != 1 || fd.applyCalls != 1 {
		t.Errorf("config reconcile did not follow cert sync: validate=%d apply=%d", fd.validateCalls, fd.applyCalls)
	}

	// The TLS Secret is VSO-owned — the operator must not annotate it.
	s := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "haproxy-operator", Name: "star-ltc"}, s); err != nil {
		t.Fatal(err)
	}
	for k := range s.Annotations {
		if strings.HasPrefix(k, "haproxy.operator/") {
			t.Errorf("operator annotation %q written to a VSO-owned TLS Secret", k)
		}
	}

	// Sync state lives on the config Secret as a JSON map instead.
	cfg := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "haproxy-operator", Name: "haproxy-config"}, cfg); err != nil {
		t.Fatal(err)
	}
	if certSyncState(cfg)["star-ltc"].Hash == "" {
		t.Error("cert-sync state missing from the config Secret annotation")
	}
}

func TestCertSyncSkipsRepushAfterRestart(t *testing.T) {
	crt, key := testBundlePEM(t)
	fd := newStorageDataplane(t)
	r, c := newTestReconciler(t, fd.server.URL+"/v3", configSecret(nil), tlsSecret("star-ltc", crt, key))
	r.CertsSecretNames = []string{"star-ltc"}

	// First reconcile pushes the cert and records state on the config Secret.
	reconcileOnce(t, r)
	pushes := 0
	for _, op := range fd.order {
		if op == "cert:POST" {
			pushes++
		}
	}
	if pushes != 1 {
		t.Fatalf("expected the initial push, order=%v", fd.order)
	}
	before := len(fd.order)

	// A fresh reconciler (simulated restart) sharing the same API state must
	// skip the push: remote serial matches AND the config Secret's cert-sync
	// annotation still holds the bundle hash.
	r2, _ := newTestReconciler(t, fd.server.URL+"/v3")
	r2.Client = c
	r2.CertsSecretNames = []string{"star-ltc"}
	if _, err := r2.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Namespace: "haproxy-operator", Name: "star-ltc"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, op := range fd.order[before:] {
		if op == "cert:POST" || op == "cert:PUT" {
			t.Errorf("unchanged cert was re-pushed after restart: %v", fd.order[before:])
		}
	}
}

func TestCertSyncFailureIsTransientAndSkipsConfig(t *testing.T) {
	crt, key := testBundlePEM(t)
	fd := newStorageDataplane(t)
	fd.certStatus = http.StatusInternalServerError
	r, c := newTestReconciler(t, fd.server.URL+"/v3", configSecret(nil), tlsSecret("star-ltc", crt, key))
	r.CertsSecretNames = []string{"star-ltc"}

	res := reconcileOnce(t, r)
	if res.RequeueAfter != backoffForFailure(1) {
		t.Fatalf("expected backoff, got %v", res.RequeueAfter)
	}
	// Cert push failed → config must not have been validated (never reach a
	// state where the cfg's missing crt gets suppressed as rejected).
	if fd.validateCalls != 0 || fd.applyCalls != 0 {
		t.Errorf("config must not be touched after cert failure: validate=%d apply=%d", fd.validateCalls, fd.applyCalls)
	}
	s := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "haproxy-operator", Name: "haproxy-config"}, s); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Annotations[LastFailedHashAnnotation]; ok {
		t.Error("cert failure must never mark the config hash rejected")
	}
}
