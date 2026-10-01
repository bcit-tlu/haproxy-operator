package controller

import (
	"bytes"
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bcit-tlu/haproxy-operator/internal/config"
	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
	"github.com/bcit-tlu/haproxy-operator/internal/status"
)

// syncCertSecret pushes one managed TLS Secret to Dataplane ssl_certificates
// storage and records the pushed bundle hash on the Secret. Errors are
// classified and surfaced by the caller.
func (r *SecretReconciler) syncCertSecret(ctx context.Context, secret *corev1.Secret) error {
	haproxyClient, err := r.getOrCreateClient(ctx)
	if err != nil {
		return err
	}
	changed, err := r.pushCertSecret(ctx, haproxyClient, secret)
	if err != nil {
		return err
	}
	if changed {
		status.EmitEvent(r.Recorder, secret, status.CertSynced, "pushed "+secret.Name+".pem to Dataplane ssl_certificates storage")
	}
	return nil
}

// ensureCertSecretsSynced pushes every managed TLS Secret ahead of config
// validation — the dataplane validation run parses `crt` paths against the
// gateway filesystem, so referenced certs must already exist there.
func (r *SecretReconciler) ensureCertSecretsSynced(ctx context.Context, namespace string, haproxyClient *haproxy.Client) error {
	for _, name := range r.CertsSecretNames {
		s := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, s); err != nil {
			return fmt.Errorf("fetch cert secret %q: %w", name, err)
		}
		if _, err := r.pushCertSecret(ctx, haproxyClient, s); err != nil {
			return fmt.Errorf("sync cert secret %q: %w", name, err)
		}
	}
	return nil
}

// pushCertSecret assembles the PEM bundle and writes it to Dataplane storage
// as <secret-name>.pem, skipping the write when the stored leaf fingerprint
// already matches. The pushed hash is annotated on the Secret for
// observability; the remote fingerprint check — not the annotation — decides
// whether a write is needed, so a file removed out-of-band is re-pushed.
func (r *SecretReconciler) pushCertSecret(ctx context.Context, haproxyClient *haproxy.Client, secret *corev1.Secret) (bool, error) {
	pemBundle, err := certPEMBundle(secret)
	if err != nil {
		return false, err
	}
	storageName := secret.Name + ".pem"
	changed, err := haproxyClient.SyncSSLCertificate(ctx, storageName, pemBundle)
	if err != nil {
		return false, err
	}

	hash := config.HashBytes(pemBundle)
	if changed || secret.Annotations[LastSyncedCertHashAnnotation] != hash {
		if perr := r.patchAnnotations(ctx, secret, func(ann map[string]string) {
			ann[LastSyncedCertHashAnnotation] = hash
			ann["haproxy.operator/last-synced-cert-time"] = time.Now().Format(time.RFC3339)
		}); perr != nil && !errors.IsConflict(perr) {
			return changed, fmt.Errorf("record cert sync state: %w", perr)
		}
	}
	log.FromContext(ctx).Info("certificate secret synced", "secret", secret.Name, "storage", storageName, "changed", changed)
	return changed, nil
}

// certPEMBundle assembles an HAProxy-ready PEM from a kubernetes.io/tls
// Secret: leaf+intermediates (tls.crt, then an optional explicit ca.crt
// chain) followed by the private key.
func certPEMBundle(secret *corev1.Secret) ([]byte, error) {
	crt := bytes.TrimSpace(secret.Data["tls.crt"])
	key := bytes.TrimSpace(secret.Data["tls.key"])
	if len(crt) == 0 || len(key) == 0 {
		return nil, fmt.Errorf("secret %s must contain tls.crt and tls.key", secret.Name)
	}
	var b bytes.Buffer
	b.Write(crt)
	b.WriteByte('\n')
	if ca := bytes.TrimSpace(secret.Data["ca.crt"]); len(ca) > 0 {
		b.Write(ca)
		b.WriteByte('\n')
	}
	b.Write(key)
	b.WriteByte('\n')
	return b.Bytes(), nil
}
