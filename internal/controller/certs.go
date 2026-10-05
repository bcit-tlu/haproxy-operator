package controller

import (
	"bytes"
	"context"
	"encoding/json"
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

// certSyncEntry is one managed cert's sync record inside CertSyncAnnotation.
type certSyncEntry struct {
	Hash string `json:"hash"`
	Time string `json:"time"`
}

// certSyncState decodes the per-cert sync map off the config Secret
// (nil-secret and malformed JSON both degrade to an empty map).
func certSyncState(s *corev1.Secret) map[string]certSyncEntry {
	out := map[string]certSyncEntry{}
	if s == nil {
		return out
	}
	_ = json.Unmarshal([]byte(s.Annotations[CertSyncAnnotation]), &out)
	return out
}

// syncCertSecret pushes one managed TLS Secret to Dataplane ssl_certificates
// storage. Sync bookkeeping lives on the config Secret (stateSecret) — the
// TLS Secrets are VSO-owned and are never annotated (bcit-tlu/haproxy-operator#43).
// Errors are classified and surfaced by the caller.
func (r *SecretReconciler) syncCertSecret(ctx context.Context, secret, stateSecret *corev1.Secret) error {
	haproxyClient, err := r.getOrCreateClient(ctx)
	if err != nil {
		return err
	}
	changed, err := r.pushCertSecret(ctx, haproxyClient, secret, stateSecret)
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
func (r *SecretReconciler) ensureCertSecretsSynced(ctx context.Context, namespace string, stateSecret *corev1.Secret, haproxyClient *haproxy.Client) error {
	for _, name := range r.CertsSecretNames {
		s := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, s); err != nil {
			return fmt.Errorf("fetch cert secret %q: %w", name, err)
		}
		if _, err := r.pushCertSecret(ctx, haproxyClient, s, stateSecret); err != nil {
			return fmt.Errorf("sync cert secret %q: %w", name, err)
		}
	}
	return nil
}

// pushCertSecret assembles the PEM bundle and writes it to Dataplane storage
// as <secret-name>.pem. The write is skipped only when the remote object
// matches on leaf serial and file size AND the recorded last-pushed bundle
// hash still equals the bundle being offered — either side's signal alone
// can miss a change (same-length chain swaps fool remote metadata; a file
// removed out-of-band fools the annotation).
func (r *SecretReconciler) pushCertSecret(ctx context.Context, haproxyClient *haproxy.Client, secret, stateSecret *corev1.Secret) (bool, error) {
	pemBundle, err := certPEMBundle(secret)
	if err != nil {
		return false, err
	}
	storageName := secret.Name + ".pem"
	hash := config.HashBytes(pemBundle)
	state := certSyncState(stateSecret)
	// The in-memory map mirrors the annotation so an absent config Secret
	// can't force a re-push (and an HAProxy reload) on every cycle.
	previouslySynced := state[secret.Name].Hash == hash || r.certSyncHashes[secret.Name] == hash
	changed, err := haproxyClient.SyncSSLCertificate(ctx, storageName, pemBundle, previouslySynced)
	if err != nil {
		return false, err
	}

	if r.certSyncHashes == nil {
		r.certSyncHashes = map[string]string{}
	}
	r.certSyncHashes[secret.Name] = hash
	if stateSecret != nil && (changed || state[secret.Name].Hash != hash) {
		state[secret.Name] = certSyncEntry{Hash: hash, Time: time.Now().Format(time.RFC3339)}
		raw, merr := json.Marshal(state)
		if merr == nil {
			if perr := r.patchAnnotations(ctx, stateSecret, func(ann map[string]string) {
				ann[CertSyncAnnotation] = string(raw)
			}); perr != nil && !errors.IsConflict(perr) {
				return changed, fmt.Errorf("record cert sync state: %w", perr)
			}
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
