// Package metrics exposes Prometheus counters/gauges for the operator's
// reconciliation lifecycle on the controller-runtime metrics registry.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ReconcileAttempts counts validation/apply attempts by phase.
	ReconcileAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "haproxy_operator_reconcile_attempts_total",
			Help: "Total reconcile phases attempted (validate, apply).",
		},
		[]string{"phase"},
	)

	// ReconcileResults counts terminal outcomes: applied, rejected,
	// transient (retryable), auth, tls, conflict, error.
	ReconcileResults = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "haproxy_operator_reconcile_results_total",
			Help: "Terminal reconcile outcomes by class.",
		},
		[]string{"class"},
	)

	// TransientErrors counts retryable failures by error class so flaky
	// Dataplane/network conditions are visible independent of rejections.
	TransientErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "haproxy_operator_transient_errors_total",
			Help: "Transient Dataplane/transport failures by class.",
		},
		[]string{"class"},
	)

	// ConfigHash records the last-seen desired hash and its state
	// (applied|rejected) — series are replaced on each state change.
	ConfigHash = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "haproxy_operator_config_hash",
			Help: "SHA256 of the last reconciled desired config by state.",
		},
		[]string{"hash", "state"},
	)

	// LastSuccessfulApply is the Unix timestamp of the last successful apply.
	LastSuccessfulApply = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "haproxy_operator_last_successful_apply_timestamp_seconds",
			Help: "Unix timestamp of the last successful configuration apply.",
		},
	)

	// DataplaneServerCertExpiry is the NotAfter of the Dataplane API server
	// leaf observed on the latest TLS handshake, by gateway hostname.
	DataplaneServerCertExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "haproxy_operator_dataplane_server_cert_expiry_timestamp_seconds",
			Help: "Unix expiry timestamp of the Dataplane API server certificate last seen on the mTLS handshake.",
		},
		[]string{"gateway"},
	)

	// DataplaneClientCertExpiry is the NotAfter of the operator's Dataplane
	// client leaf parsed from the mounted certificate file (VSO rotates the
	// file in place).
	DataplaneClientCertExpiry = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "haproxy_operator_dataplane_client_cert_expiry_timestamp_seconds",
			Help: "Unix expiry timestamp of the operator's Dataplane API client certificate file.",
		},
	)

	// ConfigDrift counts periodic-requeue checks that found the gateway's
	// live raw config diverged from the last-observed applied config.
	ConfigDrift = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "haproxy_operator_config_drift_total",
			Help: "Total drift detections: live gateway config differed from the last-observed applied config.",
		},
		[]string{"secret"},
	)

	// ConfigInSync is 1 while the live gateway config matches the
	// last-observed applied config, 0 after drift is detected.
	ConfigInSync = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "haproxy_operator_config_in_sync",
			Help: "Whether the gateway's live config matches the last-observed applied config (1) or has drifted (0).",
		},
		[]string{"secret"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		ReconcileAttempts,
		ReconcileResults,
		TransientErrors,
		ConfigHash,
		LastSuccessfulApply,
		DataplaneServerCertExpiry,
		DataplaneClientCertExpiry,
		ConfigDrift,
		ConfigInSync,
	)
}
