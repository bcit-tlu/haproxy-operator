package main

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/bcit-tlu/haproxy-operator/internal/controller"
	"github.com/bcit-tlu/haproxy-operator/internal/haproxy"
	"github.com/bcit-tlu/haproxy-operator/internal/local"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func main() {
	var (
		mode                 string
		metricsAddr          string
		enableLeaderElection bool
		probeAddr            string
		watchNamespace       string
		secretName           string
		secretKey            string
		localConfigPath      string
		localWatch           bool
		localPoll            time.Duration
		dataplaneURL         string
		dataplaneCACert      string
		dataplaneClientCert  string
		dataplaneClientKey   string
		dataplaneUsername    string
		dataplanePassword    string
		dataplaneInsecure    bool
		spireSocketPath      string
	)

	flag.StringVar(&mode, "mode", envOr("MODE", "k8s"), "Run mode: k8s or local")
	flag.StringVar(&metricsAddr, "metrics-bind-address", envOr("METRICS_ADDR", ":9090"), "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", envOr("PROBE_ADDR", ":8081"), "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", envOr("LEADER_ELECT", "") == "true",
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&watchNamespace, "namespace", envOr("WATCH_NAMESPACE", ""),
		"Namespace to watch for Secrets.")
	flag.StringVar(&secretName, "secret-name", envOr("SECRET_NAME", ""),
		"Name of the Secret containing the haproxy.cfg")
	flag.StringVar(&secretKey, "secret-key", envOr("SECRET_KEY", "haproxy.cfg"),
		"Key in the Secret containing the haproxy.cfg")
	flag.StringVar(&localConfigPath, "local-config-path", envOr("LOCAL_CONFIG_PATH", ""),
		"Path to haproxy.cfg to apply in local mode")
	flag.BoolVar(&localWatch, "local-watch", envOr("LOCAL_WATCH", "true") == "true",
		"Watch local config file for changes in local mode")
	flag.DurationVar(&localPoll, "local-poll", 5*time.Second,
		"Polling interval for local mode")

	flag.StringVar(&dataplaneURL, "dataplane-url", envOr("DATAPLANE_URL", "https://haproxy:5555/v3"), "HAProxy Data Plane API base URL")
	flag.StringVar(&dataplaneCACert, "dataplane-ca-cert", envOr("DATAPLANE_CA_CERT", ""), "Path to Data Plane API CA certificate (mTLS)")
	flag.StringVar(&dataplaneClientCert, "dataplane-client-cert", envOr("DATAPLANE_CLIENT_CERT", ""), "Path to Data Plane API client certificate (mTLS)")
	flag.StringVar(&dataplaneClientKey, "dataplane-client-key", envOr("DATAPLANE_CLIENT_KEY", ""), "Path to Data Plane API client key (mTLS)")
	flag.StringVar(&dataplaneUsername, "dataplane-username", envOr("DATAPLANE_USERNAME", ""), "Data Plane API basic auth username")
	flag.StringVar(&dataplanePassword, "dataplane-password", envOr("DATAPLANE_PASSWORD", ""), "Data Plane API basic auth password")
	flag.BoolVar(&dataplaneInsecure, "dataplane-insecure", envOr("DATAPLANE_INSECURE", "") == "true", "Skip Data Plane API TLS verification (not recommended)")
	flag.StringVar(&spireSocketPath, "spire-socket", envOr("SPIRE_AGENT_SOCKET", ""), "SPIRE Agent Workload API socket path (unix:///run/spire/agent.sock)")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if mode == "k8s" {
		if watchNamespace == "" {
			watchNamespace = "haproxy-operator"
		}
		if secretName == "" {
			secretName = "haproxy-config"
		}
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if mode == "local" {
		if localConfigPath == "" {
			setupLog.Error(nil, "local-config-path is required in local mode")
			os.Exit(1)
		}
		if dataplaneURL == "https://haproxy:5555/v3" {
			dataplaneURL = "http://haproxy:5555/v3"
			dataplaneCACert = ""
			dataplaneClientCert = ""
			dataplaneClientKey = ""
		}

		haproxyClient, err := haproxy.NewClient(haproxy.APIConfig{
			BaseURL:        dataplaneURL,
			CACertPath:     dataplaneCACert,
			ClientCertPath: dataplaneClientCert,
			ClientKeyPath:  dataplaneClientKey,
			Username:       dataplaneUsername,
			Password:       dataplanePassword,
			Insecure:       dataplaneInsecure,
		})
		if err != nil {
			setupLog.Error(err, "failed to create dataplane client")
			os.Exit(1)
		}

		runner := &local.Runner{
			CfgPath:   localConfigPath,
			Client:    haproxyClient,
			PollEvery: localPoll,
			Watch:     localWatch,
		}

		ctx := ctrl.SetupSignalHandler()
		if err := runner.Run(ctx); err != nil && err != context.Canceled {
			setupLog.Error(err, "local runner exited with error")
			os.Exit(1)
		}
		return
	}

	setupLog.Info("starting haproxy-operator",
		"mode", mode,
		"namespace", watchNamespace,
		"secretName", secretName,
		"secretKey", secretKey,
		"dataplaneURL", dataplaneURL,
		"spireSocket", spireSocketPath,
	)

	var cacheOpts cache.Options
	if watchNamespace != "" {
		cacheOpts = cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				watchNamespace: {},
			},
		}
	}

	mgr, err := ctrl.NewManager(loadRESTConfig(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "haproxy-operator.tlu.bcit.ca",
		Cache:                  cacheOpts,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.SecretReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		SecretName:      secretName,
		SecretKey:       secretKey,
		SpireSocketPath: spireSocketPath,
		APIConfig: haproxy.APIConfig{
			BaseURL:        dataplaneURL,
			CACertPath:     dataplaneCACert,
			ClientCertPath: dataplaneClientCert,
			ClientKeyPath:  dataplaneClientKey,
			Username:       dataplaneUsername,
			Password:       dataplanePassword,
			Insecure:       dataplaneInsecure,
		},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Secret")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func loadRESTConfig() *rest.Config {
	override := envOr("KUBE_APISERVER", "")
	kubeconfig := envOr("KUBECONFIG", "")
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags(override, kubeconfig)
		if err != nil {
			setupLog.Error(err, "unable to build rest config", "apiserver", override, "kubeconfig", kubeconfig)
			os.Exit(1)
		}
		return cfg
	}
	if override == "" {
		return ctrl.GetConfigOrDie()
	}

	cfg, err := clientcmd.BuildConfigFromFlags(override, kubeconfig)
	if err != nil {
		setupLog.Error(err, "unable to build rest config", "apiserver", override, "kubeconfig", kubeconfig)
		os.Exit(1)
	}
	return cfg
}
