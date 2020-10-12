package main

import (
	"errors"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/starboard"

	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"github.com/aquasecurity/starboard/pkg/operator/controller/job"
	"github.com/aquasecurity/starboard/pkg/operator/controller/pod"

	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/aquasecurity/starboard/pkg/operator/logs"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/aquasecurity/starboard/pkg/operator/aqua"

	"github.com/aquasecurity/starboard/pkg/operator/scanner"
	"github.com/aquasecurity/starboard/pkg/operator/trivy"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/aquasecurity/starboard/pkg/operator/reports"

	starboardv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	batchv1 "k8s.io/api/batch/v1"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// GoReleaser sets three ldflags:
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	versionInfo = starboard.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
)

var (
	scheme   = runtime.NewScheme()
	setupLog = log.Log.WithName("main")
)

func init() {
	_ = corev1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = starboardv1alpha1.AddToScheme(scheme)
}

func main() {
	if err := run(); err != nil {
		setupLog.Error(err, "Unable to run manager")
	}
}

func run() error {
	setupLog.Info("Starting operator", "version", versionInfo)
	config, err := etc.GetOperatorConfig()
	if err != nil {
		return fmt.Errorf("getting operator config: %w", err)
	}

	log.SetLogger(zap.New(zap.UseDevMode(config.Operator.LogDevMode)))

	// Validate configured namespaces to resolve install mode.
	operatorNamespace, err := config.Operator.GetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("getting operator namespace: %w", err)
	}

	targetNamespaces := config.Operator.GetTargetNamespaces()

	installMode, err := config.Operator.GetInstallMode()
	if err != nil {
		return fmt.Errorf("getting install mode: %w", err)
	}
	setupLog.Info("Resolving install mode", "install mode", installMode,
		"operator namespace", operatorNamespace,
		"target namespaces", targetNamespaces)

	// Set the default manager options.
	options := manager.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     config.Operator.MetricsBindAddress,
		HealthProbeBindAddress: config.Operator.HealthProbeBindAddress,
	}

	switch installMode {
	case etc.InstallModeOwnNamespace:
		// Add support for OwnNamespace set in STARBOARD_NAMESPACE (e.g. marketplace) and STARBOARD_TARGET_NAMESPACES (e.g. marketplace)
		setupLog.Info("Constructing single-namespaced cache", "namespace", targetNamespaces[0])
		options.Namespace = targetNamespaces[0]
	case etc.InstallModeSingleNamespace:
		// Add support for SingleNamespace set in STARBOARD_NAMESPACE (e.g. marketplace) and STARBOARD_TARGET_NAMESPACES (e.g. foo)
		cachedNamespaces := append(targetNamespaces, operatorNamespace)
		setupLog.Info("Constructing multi-namespaced cache", "namespaces", cachedNamespaces)
		options.Namespace = targetNamespaces[0]
		options.NewCache = cache.MultiNamespacedCacheBuilder(cachedNamespaces)
	case etc.InstallModeMultiNamespace:
		// Add support for MultiNamespace set in STARBOARD_NAMESPACE (e.g. marketplace) and STARBOARD_TARGET_NAMESPACES (e.g. foo,bar).
		// Note that we may face performance issues when using this with a high number of namespaces.
		// More: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
		cachedNamespaces := append(targetNamespaces, operatorNamespace)
		setupLog.Info("Constructing multi-namespaced cache", "namespaces", cachedNamespaces)
		options.Namespace = ""
		options.NewCache = cache.MultiNamespacedCacheBuilder(cachedNamespaces)
	case etc.InstallModeAllNamespaces:
		// Add support for AllNamespaces set in STARBOARD_NAMESPACE (e.g. marketplace) and STARBOARD_TARGET_NAMESPACES left blank.
		setupLog.Info("Watching all namespaces")
		options.Namespace = ""
	default:
		return fmt.Errorf("unrecognized install mode: %v", installMode)
	}

	kubernetesConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kube client config: %w", err)
	}

	// The only reason we're using kubernetes.Clientset is that we need it to read Pod logs,
	// which is not supported by the client returned by the ctrl.Manager.
	kubernetesClientset, err := kubernetes.NewForConfig(kubernetesConfig)
	if err != nil {
		return fmt.Errorf("constructing kube client: %w", err)
	}

	mgr, err := ctrl.NewManager(kubernetesConfig, options)
	if err != nil {
		return fmt.Errorf("constructing controllers manager: %w", err)
	}

	err = mgr.AddReadyzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	err = mgr.AddHealthzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	scanner, err := getEnabledScanner(config)
	if err != nil {
		return err
	}

	store := reports.NewStore(mgr.GetClient(), scheme)

	if err = (&pod.PodController{
		Config:  config.Operator,
		Client:  mgr.GetClient(),
		Store:   store,
		Scanner: scanner,
		Scheme:  mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create pod controller: %w", err)
	}

	if err = (&job.JobController{
		Config:     config.Operator,
		LogsReader: logs.NewReader(kubernetesClientset),
		Client:     mgr.GetClient(),
		Store:      store,
		Scanner:    scanner,
		Scheme:     mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create job controller: %w", err)
	}

	setupLog.Info("Starting controllers manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}

func getEnabledScanner(config etc.Config) (scanner.VulnerabilityScanner, error) {
	if config.ScannerTrivy.Enabled && config.ScannerAquaCSP.Enabled {
		return nil, fmt.Errorf("invalid configuration: multiple vulnerability scanners enabled")
	}
	if !config.ScannerTrivy.Enabled && !config.ScannerAquaCSP.Enabled {
		return nil, fmt.Errorf("invalid configuration: none vulnerability scanner enabled")
	}
	if config.ScannerTrivy.Enabled {
		setupLog.Info("Using Trivy as vulnerability scanner", "image", config.ScannerTrivy.ImageRef)
		return trivy.NewScanner(config.ScannerTrivy), nil
	}
	if config.ScannerAquaCSP.Enabled {
		setupLog.Info("Using Aqua CSP as vulnerability scanner", "image", config.ScannerAquaCSP.ImageRef)
		return aqua.NewScanner(versionInfo, config.ScannerAquaCSP), nil
	}
	return nil, errors.New("invalid configuration: unhandled vulnerability scanners config")
}
