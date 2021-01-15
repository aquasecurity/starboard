package operator

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/config"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/operator/controller"
	"github.com/aquasecurity/starboard/pkg/operator/controller/job"
	"github.com/aquasecurity/starboard/pkg/operator/controller/pod"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/logs"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	setupLog = log.Log.WithName("operator")
)

func Run(buildInfo starboard.BuildInfo, operatorConfig etc.Config) error {
	setupLog.Info("Starting operator", "buildInfo", buildInfo)

	// Validate configured namespaces to resolve install mode.
	operatorNamespace, err := operatorConfig.GetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("getting operator namespace: %w", err)
	}

	targetNamespaces := operatorConfig.GetTargetNamespaces()

	installMode, err := operatorConfig.GetInstallMode()
	if err != nil {
		return fmt.Errorf("getting install mode: %w", err)
	}
	setupLog.Info("Resolving install mode", "install mode", installMode,
		"operator namespace", operatorNamespace,
		"target namespaces", targetNamespaces)

	// Set the default manager options.
	options := manager.Options{
		Scheme:                 starboard.NewScheme(),
		MetricsBindAddress:     operatorConfig.MetricsBindAddress,
		HealthProbeBindAddress: operatorConfig.HealthProbeBindAddress,
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

	configManager := starboard.NewConfigManager(kubernetesClientset, operatorNamespace)
	err = configManager.EnsureDefault(context.Background())
	if err != nil {
		return err
	}

	starboardConfig, err := configManager.Read(context.Background())
	if err != nil {
		return err
	}

	store := vulnerabilityreport.NewControllerRuntimeReadWriter(mgr.GetClient(), mgr.GetScheme())
	idGenerator := ext.NewGoogleUUIDGenerator()

	scanner, err := config.GetVulnerabilityReportPlugin(buildInfo, starboardConfig)
	if err != nil {
		return err
	}

	analyzer := controller.NewAnalyzer(operatorConfig,
		store,
		mgr.GetClient())

	reconciler := controller.NewReconciler(mgr.GetScheme(),
		operatorConfig,
		mgr.GetClient(),
		store,
		idGenerator,
		scanner,
		logs.NewReader(kubernetesClientset))

	if err = (&pod.PodController{
		Config:     operatorConfig,
		Client:     mgr.GetClient(),
		Analyzer:   analyzer,
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create pod controller: %w", err)
	}

	if err = (&job.JobController{
		Config:     operatorConfig,
		Client:     mgr.GetClient(),
		Analyzer:   analyzer,
		Reconciler: reconciler,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create job controller: %w", err)
	}

	setupLog.Info("Starting controllers manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}
