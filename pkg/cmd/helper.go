package cmd

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/plugin"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"go.uber.org/multierr"
	_ "go.uber.org/multierr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/cheggaaa/pb"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/kubernetes/pkg/printers"
)

const (
	AppsGroup              = "apps"
	CoreGroup              = "cores"
	BatchGroup             = "batch"
	RbacGroup              = "rbac"
	NetworkingGroup        = "networking"
	V1Version              = "v1"
	V1beta1Version         = "v1Beta1"
	Deployments            = "deployments"
	ReplicaSets            = "replicasets"
	ReplicationControllers = "replicationcontrollers"
	StatefulSets           = "statefulsets"
	DaemonSets             = "daemonsets"
	CronJobs               = "cronjobs"
	Services               = "services"
	Jobs                   = "jobs"
	Pods                   = "pods"
	ConfigMaps             = "configmaps"
	Roles                  = "roles"
	RoleBindings           = "rolebindings"
	NetworkPolicys         = "networkpolicy"
	Ingresss               = "ingresss"
	ResourceQuotas         = "resourceQuotas"
	LimitRanges            = "limitranges"
)

func getNamespaceGVR() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: Deployments,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: Pods,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: ReplicaSets,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: ReplicationControllers,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: StatefulSets,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: DaemonSets,
		},
		{
			Version:  V1beta1Version,
			Group:    BatchGroup,
			Resource: CronJobs,
		},
		{
			Version:  V1Version,
			Group:    BatchGroup,
			Resource: Jobs,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: Services,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: ConfigMaps,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: Roles,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: RoleBindings,
		},
		{
			Version:  V1Version,
			Group:    NetworkingGroup,
			Resource: NetworkPolicys,
		},
		{
			Version:  V1Version,
			Group:    NetworkingGroup,
			Resource: Ingresss,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: ResourceQuotas,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: LimitRanges,
		},
	}
}

func getObjectsRef(ctx context.Context, inConfig *rest.Config, namespace string, gvrs []schema.GroupVersionResource) ([]kube.ObjectRef, error) {
	ObjRefs := make([]kube.ObjectRef, 0)
	client, err := dynamic.NewForConfig(inConfig)
	if err != nil {
		return nil, err
	}
	for _, gvr := range gvrs {
		var dclient dynamic.ResourceInterface
		if len(namespace) == 0 {
			dclient = client.Resource(gvr)
		} else {
			dclient = client.Resource(gvr).Namespace(namespace)
		}
		objectList, err := dclient.List(ctx, metav1.ListOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		for _, item := range objectList.Items {
			ObjRefs = append(ObjRefs, kube.ObjectRef{Namespace: namespace, Kind: kube.Kind(item.GetKind()), Name: item.GetName()})
		}
	}
	return ObjRefs, nil
}

func getWorkloadObjectRef(allResources []kube.ObjectRef) []kube.ObjectRef {
	workloads := make([]kube.ObjectRef, 0)
	for _, resource := range allResources {
		if kube.IsWorkload(string(resource.Kind)) {
			workloads = append(workloads, resource)
		}
	}
	return workloads
}

func getProgressBar(size int, title string, cmd *cobra.Command) Bar {
	silent := cmd.Flag("silent").Value.String()
	if silent == "true" {
		return &DummyProgressBar{}
	}
	return pb.New(size).SetRefreshRate(time.Second).SetWidth(80).SetMaxWidth(80).Prefix(fmt.Sprintf("Scanning %s...", title)).Start()
}

type Bar interface {
	Add(add int) int
	Finish()
}
type DummyProgressBar struct {
}

func (dm DummyProgressBar) Add(add int) int {
	// do nothing
	return 0
}

func (dm DummyProgressBar) Finish() {
	// do nothing
}

func getPrinter(cmd *cobra.Command) (printers.ResourcePrinter, error) {
	format := cmd.Flag("output").Value.String()
	var printer printers.ResourcePrinter

	switch format {
	case "yaml", "json":
		printer, err := genericclioptions.NewPrintFlags("").
			WithTypeSetter(starboard.NewScheme()).
			WithDefaultOutput(format).
			ToPrinter()
		if err != nil {
			return nil, err
		}
		return printer, nil
	case "":
		printer = printers.NewTablePrinter()
		return printer, nil
	default:
		return nil, fmt.Errorf("invalid output format %q, allowed formats are: yaml,json", format)
	}
}

func checkScanningErrors(errChan <-chan error) error {
	scanErr := make([]error, 0)
	if len(errChan) != 0 {
		for e := range errChan {
			scanErr = append(scanErr, e)
		}
		return multierr.Combine(scanErr...)
	}
	return nil
}

func printScannerReports(cmd *cobra.Command, outWriter io.Writer, reportChan <-chan runtime.Object) error {
	printer, err := getPrinter(cmd)
	if err != nil {
		return err
	}
	for cReport := range reportChan {
		err := printer.PrintObj(cReport, outWriter)
		if err != nil {
			return err
		}

	}
	return nil
}

func ExecuteChecks(scanFuncs []func() (runtime.Object, error)) (chan runtime.Object, chan error) {
	errChan := make(chan error, len(scanFuncs))
	reportChan := make(chan runtime.Object, len(scanFuncs))
	var wg sync.WaitGroup
	wg.Add(len(scanFuncs))
	for _, sf := range scanFuncs {
		go Work(&wg, errChan, reportChan, sf)
	}
	wg.Wait()
	close(reportChan)
	close(errChan)
	return reportChan, errChan
}

func Work(wg *sync.WaitGroup, scanErr chan<- error, reportChan chan<- runtime.Object, scanFuncs func() (runtime.Object, error)) {
	func(errChan chan<- error, reportChan chan<- runtime.Object) {
		defer wg.Done()
		reports, err := scanFuncs()
		if err != nil {
			errChan <- err
			return
		}
		reportChan <- reports
	}(scanErr, reportChan)
}

func ScanVulnerabilities(ctx context.Context, workloads []kube.ObjectRef, cmd *cobra.Command, vulnerabilityScanner *vulnerabilityreport.Scanner) func() (runtime.Object, error) {
	return func() (runtime.Object, error) {
		bar := getProgressBar(len(workloads), "Vulnerabilities", cmd)
		list := &v1alpha1.VulnerabilityReportList{
			Items: []v1alpha1.VulnerabilityReport{},
		}
		for _, workload := range workloads {
			bar.Add(1)
			reports, err := vulnerabilityScanner.Scan(ctx, workload)
			if err != nil {
				return nil, err
			}
			for _, report := range reports {
				list.Items = append(list.Items, report)
			}
		}
		bar.Finish()
		return list, nil
	}
}

func ScanResourceConfig(ctx context.Context, allResources []kube.ObjectRef, cmd *cobra.Command, configScanner *configauditreport.Scanner) func() (runtime.Object, error) {
	return func() (runtime.Object, error) {
		bar := getProgressBar(len(allResources), "Resource Config", cmd)
		list := &v1alpha1.ConfigAuditReportList{
			Items: []v1alpha1.ConfigAuditReport{},
		}
		for _, resource := range allResources {
			bar.Add(1)
			reportBuilder, err := configScanner.Scan(ctx, resource)
			report, err := reportBuilder.GetReport()
			if err != nil {
				return nil, err
			}
			list.Items = append(list.Items, report)
		}
		bar.Finish()
		return list, nil
	}
}

func getVulnerabilityScanner(ctx context.Context, cmd *cobra.Command, kubeConfig *rest.Config, buildInfo starboard.BuildInfo, kubeClient client.Client) (*vulnerabilityreport.Scanner, error) {
	kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
	config, err := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName).Read(ctx)
	if err != nil {
		return nil, err
	}
	opts, err := getScannerOpts(cmd)
	if err != nil {
		return nil, err
	}
	plugin, pluginContext, err := plugin.NewResolver().
		WithBuildInfo(buildInfo).
		WithNamespace(starboard.NamespaceName).
		WithServiceAccountName(starboard.ServiceAccountName).
		WithConfig(config).
		WithClient(kubeClient).
		GetVulnerabilityPlugin()
	if err != nil {
		return nil, err
	}
	scanner := vulnerabilityreport.NewScanner(kubeClientset, kubeClient, plugin, pluginContext, config, opts)
	return scanner, nil
}
