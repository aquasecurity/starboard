package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

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
	PolicyGroup            = "policy"
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
	ClusterRoleBindings    = "clusterrolebindings"
	ClusterRoles           = "clusterroles"
	PodSecurityPolicy      = "podsecuritypolicys"
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

func getObjectsRef(ctx context.Context, client dynamic.Interface, namespace string, gvrs []schema.GroupVersionResource) ([]kube.ObjectRef, error) {
	ObjRefs := make([]kube.ObjectRef, 0)
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

func checkScanningErrors(scanErr chan error) error {
	close(scanErr)
	if len(scanErr) != 0 {
		for e := range scanErr {
			return e
		}
	}
	return nil
}

func printScannerReports(cmd *cobra.Command, outWriter io.Writer, reportChan chan runtime.Object) error {
	printer, err := getPrinter(cmd)
	if err != nil {
		return err
	}
	close(reportChan)
	for cReport := range reportChan {
		err := printer.PrintObj(cReport, outWriter)
		if err != nil {
			return err
		}

	}
	return nil
}
