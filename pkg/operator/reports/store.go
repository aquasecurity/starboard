package reports

import (
	"context"
	"fmt"
	"reflect"

	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	starboardv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	log = ctrl.Log.WithName("store")
)

type StoreInterface interface {
	SaveVulnerabilityReports(ctx context.Context, reports vulnerabilities.WorkloadVulnerabilities, owner kube.Object, hash string) error
	GetVulnerabilityReportsByOwnerAndHash(ctx context.Context, owner kube.Object, hash string) (vulnerabilities.WorkloadVulnerabilities, error)
	HasVulnerabilityReports(ctx context.Context, owner kube.Object, hash string, containerImages kube.ContainerImages) (bool, error)
}

type store struct {
	client client.Client
	scheme *runtime.Scheme
}

func NewStore(client client.Client, scheme *runtime.Scheme) StoreInterface {
	return &store{
		client: client,
		scheme: scheme,
	}
}

func (s *store) SaveVulnerabilityReports(ctx context.Context, reports vulnerabilities.WorkloadVulnerabilities, owner kube.Object, hash string) error {
	ownerObject, err := s.getRuntimeObjectFor(ctx, owner)
	if err != nil {
		return err
	}

	for container, report := range reports {
		err := s.createOrUpdate(ctx, container, report, ownerObject, hash)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *store) createOrUpdate(ctx context.Context, containerName string, report starboardv1alpha1.VulnerabilityScanResult, owner metav1.Object, hash string) error {
	namespace := owner.GetNamespace()

	reportName, err := vulnerabilityreport.NewNameBuilder(s.scheme).
		Owner(owner).
		Container(containerName).Get()

	if err != nil {
		return err
	}

	vulnerabilityReport := starboardv1alpha1.VulnerabilityReport{}

	err = s.client.Get(ctx, types.NamespacedName{Name: reportName, Namespace: namespace}, &vulnerabilityReport)

	if err == nil {
		log.Info("Updating VulnerabilityReport",
			"report", fmt.Sprintf("%s/%s", namespace, reportName),
			"hash", hash)

		// Do not modify the object that might be cached.
		cloned := vulnerabilityReport.DeepCopy()
		cloned.Labels[kube.LabelPodSpecHash] = hash
		cloned.Report = report

		return s.client.Update(ctx, cloned)
	}

	if errors.IsNotFound(err) {
		log.Info("Creating VulnerabilityReport",
			"report", fmt.Sprintf("%s/%s", namespace, reportName),
			"hash", hash)

		vulnerabilityReport, err = vulnerabilityreport.NewBuilder(s.scheme).
			Owner(owner).
			Container(containerName).
			ScanResult(report).
			ReportName(reportName).
			PodSpecHash(hash).Get()

		return s.client.Create(ctx, &vulnerabilityReport)
	}

	return err
}

func (s *store) GetVulnerabilityReportsByOwnerAndHash(ctx context.Context, workload kube.Object, hash string) (vulnerabilities.WorkloadVulnerabilities, error) {
	vulnerabilityList := &starboardv1alpha1.VulnerabilityReportList{}

	err := s.client.List(ctx, vulnerabilityList, client.MatchingLabels{
		kube.LabelResourceKind:      string(workload.Kind),
		kube.LabelResourceNamespace: workload.Namespace,
		kube.LabelResourceName:      workload.Name,
		kube.LabelPodSpecHash:       hash,
	}, client.InNamespace(workload.Namespace))
	if err != nil {
		return nil, err
	}

	reports := make(map[string]starboardv1alpha1.VulnerabilityScanResult)
	for _, item := range vulnerabilityList.Items {
		if container, ok := item.Labels[kube.LabelContainerName]; ok {
			reports[container] = item.Report
		}
	}
	return reports, nil
}

func (s *store) getRuntimeObjectFor(ctx context.Context, workload kube.Object) (metav1.Object, error) {
	var obj runtime.Object
	switch workload.Kind {
	case kube.KindPod:
		obj = &corev1.Pod{}
	case kube.KindReplicaSet:
		obj = &appsv1.ReplicaSet{}
	case kube.KindReplicationController:
		obj = &corev1.ReplicationController{}
	case kube.KindDeployment:
		obj = &appsv1.Deployment{}
	case kube.KindStatefulSet:
		obj = &appsv1.StatefulSet{}
	case kube.KindDaemonSet:
		obj = &appsv1.DaemonSet{}
	case kube.KindCronJob:
		obj = &v1beta1.CronJob{}
	case kube.KindJob:
		obj = &batchv1.Job{}
	default:
		return nil, fmt.Errorf("unknown workload kind: %s", workload.Kind)
	}
	err := s.client.Get(ctx, types.NamespacedName{Name: workload.Name, Namespace: workload.Namespace}, obj)
	if err != nil {
		return nil, err
	}
	return obj.(metav1.Object), nil
}

func (s *store) HasVulnerabilityReports(ctx context.Context, owner kube.Object, hash string, containerImages kube.ContainerImages) (bool, error) {
	vulnerabilityReports, err := s.GetVulnerabilityReportsByOwnerAndHash(ctx, owner, hash)
	if err != nil {
		return false, err
	}

	actual := map[string]bool{}
	for containerName, _ := range vulnerabilityReports {
		actual[containerName] = true
	}

	expected := map[string]bool{}
	for containerName, _ := range containerImages {
		expected[containerName] = true
	}

	return reflect.DeepEqual(actual, expected), nil
}
