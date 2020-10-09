package reports

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/aquasecurity/starboard/pkg/operator/etc"
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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/aquasecurity/starboard/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	log = ctrl.Log.WithName("store")
)

type StoreInterface interface {
	SaveVulnerabilityReports(ctx context.Context, owner kube.Object, hash string, reports vulnerabilities.WorkloadVulnerabilities) error
	GetVulnerabilityReportsByOwnerAndHash(ctx context.Context, owner kube.Object, hash string) (vulnerabilities.WorkloadVulnerabilities, error)
	HasVulnerabilityReports(ctx context.Context, owner kube.Object, hash string, containerImages kube.ContainerImages) (bool, error)
}

type Store struct {
	client client.Client
	scheme *runtime.Scheme
}

func NewStore(client client.Client, scheme *runtime.Scheme) *Store {
	return &Store{
		client: client,
		scheme: scheme,
	}
}

func (s *Store) SaveVulnerabilityReports(ctx context.Context, workload kube.Object, hash string, reports vulnerabilities.WorkloadVulnerabilities) error {
	owner, err := s.getRuntimeObjectFor(ctx, workload)
	if err != nil {
		return err
	}

	for containerName, report := range reports {
		reportName := fmt.Sprintf("%s-%s-%s", strings.ToLower(string(workload.Kind)),
			workload.Name, containerName)

		vulnerabilityReport := &starboardv1alpha1.VulnerabilityReport{}

		err := s.client.Get(ctx, types.NamespacedName{Name: reportName, Namespace: workload.Namespace}, vulnerabilityReport)
		if errors.IsNotFound(err) {
			vulnerabilityReport = &starboardv1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      reportName,
					Namespace: workload.Namespace,
					Labels: labels.Set{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
						kube.LabelContainerName:     containerName,
						etc.LabelPodSpecHash:        hash,
					},
				},
				Report: report,
			}
			err = controllerutil.SetOwnerReference(owner, vulnerabilityReport, s.scheme)
			if err != nil {
				return err
			}
			log.Info("Creating VulnerabilityReport",
				"report", fmt.Sprintf("%s/%s", workload.Namespace, reportName),
				"hash", hash)
			err := s.client.Create(ctx, vulnerabilityReport)
			if err != nil {
				return err
			}
			return nil
		}

		// Do not modify the object that might be cached.
		cloned := vulnerabilityReport.DeepCopy()
		cloned.Labels[etc.LabelPodSpecHash] = hash
		cloned.Report = report
		log.Info("Updating VulnerabilityReport",
			"report", fmt.Sprintf("%s/%s", workload.Namespace, reportName),
			"hash", hash)
		return s.client.Update(ctx, cloned)
	}
	return nil
}

func (s *Store) GetVulnerabilityReportsByOwnerAndHash(ctx context.Context, workload kube.Object, hash string) (vulnerabilities.WorkloadVulnerabilities, error) {
	vulnerabilityList := &starboardv1alpha1.VulnerabilityReportList{}

	err := s.client.List(ctx, vulnerabilityList, client.MatchingLabels{
		kube.LabelResourceKind:      string(workload.Kind),
		kube.LabelResourceNamespace: workload.Namespace,
		kube.LabelResourceName:      workload.Name,
		etc.LabelPodSpecHash:        hash,
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

func (s *Store) getRuntimeObjectFor(ctx context.Context, workload kube.Object) (metav1.Object, error) {
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

func (s *Store) HasVulnerabilityReports(ctx context.Context, owner kube.Object, hash string, containerImages kube.ContainerImages) (bool, error) {
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
