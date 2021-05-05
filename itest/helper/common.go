package helper

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/starboard"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"time"
)

type Helper struct {
	scheme                *runtime.Scheme
	kubeClient            client.Client
	kubeBenchReportReader kubebench.Reader
}

func NewHelper(scheme *runtime.Scheme, client client.Client) *Helper {
	return &Helper{
		scheme:                scheme,
		kubeClient:            client,
		kubeBenchReportReader: kubebench.NewReadWriter(client),
	}
}

func (h *Helper) HasActiveReplicaSet(namespace, name string) func() (bool, error) {
	return func() (bool, error) {
		rs, err := h.GetActiveReplicaSetForDeployment(namespace, name)
		if err != nil {
			return false, err
		}
		return rs != nil, nil
	}
}

func (h *Helper) HasVulnerabilityReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, h.scheme)
		if err != nil {
			return false, err
		}
		var reportList v1alpha1.VulnerabilityReportList
		err = h.kubeClient.List(context.Background(), &reportList, client.MatchingLabels{
			starboard.LabelResourceKind:      gvk.Kind,
			starboard.LabelResourceName:      obj.GetName(),
			starboard.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}
		return len(reportList.Items) == 1, nil
	}
}

func (h *Helper) HasConfigAuditReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, h.scheme)
		if err != nil {
			return false, err
		}
		var reportsList v1alpha1.ConfigAuditReportList
		err = h.kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
			starboard.LabelResourceKind:      gvk.Kind,
			starboard.LabelResourceName:      obj.GetName(),
			starboard.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}

		return len(reportsList.Items) == 1 && reportsList.Items[0].DeletionTimestamp == nil, nil
	}
}

func (h *Helper) DeleteConfigAuditReportOwnedBy(obj client.Object) error {
	gvk, err := apiutil.GVKForObject(obj, h.scheme)
	if err != nil {
		return err
	}
	var reportsList v1alpha1.ConfigAuditReportList
	err = h.kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
		starboard.LabelResourceKind:      gvk.Kind,
		starboard.LabelResourceName:      obj.GetName(),
		starboard.LabelResourceNamespace: obj.GetNamespace(),
	})
	if err != nil {
		return err
	}

	return h.kubeClient.Delete(context.Background(), &reportsList.Items[0])
}

func (h *Helper) GetActiveReplicaSetForDeployment(namespace, name string) (*appsv1.ReplicaSet, error) {
	var deployment appsv1.Deployment
	var replicaSetList appsv1.ReplicaSetList

	err := h.kubeClient.Get(context.TODO(), types.NamespacedName{
		Name: name, Namespace: namespace,
	}, &deployment)
	if err != nil {
		return nil, err
	}

	deploymentSelector, err := metav1.LabelSelectorAsMap(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("mapping label selector: %w", err)
	}
	selector := labels.Set(deploymentSelector)

	err = h.kubeClient.List(context.TODO(), &replicaSetList, client.MatchingLabels(selector))

	if err != nil {
		return nil, err
	}

	for _, replicaSet := range replicaSetList.Items {
		if deployment.Annotations["deployment.kubernetes.io/revision"] !=
			replicaSet.Annotations["deployment.kubernetes.io/revision"] {
			continue
		}
		return replicaSet.DeepCopy(), nil
	}
	return nil, nil
}

func (h *Helper) HasCISKubeBenchReportOwnedBy(node corev1.Node) func() (bool, error) {
	return func() (bool, error) {
		report, err := h.kubeBenchReportReader.FindByOwner(context.Background(), kube.Object{Kind: kube.KindNode, Name: node.Name})
		if err != nil {
			return false, err
		}
		return report != nil, nil
	}
}

func (h *Helper) UpdateDeploymentImage(namespace, name string) error {
	// TODO Check kubectl set image implementation
	return wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		var deployment appsv1.Deployment
		err := h.kubeClient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, &deployment)
		if err != nil {
			return false, err
		}

		dcDeploy := deployment.DeepCopy()
		dcDeploy.Spec.Template.Spec.Containers[0].Image = "wordpress:5"
		err = h.kubeClient.Update(context.TODO(), dcDeploy)
		if err != nil && errors.IsConflict(err) {
			return false, nil
		}

		return err == nil, err
	})
}
