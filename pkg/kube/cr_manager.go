package kube

import (
	"context"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

const (
	polarisConfigYAML = `---
checks:
  # reliability
  multipleReplicasForDeployment: ignore
  priorityClassNotSet: ignore
  # resources
  cpuRequestsMissing: warning
  cpuLimitsMissing: warning
  memoryRequestsMissing: warning
  memoryLimitsMissing: warning
  # images
  tagNotSpecified: danger
  pullPolicyNotAlways: ignore
  # healthChecks
  readinessProbeMissing: warning
  livenessProbeMissing: warning
  # networking
  hostNetworkSet: warning
  hostPortSet: warning
  # security
  hostIPCSet: danger
  hostPIDSet: danger
  notReadOnlyRootFilesystem: warning
  privilegeEscalationAllowed: danger
  runAsRootAllowed: warning
  runAsPrivileged: danger
  dangerousCapabilities: danger
  insecureCapabilities: warning
exemptions:
  - controllerNames:
    - kube-apiserver
    - kube-proxy
    - kube-scheduler
    - etcd-manager-events
    - kube-controller-manager
    - kube-dns
    - etcd-manager-main
    rules:
    - hostPortSet
    - hostNetworkSet
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
    - runAsRootAllowed
    - runAsPrivileged
    - notReadOnlyRootFilesystem
    - hostPIDSet
  - controllerNames:
    - kube-flannel-ds
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - notReadOnlyRootFilesystem
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuLimitsMissing
  - controllerNames:
    - cert-manager
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - cluster-autoscaler
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
  - controllerNames:
    - vpa
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - datadog
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - nginx-ingress-controller
    rules:
    - privilegeEscalationAllowed
    - insecureCapabilities
    - runAsRootAllowed
  - controllerNames:
    - dns-controller
    - datadog-datadog
    - kube-flannel-ds
    - kube2iam
    - aws-iam-authenticator
    - datadog
    - kube2iam
    rules:
    - hostNetworkSet
  - controllerNames:
    - aws-iam-authenticator
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - dnsmasq
    - autoscaler
    - kubernetes-dashboard
    - install-cni
    - kube2iam
    rules:
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - runAsRootAllowed
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-controller
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - cert-manager
    - dns-controller
    - kubedns
    - dnsmasq
    - autoscaler
    - insights-agent-goldilocks-vpa-install
    - datadog
    rules:
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
  - controllerNames:
    - kube2iam
    - kube-flannel-ds
    rules:
    - runAsPrivileged
  - controllerNames:
    - kube-hunter
    rules:
    - hostPIDSet
  - controllerNames:
    - polaris
    - kube-hunter
    - goldilocks
    - insights-agent-goldilocks-vpa-install
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - insights-agent-goldilocks-controller
    rules:
    - livenessProbeMissing
    - readinessProbeMissing
  - controllerNames:
    - insights-agent-goldilocks-vpa-install
    - kube-hunter
    rules:
    - runAsRootAllowed
`
)

// TODO This is no longer CRManager as we're creating other resources, such as ClusterRoles and ConfigMaps
// CRManager defined methods for managing Kubernetes custom resources.
type CRManager interface {
	Init(ctx context.Context) error
	Cleanup(ctx context.Context) error
}

type crManager struct {
	clientset    kubernetes.Interface
	clientsetext extapi.ApiextensionsV1beta1Interface
}

// NewCRManager constructs a CRManager with the given Kubernetes interface.
func NewCRManager(clientset kubernetes.Interface, clientsetext extapi.ApiextensionsV1beta1Interface) CRManager {
	return &crManager{
		clientset:    clientset,
		clientsetext: clientsetext,
	}
}

func (m *crManager) Init(ctx context.Context) (err error) {
	err = m.createOrUpdateCRD(ctx, &starboard.VulnerabilitiesCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdateCRD(ctx, &starboard.CISKubeBenchReportCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdateCRD(ctx, &starboard.KubeHunterReportCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdateCRD(ctx, &starboard.ConfigAuditReportCRD)
	if err != nil {
		return
	}
	// TODO We should wait for CRD statuses and make sure that the names were accepted

	err = m.createNamespaceIfNotFound(ctx, NamespaceStarboard)
	if err != nil {
		return
	}

	err = m.initPolaris(ctx)
	return
}

// TODO Move this logic to Polaris scanner structure
func (m *crManager) initPolaris(ctx context.Context) (err error) {
	err = m.createServiceAccountIfNotFound(ctx, ServiceAccountPolaris)
	if err != nil {
		return
	}

	err = m.createConfigMapIfNotFound(ctx, ConfigMapPolaris, map[string]string{
		"config.yaml": polarisConfigYAML,
	})
	if err != nil {
		return
	}

	err = m.createOrUpdateClusterRole(ctx, &rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{
			Name: "starboard-polaris",
		},
		Rules: []rbac.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"nodes",
					"namespaces",
					"pods",
				},
				Verbs: []string{
					"list",
					"get",
				},
			},
			{
				APIGroups: []string{
					"apps",
				},
				Resources: []string{
					"deployments",
					"statefulsets",
					"daemonsets",
					"replicationcontrollers",
					"replicasets",
				},
				Verbs: []string{
					"list",
					"get",
				},
			},
			{
				APIGroups: []string{
					"batch",
				},
				Resources: []string{
					"jobs",
					"cronjobs",
				},
				Verbs: []string{
					"list",
					"get",
				},
			},
		},
	})
	if err != nil {
		return
	}

	err = m.createOrUpdateClusterRoleBinding(ctx, &rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Name: "starboard-polaris",
		},
		RoleRef: rbac.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "starboard-polaris",
		},
		Subjects: []rbac.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ServiceAccountPolaris,
				Namespace: NamespaceStarboard,
			},
		},
	})

	return
}

// TODO Move this logic to Polaris scanner structure
func (m *crManager) cleanupPolaris(ctx context.Context) (err error) {
	klog.V(3).Infof("Deleting ClusterRoleBinding %s", "starboard-polaris")
	err = m.clientset.RbacV1().ClusterRoleBindings().Delete(ctx, "starboard-polaris", meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ClusterRole: %s", "starboard-polars")
	err = m.clientset.RbacV1().ClusterRoles().Delete(ctx, "starboard-polaris", meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ServiceAccount %s/%s", NamespaceStarboard, ServiceAccountPolaris)
	err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Delete(ctx, ServiceAccountPolaris, meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ConfigMap %s/%s", NamespaceStarboard, ConfigMapPolaris)
	err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Delete(ctx, ConfigMapPolaris, meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	return nil
}

func (m *crManager) createNamespaceIfNotFound(ctx context.Context, name string) (err error) {
	_, err = m.clientset.CoreV1().Namespaces().Get(ctx, name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Namespace %s already exists", name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating namespace %s", name)
		_, err = m.clientset.CoreV1().Namespaces().Create(ctx, &core.Namespace{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
		}, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createServiceAccountIfNotFound(ctx context.Context, name string) (err error) {
	_, err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Get(ctx, name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("ServiceAccount %s already exists", name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ServiceAccount %s", name)
		_, err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Create(ctx, &core.ServiceAccount{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
		}, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createConfigMapIfNotFound(ctx context.Context, name string, data map[string]string) (err error) {
	_, err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Get(ctx, name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("ConfigMap %s already exists", name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ConfigMap %s", name)
		_, err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Create(ctx, &core.ConfigMap{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
			Data: data,
		}, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createOrUpdateClusterRole(ctx context.Context, cr *rbac.ClusterRole) (err error) {
	existingRole, err := m.clientset.RbacV1().ClusterRoles().Get(ctx, cr.GetName(), meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRole %s", cr.GetName())
		deepCopy := existingRole.DeepCopy()
		deepCopy.Rules = cr.Rules
		_, err = m.clientset.RbacV1().ClusterRoles().Update(ctx, deepCopy, meta.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRole %s", cr.GetName())
		_, err = m.clientset.RbacV1().ClusterRoles().Create(ctx, cr, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createOrUpdateClusterRoleBinding(ctx context.Context, crb *rbac.ClusterRoleBinding) (err error) {
	existingBinding, err := m.clientset.RbacV1().ClusterRoleBindings().Get(ctx, crb.Name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRoleBinding %s", crb.GetName())
		deepCopy := existingBinding.DeepCopy()
		deepCopy.RoleRef = crb.RoleRef
		deepCopy.Subjects = crb.Subjects
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Update(ctx, deepCopy, meta.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRoleBinding %s", crb.GetName())
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createOrUpdateCRD(ctx context.Context, crd *ext.CustomResourceDefinition) (err error) {
	existingCRD, err := m.clientsetext.CustomResourceDefinitions().Get(ctx, crd.Name, meta.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating CRD: %s", crd.Name)
		deepCopy := existingCRD.DeepCopy()
		deepCopy.Spec = crd.Spec
		_, err = m.clientsetext.CustomResourceDefinitions().Update(ctx, deepCopy, meta.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating CRD: %s", crd.Name)
		_, err = m.clientsetext.CustomResourceDefinitions().Create(ctx, crd, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) deleteCRD(ctx context.Context, name string) (err error) {
	klog.V(3).Infof("Deleting CRD: %s", name)
	err = m.clientsetext.CustomResourceDefinitions().Delete(ctx, name, meta.DeleteOptions{})
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	return
}

func (m *crManager) Cleanup(ctx context.Context) (err error) {
	err = m.deleteCRD(ctx, starboard.VulnerabilitiesCRName)
	if err != nil {
		return
	}
	err = m.deleteCRD(ctx, starboard.CISKubeBenchReportCRName)
	if err != nil {
		return
	}
	err = m.deleteCRD(ctx, starboard.KubeHunterReportCRName)
	if err != nil {
		return
	}
	err = m.deleteCRD(ctx, starboard.ConfigAuditReportCRName)
	if err != nil {
		return
	}
	err = m.cleanupPolaris(ctx)
	if err != nil {
		return
	}
	return
}
