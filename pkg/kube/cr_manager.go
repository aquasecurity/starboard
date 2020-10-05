package kube

import (
	"context"
	"fmt"
	"time"

	"k8s.io/utils/pointer"

	"k8s.io/apimachinery/pkg/labels"

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
	clusterRoleStarboard        = "starboard"
	clusterRoleBindingStarboard = "starboard"
)

const (
	polarisConfigYAML = `checks:
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

var (
	namespace = &core.Namespace{
		ObjectMeta: meta.ObjectMeta{
			Name: NamespaceStarboard,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
	}
	serviceAccount = &core.ServiceAccount{
		ObjectMeta: meta.ObjectMeta{
			Name: ServiceAccountStarboard,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
		AutomountServiceAccountToken: pointer.BoolPtr(false),
	}
	configMap = &core.ConfigMap{
		ObjectMeta: meta.ObjectMeta{
			Name: ConfigMapStarboard,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
		Data: map[string]string{
			"trivy.severity":      "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			"trivy.imageRef":      "docker.io/aquasec/trivy:0.9.1",
			"polaris.config.yaml": polarisConfigYAML,
		},
	}
	clusterRole = &rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{
			Name: clusterRoleStarboard,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
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
	}
	clusterRoleBinding = &rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Name: clusterRoleBindingStarboard,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
		RoleRef: rbac.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRoleStarboard,
		},
		Subjects: []rbac.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ServiceAccountStarboard,
				Namespace: NamespaceStarboard,
			},
		},
	}
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
	err = m.createOrUpdateCRD(ctx, &starboard.VulnerabilityReportsCRD)
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

	err = m.createNamespaceIfNotFound(ctx, namespace)
	if err != nil {
		return
	}

	err = m.createConfigMapIfNotFound(ctx, configMap)
	if err != nil {
		return
	}

	err = m.initRBAC(ctx)
	return
}

func (m *crManager) initRBAC(ctx context.Context) (err error) {
	err = m.createServiceAccountIfNotFound(ctx, serviceAccount)
	if err != nil {
		return
	}

	err = m.createOrUpdateClusterRole(ctx, clusterRole)
	if err != nil {
		return
	}

	err = m.createOrUpdateClusterRoleBinding(ctx, clusterRoleBinding)

	return
}

func (m *crManager) cleanupRBAC(ctx context.Context) (err error) {
	klog.V(3).Infof("Deleting ClusterRoleBinding %q", clusterRoleBindingStarboard)
	err = m.clientset.RbacV1().ClusterRoleBindings().Delete(ctx, clusterRoleBindingStarboard, meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ClusterRole %q", clusterRoleStarboard)
	err = m.clientset.RbacV1().ClusterRoles().Delete(ctx, clusterRoleStarboard, meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ServiceAccount %q", NamespaceStarboard+"/"+ServiceAccountStarboard)
	err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Delete(ctx, ServiceAccountStarboard, meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	return nil
}

var (
	cleanupPollingInterval = 2 * time.Second
	cleanupTimeout         = 30 * time.Second
)

func (m *crManager) cleanupNamespace(ctx context.Context) error {
	klog.V(3).Infof("Deleting Namespace %q", NamespaceStarboard)
	err := m.clientset.CoreV1().Namespaces().Delete(ctx, NamespaceStarboard, meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	for {
		select {
		// This case controls the polling interval
		case <-time.After(cleanupPollingInterval):
			_, err := m.clientset.CoreV1().Namespaces().Get(ctx, NamespaceStarboard, meta.GetOptions{})
			if errors.IsNotFound(err) {
				klog.V(3).Infof("Deleted Namespace %q", NamespaceStarboard)
				return nil
			}
		// This case caters for polling timeout
		case <-time.After(cleanupTimeout):
			return fmt.Errorf("deleting namespace timed out")
		}
	}
}

func (m *crManager) createNamespaceIfNotFound(ctx context.Context, ns *core.Namespace) (err error) {
	_, err = m.clientset.CoreV1().Namespaces().Get(ctx, ns.Name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Namespace %q already exists", ns.Name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating Namespace %q", ns.Name)
		_, err = m.clientset.CoreV1().Namespaces().Create(ctx, ns, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createServiceAccountIfNotFound(ctx context.Context, sa *core.ServiceAccount) (err error) {
	name := sa.Name
	_, err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Get(ctx, name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("ServiceAccount %q already exists", NamespaceStarboard+"/"+name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ServiceAccount %q", NamespaceStarboard+"/"+name)
		_, err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Create(ctx, sa, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createConfigMapIfNotFound(ctx context.Context, cm *core.ConfigMap) (err error) {
	name := cm.Name
	_, err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Get(ctx, name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("ConfigMap %q already exists", NamespaceStarboard+"/"+name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ConfigMap %q", NamespaceStarboard+"/"+name)
		_, err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Create(ctx, cm, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createOrUpdateClusterRole(ctx context.Context, cr *rbac.ClusterRole) (err error) {
	existingRole, err := m.clientset.RbacV1().ClusterRoles().Get(ctx, cr.GetName(), meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRole %q", cr.GetName())
		deepCopy := existingRole.DeepCopy()
		deepCopy.Rules = cr.Rules
		_, err = m.clientset.RbacV1().ClusterRoles().Update(ctx, deepCopy, meta.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRole %q", cr.GetName())
		_, err = m.clientset.RbacV1().ClusterRoles().Create(ctx, cr, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createOrUpdateClusterRoleBinding(ctx context.Context, crb *rbac.ClusterRoleBinding) (err error) {
	existingBinding, err := m.clientset.RbacV1().ClusterRoleBindings().Get(ctx, crb.Name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRoleBinding %q", crb.GetName())
		deepCopy := existingBinding.DeepCopy()
		deepCopy.RoleRef = crb.RoleRef
		deepCopy.Subjects = crb.Subjects
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Update(ctx, deepCopy, meta.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRoleBinding %q", crb.GetName())
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) createOrUpdateCRD(ctx context.Context, crd *ext.CustomResourceDefinition) (err error) {
	existingCRD, err := m.clientsetext.CustomResourceDefinitions().Get(ctx, crd.Name, meta.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating CRD %q", crd.Name)
		deepCopy := existingCRD.DeepCopy()
		deepCopy.Spec = crd.Spec
		_, err = m.clientsetext.CustomResourceDefinitions().Update(ctx, deepCopy, meta.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating CRD %q", crd.Name)
		_, err = m.clientsetext.CustomResourceDefinitions().Create(ctx, crd, meta.CreateOptions{})
		return
	}
	return
}

func (m *crManager) deleteCRD(ctx context.Context, name string) (err error) {
	klog.V(3).Infof("Deleting CRD %q", name)
	err = m.clientsetext.CustomResourceDefinitions().Delete(ctx, name, meta.DeleteOptions{})
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	return
}

func (m *crManager) Cleanup(ctx context.Context) (err error) {
	err = m.deleteCRD(ctx, starboard.VulnerabilityReportsCRName)
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
	err = m.cleanupRBAC(ctx)
	if err != nil {
		return
	}

	klog.V(3).Infof("Deleting ConfigMap %q", NamespaceStarboard+"/"+ConfigMapStarboard)
	err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Delete(ctx, ConfigMapStarboard, meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}

	err = m.cleanupNamespace(ctx)
	if err != nil {
		return
	}
	return
}
