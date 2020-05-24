package kube

import (
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
  # resources
  cpuRequestsMissing: warning
  cpuLimitsMissing: warning
  memoryRequestsMissing: warning
  memoryLimitsMissing: warning
  # images
  tagNotSpecified: error
  pullPolicyNotAlways: ignore
  # healthChecks
  readinessProbeMissing: warning
  livenessProbeMissing: warning
  # networking
  hostNetworkSet: warning
  hostPortSet: warning
  # security
  hostIPCSet: error
  hostPIDSet: error
  notReadOnlyRootFileSystem: warning
  privilegeEscalationAllowed: error
  runAsRootAllowed: warning
  runAsPrivileged: error
  dangerousCapabilities: error
  insecureCapabilities: warning
controllersToScan:
  - Deployments
  - StatefulSets
  - DaemonSets
  - CronJobs
  - Jobs
  - ReplicationControllers
exemptions:
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
      - notReadOnlyRootFileSystem
  - controllerNames:
      - cert-manager
      - dns-controller
      - kubedns
      - dnsmasq
      - autoscaler
      - insights-agent-goldilocks-vpa-install
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
      - notReadOnlyRootFileSystem
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
	Init() error
	Cleanup() error
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

func (m *crManager) Init() (err error) {
	err = m.createOrUpdateCRD(&starboard.VulnerabilitiesCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdateCRD(&starboard.CISKubeBenchReportCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdateCRD(&starboard.KubeHunterReportCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdateCRD(&starboard.ConfigAuditReportCRD)
	if err != nil {
		return
	}
	// TODO We should wait for CRD statuses and make sure that the names were accepted

	err = m.createNamespaceIfNotFound(NamespaceStarboard)
	if err != nil {
		return
	}

	err = m.initPolaris()
	return
}

// TODO Move this logic to Polaris scanner structure
func (m *crManager) initPolaris() (err error) {
	err = m.createServiceAccountIfNotFound(ServiceAccountPolaris)
	if err != nil {
		return
	}

	err = m.createConfigMapIfNotFound(ConfigMapPolaris, map[string]string{
		"config.yaml": polarisConfigYAML,
	})
	if err != nil {
		return
	}

	err = m.createOrUpdateClusterRole(&rbac.ClusterRole{
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

	err = m.createOrUpdateClusterRoleBinding(&rbac.ClusterRoleBinding{
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
func (m *crManager) cleanupPolaris() (err error) {
	klog.V(3).Infof("Deleting ClusterRoleBinding %s", "starboard-polaris")
	err = m.clientset.RbacV1().ClusterRoleBindings().Delete("starboard-polaris", &meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ClusterRole: %s", "starboard-polars")
	err = m.clientset.RbacV1().ClusterRoles().Delete("starboard-polaris", &meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ServiceAccount %s/%s", NamespaceStarboard, ServiceAccountPolaris)
	err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Delete(ServiceAccountPolaris, &meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ConfigMap %s/%s", NamespaceStarboard, ConfigMapPolaris)
	err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Delete(ConfigMapPolaris, &meta.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	return nil
}

func (m *crManager) createNamespaceIfNotFound(name string) (err error) {
	_, err = m.clientset.CoreV1().Namespaces().Get(name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Namespace %s already exists", name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating namespace %s", name)
		_, err = m.clientset.CoreV1().Namespaces().Create(&core.Namespace{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
		})
		return
	}
	return
}

func (m *crManager) createServiceAccountIfNotFound(name string) (err error) {
	_, err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Get(name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("ServiceAccount %s already exists", name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ServiceAccount %s", name)
		_, err = m.clientset.CoreV1().ServiceAccounts(NamespaceStarboard).Create(&core.ServiceAccount{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
		})
		return
	}
	return
}

func (m *crManager) createConfigMapIfNotFound(name string, data map[string]string) (err error) {
	_, err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Get(name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("ConfigMap %s already exists", name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ConfigMap %s", name)
		_, err = m.clientset.CoreV1().ConfigMaps(NamespaceStarboard).Create(&core.ConfigMap{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
			Data: data,
		})
		return
	}
	return
}

func (m *crManager) createOrUpdateClusterRole(cr *rbac.ClusterRole) (err error) {
	existingRole, err := m.clientset.RbacV1().ClusterRoles().Get(cr.GetName(), meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRole %s", cr.GetName())
		deepCopy := existingRole.DeepCopy()
		deepCopy.Rules = cr.Rules
		_, err = m.clientset.RbacV1().ClusterRoles().Update(deepCopy)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRole %s", cr.GetName())
		_, err = m.clientset.RbacV1().ClusterRoles().Create(cr)
		return
	}
	return
}

func (m *crManager) createOrUpdateClusterRoleBinding(crb *rbac.ClusterRoleBinding) (err error) {
	existingBinding, err := m.clientset.RbacV1().ClusterRoleBindings().Get(crb.Name, meta.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRoleBinding %s", crb.GetName())
		deepCopy := existingBinding.DeepCopy()
		deepCopy.RoleRef = crb.RoleRef
		deepCopy.Subjects = crb.Subjects
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Update(deepCopy)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRoleBinding %s", crb.GetName())
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Create(crb)
		return
	}
	return
}

func (m *crManager) createOrUpdateCRD(crd *ext.CustomResourceDefinition) (err error) {
	existingCRD, err := m.clientsetext.CustomResourceDefinitions().Get(crd.Name, meta.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating CRD: %s", crd.Name)
		deepCopy := existingCRD.DeepCopy()
		deepCopy.Spec = crd.Spec
		_, err = m.clientsetext.CustomResourceDefinitions().Update(deepCopy)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating CRD: %s", crd.Name)
		_, err = m.clientsetext.CustomResourceDefinitions().Create(crd)
		return
	}
	return
}

func (m *crManager) deleteCRD(name string) (err error) {
	klog.V(3).Infof("Deleting CRD: %s", name)
	err = m.clientsetext.CustomResourceDefinitions().Delete(name, &meta.DeleteOptions{})
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	return
}

func (m *crManager) Cleanup() (err error) {
	err = m.deleteCRD(starboard.VulnerabilitiesCRName)
	if err != nil {
		return
	}
	err = m.deleteCRD(starboard.CISKubeBenchReportCRName)
	if err != nil {
		return
	}
	err = m.deleteCRD(starboard.KubeHunterReportCRName)
	if err != nil {
		return
	}
	err = m.deleteCRD(starboard.ConfigAuditReportCRName)
	if err != nil {
		return
	}
	err = m.cleanupPolaris()
	if err != nil {
		return
	}
	return
}
