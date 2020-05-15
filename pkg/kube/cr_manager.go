package kube

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	core "k8s.io/api/core/v1"
	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

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
	err = m.createNamespaceIfNotFound(NamespaceStarboard)
	if err != nil {
		return
	}

	err = m.createOrUpdate(&sec.VulnerabilitiesCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdate(&sec.CISKubeBenchReportCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdate(&sec.KubeHunterReportCRD)
	if err != nil {
		return
	}

	err = m.createOrUpdate(&sec.ConfigAuditReportCRD)

	// TODO We should wait for CRD statuses and make sure that the names were accepted
	return
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

func (m *crManager) createOrUpdate(crd *ext.CustomResourceDefinition) (err error) {
	existingCRD, err := m.clientsetext.CustomResourceDefinitions().Get(crd.Name, meta.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating CRD: %s", crd.Name)
		deepCopy := existingCRD.DeepCopy()
		deepCopy.Spec = crd.Spec
		_, err = m.clientsetext.CustomResourceDefinitions().Update(deepCopy)
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating CRD: %s", crd.Name)
		_, err = m.clientsetext.CustomResourceDefinitions().Create(crd)
		return
	}
	return
}

func (m *crManager) Cleanup() (err error) {
	err = m.clientsetext.CustomResourceDefinitions().Delete(sec.VulnerabilitiesCRName, &meta.DeleteOptions{})
	if err != nil {
		return
	}
	err = m.clientsetext.CustomResourceDefinitions().Delete(sec.CISKubeBenchReportCRName, &meta.DeleteOptions{})
	if err != nil {
		return
	}
	err = m.clientsetext.CustomResourceDefinitions().Delete(sec.KubeHunterReportCRName, &meta.DeleteOptions{})
	if err != nil {
		return
	}
	err = m.clientsetext.CustomResourceDefinitions().Delete(sec.ConfigAuditReportCRName, &meta.DeleteOptions{})
	return
}
