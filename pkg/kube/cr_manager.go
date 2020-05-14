package kube

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

// CRManager defined methods for managing Kubernetes custom resources.
type CRManager interface {
	Init() error
	Cleanup() error
}

type crManager struct {
	client extapi.ApiextensionsV1beta1Interface
}

// NewCRManager constructs a CRManager with the given Kubernetes config.
func NewCRManager(client extapi.ApiextensionsV1beta1Interface) (CRManager, error) {
	return &crManager{
		client: client,
	}, nil
}

func (m *crManager) Init() (err error) {
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

func (m *crManager) createOrUpdate(crd *v1beta1.CustomResourceDefinition) (err error) {
	existingCRD, err := m.client.CustomResourceDefinitions().Get(crd.Name, meta.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating CRD: %s", crd.Name)
		deepCopy := existingCRD.DeepCopy()
		deepCopy.Spec = crd.Spec
		_, err = m.client.CustomResourceDefinitions().Update(deepCopy)
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating CRD: %s", crd.Name)
		_, err = m.client.CustomResourceDefinitions().Create(crd)
		return
	}
	return
}

func (m *crManager) Cleanup() (err error) {
	err = m.client.CustomResourceDefinitions().Delete(sec.VulnerabilitiesCRName, &meta.DeleteOptions{})
	if err != nil {
		return
	}
	err = m.client.CustomResourceDefinitions().Delete(sec.CISKubeBenchReportCRName, &meta.DeleteOptions{})
	if err != nil {
		return
	}
	err = m.client.CustomResourceDefinitions().Delete(sec.KubeHunterReportCRName, &meta.DeleteOptions{})
	if err != nil {
		return
	}
	err = m.client.CustomResourceDefinitions().Delete(sec.ConfigAuditReportCRName, &meta.DeleteOptions{})
	return
}
