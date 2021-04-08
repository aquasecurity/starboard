package starboard

import (
	_ "embed"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
)

var (
	//go:embed deploy/crd/vulnerabilityreports.crd.yaml
	vulnerabilityReportsCRD []byte
)

func GetVulnerabilityReportsCRD() (apiextensionsv1.CustomResourceDefinition, error) {
	var crd apiextensionsv1.CustomResourceDefinition
	_, _, err := scheme.Codecs.UniversalDecoder().Decode(vulnerabilityReportsCRD, nil, &crd)
	if err != nil {
		return apiextensionsv1.CustomResourceDefinition{}, err
	}
	return crd, nil
}
