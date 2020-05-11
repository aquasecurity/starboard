package crd

import (
	"errors"
	"strings"

	"github.com/aquasecurity/starboard/pkg/kubehunter"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	secapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

type writer struct {
	client *secapi.Clientset
}

func NewWriter(config *rest.Config) (w kubehunter.Writer, err error) {
	client, err := secapi.NewForConfig(config)
	if err != nil {
		return
	}
	w = &writer{
		client: client,
	}
	return
}

func (w *writer) Write(report sec.KubeHunterOutput, cluster string) (err error) {
	if strings.TrimSpace(cluster) == "" {
		err = errors.New("cluster name must not be blank")
		return
	}
	// TODO Check if an instance of the report with the given name already exists.
	// TODO If exists just update it, create new instance otherwise
	_, err = w.client.AquasecurityV1alpha1().KubeHunterReports().Create(&sec.KubeHunterReport{
		ObjectMeta: meta.ObjectMeta{
			Name:   cluster,
			Labels: map[string]string{},
		},
		Report: report,
	})
	return
}
