package kube

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
)

// Object is a simplified representation a Kubernetes object.
// Each object has kind, which designates the type of the entity it represents.
// Objects have names and many of them live in namespaces.
type Object struct {
	Kind      Kind
	Name      string
	Namespace string
}

// Kind represents the type of a Kubernetes Object.
type Kind string

const (
	KindUnknown Kind = "Unknown"

	KindNode Kind = "Node"

	KindPod                   Kind = "Pod"
	KindReplicaSet            Kind = "ReplicaSet.apps"
	KindReplicationController Kind = "ReplicationController"
	KindDeployment            Kind = "Deployment.apps"
	KindStatefulSet           Kind = "StatefulSet.apps"
	KindDaemonSet             Kind = "DaemonSet.apps"
	KindCronJob               Kind = "CronJob.batch"
	KindJob                   Kind = "Job.batch"
)

func ObjectFromLabelsSet(set labels.Set) (Object, error) {
	if !set.Has(LabelResourceKind) {
		return Object{}, fmt.Errorf("required label does not exist: %s", LabelResourceKind)
	}
	if !set.Has(LabelResourceName) {
		return Object{}, fmt.Errorf("required label does not exist: %s", LabelResourceName)
	}
	return Object{
		Kind:      Kind(set.Get(LabelResourceKind)),
		Name:      set.Get(LabelResourceName),
		Namespace: set.Get(LabelResourceNamespace),
	}, nil
}

func KindFromResource(resource string) (Kind, error) {
	switch resource {
	case "pods", "pod", "po":
		return KindPod, nil
	case "replicasets.apps", "replicasets", "replicaset", "rs":
		return KindReplicaSet, nil
	case "replicationcontrollers", "replicationcontroller", "rc":
		return KindReplicationController, nil
	case "deployments.apps", "deployments", "deployment", "deploy":
		return KindDeployment, nil
	case "statefulsets.apps", "statefulsets", "statefulset", "sts":
		return KindStatefulSet, nil
	case "daemonsets.apps", "daemonsets", "daemonset", "ds":
		return KindDaemonSet, nil
	case "cronjobs.batch", "cronjob.batch", "cronjobs", "cronjob", "cj":
		return KindCronJob, nil
	case "jobs.batch", "job.batch", "jobs", "job":
		return KindJob, nil
	}
	return KindUnknown, fmt.Errorf("unrecognized resource: %s", resource)
}

// ContainerImages is a simple structure to hold the mapping between container names and container image references.
type ContainerImages map[string]string

func (ci ContainerImages) AsJSON() (string, error) {
	writer, err := json.Marshal(ci)
	if err != nil {
		return "", err
	}
	return string(writer), nil
}

func (ci ContainerImages) FromJSON(value string) error {
	return json.Unmarshal([]byte(value), &ci)
}
