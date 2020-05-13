package kube

import (
	"fmt"
)

const (
	// Deprecated use LabelResourceKind instead, which is more generic
	LabelWorkloadKind = "starboard.workload.kind"
	// Deprecated use LabelResourceName instead, which is more generic
	LabelWorkloadName  = "starboard.workload.name"
	LabelContainerName = "starboard.container.name"
	LabelResourceKind  = "starboard.resource.kind"
	LabelResourceName  = "starboard.resource.name"

	LabelScannerName   = "starboard.scanner.name"
	LabelScannerVendor = "starboard.scanner.vendor"

	LabelHistoryLatest = "starboard.history.latest"
)

const (
	AnnotationHistoryLimit = "starboard.history.limit"
)

// WorkloadKind is an enum defining the different kinds of Kubernetes workloads.
type WorkloadKind int

const (
	WorkloadKindUnknown WorkloadKind = iota
	WorkloadKindPod
	WorkloadKindReplicaSet
	WorkloadKindReplicationController
	WorkloadKindDeployment
	WorkloadKindStatefulSet
	WorkloadKindDaemonSet
	WorkloadKindCronJob
	WorkloadKindJob
)

var workloadKindToString = map[WorkloadKind]string{
	WorkloadKindUnknown:               "Unknown",
	WorkloadKindPod:                   "Pod",
	WorkloadKindReplicaSet:            "ReplicaSet",
	WorkloadKindReplicationController: "ReplicationController",
	WorkloadKindDeployment:            "Deployment",
	WorkloadKindStatefulSet:           "StatefulSet",
	WorkloadKindDaemonSet:             "DaemonSet",
	WorkloadKindCronJob:               "CronJob",
	WorkloadKindJob:                   "Job",
}

func (t WorkloadKind) String() string {
	if s, exists := workloadKindToString[t]; exists {
		return s
	}
	return "Unknown"
}

type Workload struct {
	Namespace string
	Kind      WorkloadKind
	Name      string
}

func (t Workload) String() string {
	return fmt.Sprintf("%s/%s", t.Kind, t.Name)
}

func WorkloadKindFromString(s string) (WorkloadKind, error) {
	switch s {
	case "pods", "pod", "po":
		return WorkloadKindPod, nil
	case "replicasets.apps", "replicasets", "replicaset", "rs":
		return WorkloadKindReplicaSet, nil
	case "replicationcontrollers", "replicationcontroller", "rc":
		return WorkloadKindReplicationController, nil
	case "deployments.apps", "deployments", "deployment", "deploy":
		return WorkloadKindDeployment, nil
	case "statefulsets.apps", "statefulsets", "statefulset", "sts":
		return WorkloadKindStatefulSet, nil
	case "daemonsets.apps", "daemonsets", "daemonset", "ds":
		return WorkloadKindDaemonSet, nil
	case "cronjobs.batch", "cronjob.batch", "cronjobs", "cronjob", "cj":
		return WorkloadKindCronJob, nil
	case "jobs.batch", "job.batch", "jobs", "job":
		return WorkloadKindJob, nil
	}
	return WorkloadKindUnknown, fmt.Errorf("unrecognized workload: %s", s)
}
