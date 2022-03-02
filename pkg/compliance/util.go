package compliance

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/emirpasic/gods/sets/hashset"
)

//mapResources map resource data
func mapResources(control v1alpha1.Control) []string {
	set := hashset.New()
	updatedResources := make([]string, 0)
	for _, resource := range control.Resources {
		if resource == "Workload" {
			set.Add("Pod", "ReplicationController", "ReplicaSet", "StatefulSet", "DaemonSet", "CronJob", "Job")
		} else {
			set.Add(resource)
		}
	}
	for _, setResource := range set.Values() {
		updatedResources = append(updatedResources, setResource.(string))
	}
	return updatedResources
}