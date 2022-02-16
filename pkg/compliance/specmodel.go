package compliance

import (
	"github.com/emirpasic/gods/sets/hashset"
)

//Spec represent the compliance specification
type Spec struct {
	Kind        string    `yaml:"kind"`
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Cron        string    `yaml:"cron"`
	Version     string    `yaml:"version"`
	Controls    []Control `yaml:"controls"`
}

//Control represent the cps controls data and mapping checks
type Control struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Resources   []string `yaml:"resources"`
	Mapping     Mapping  `yaml:"mapping"`
}

//Check represent the tool who perform the control check
type Check struct {
	ID string `yaml:"id"`
}

//Mapping represent the tool who perform the control check
type Mapping struct {
	Tool   string  `yaml:"tool"`
	Checks []Check `yaml:"checks"`
}

//UnmarshalYAML over unmarshall to add logic
func (at *Control) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type control Control
	if err := unmarshal((*control)(at)); err != nil {
		return err
	}
	set := hashset.New()
	updatedResources := make([]string, 0)
	for _, resource := range at.Resources {
		if resource == "Workload" {
			set.Add("Pod", "ReplicationController", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob")
		} else {
			set.Add(resource)
		}
	}
	for _, setResource := range set.Values() {
		updatedResources = append(updatedResources, setResource.(string))
	}
	at.Resources = updatedResources
	return nil
}
