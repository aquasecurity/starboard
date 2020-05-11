package v1alpha1

// Scanner is the spec for a scanner generating a security assessment report.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type KubernetesResource struct {
	Kind string `json:"kind"` // Pod, Deployment, Node, etc.
	Name string `json:"name"` // my-pod, my-deployment, my-node, etc.
}

type KubernetesNamespacedResource struct {
	Namespace string `json:"namespace"`
	KubernetesResource
}
