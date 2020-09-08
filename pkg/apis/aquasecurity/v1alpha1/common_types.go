package v1alpha1

// Scanner is the spec for a scanner generating a security assessment report.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}
