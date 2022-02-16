package v1alpha1

const (
	TTLReportAnnotation = "starboard.aquasecurity.github.io/report-ttl"
)

// Scanner is the spec for a scanner generating a security assessment report.
type Scanner struct {
	// Name the name of the scanner.
	Name string `json:"name"`

	// Vendor the name of the vendor providing the scanner.
	Vendor string `json:"vendor"`

	// Version the version of the scanner.
	Version string `json:"version"`
}

// Compliance is the specs for a security assessment report.
type Compliance struct {
	// Name the name of the compliance report.
	Kind string `json:"kind"`
	// Name the name of the compliance report.
	Name string `json:"name"`
	// Description of the compliance report.
	Description string `json:"description"`

	// Version the compliance report.
	Version string `json:"version"`
}
