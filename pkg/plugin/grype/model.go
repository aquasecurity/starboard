package grype

type ScanReport struct {
	Matches    []Match    `json:"matches"`
	Source     Source     `json:"source"`
	Descriptor Descriptor `json:"descriptor"`
}

type Match struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Artifact      Artifact      `json:"artifact"`
}

type Vulnerability struct {
	Id          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Severity    string   `json:"severity"`
	URLs        []string `json:"urls"`
	Description string   `json:"description"`
	CVSs        []CVS    `json:"cvss"`
	Fix         Fix      `json:"fix"`
}

type Artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type CVS struct {
	Version string     `json:"version"`
	Metrics CVSMetrics `json:"metrics"`
}

type CVSMetrics struct {
	BaseScore *float64 `json:"baseScore"`
}

type Source struct {
	Target Target `json:"target"`
}

type Target struct {
	UserInput      string `json:"userInput"`
	ManifestDigest string `json:"manifestDigest"`
}

type Descriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
