package compliance

import (
	"embed"
	"fmt"
	"gopkg.in/yaml.v2"
)

const SpecsFolder = "specs"

var (
	//go:embed specs
	res embed.FS
)

func LoadClusterComplianceSpecs() ([]Spec, error) {
	dir, _ := res.ReadDir(SpecsFolder)
	specs := make([]Spec, 0)
	for _, r := range dir {
		file, err := res.Open(fmt.Sprintf("%s/%s", SpecsFolder, r.Name()))
		if err != nil {
			return specs, err
		}
		var spec Spec
		err = yaml.NewDecoder(file).Decode(&spec)
		if err != nil {
			return specs, err
		}
		specs = append(specs, spec)
	}
	return specs, nil
}
