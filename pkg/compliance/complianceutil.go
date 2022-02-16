package compliance

import (
	"embed"
	"fmt"
	"github.com/go-logr/logr"
	"gopkg.in/yaml.v2"
)

const SpecsFolder = "specs"

var (
	//go:embed specs
	res embed.FS
)

func LoadClusterComplianceSpecs(log logr.Logger) ([]Spec, error) {
	dir, _ := res.ReadDir(SpecsFolder)
	specs := make([]Spec, 0)
	for _, r := range dir {
		file, err := res.Open(fmt.Sprintf("%s/%s", SpecsFolder, r.Name()))
		if err != nil {
			log.V(1).Error(err, "failed to load compliance specs")
		}
		var spec Spec
		err = yaml.NewDecoder(file).Decode(&spec)
		if err != nil {
			log.V(1).Error(err, "failed to decode compliance specs")
		}
		specs = append(specs, spec)
	}
	return specs, nil
}
