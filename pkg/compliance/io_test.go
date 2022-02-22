package compliance

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sort"
	"testing"
)

func TestPopulateSpecDataToMaps(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name           string
		specPath       string
		tools          []string
		ids            []string
		wantMappedData *specDataMapping
	}{
		{name: "spec file with good format", ids: []string{"1.0", "8.1"}, tools: []string{"config-audit", "kube-bench"}, specPath: "./fixture/nsa-1.0.yaml", wantMappedData: &specDataMapping{
			toolResourceListNames: map[string]*hashset.Set{"config-audit": hashset.New("Job", "Pod", "ReplicationController", "ReplicaSet", "StatefulSet", "DaemonSet", "CronJob"),
				"kube-bench": hashset.New("Node")},
			controlIDControlObject: map[string]v1alpha1.Control{"1.0": {ID: "1.0", Name: "Non-root containers",
				Resources: []string{"Job", "Pod", "ReplicationController", "ReplicaSet", "StatefulSet", "DaemonSet", "CronJob"},
				Mapping:   v1alpha1.Mapping{Tool: "config-audit", Checks: []v1alpha1.SpecCheck{{ID: "KSV012"}}}}, "8.1": {ID: "8.1", Name: "Audit log path is configure",
				Resources: []string{"Node"},
				Mapping:   v1alpha1.Mapping{Tool: "kube-bench", Checks: []v1alpha1.SpecCheck{{ID: "1.2.22"}}}}},
			controlCheckIds: map[string][]string{"1.0": {"KSV012"}, "8.1": {"1.2.22"}}}},
		{name: "spec file with no controls", specPath: "./fixture/nsa-1.0_no_controls.yaml"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specData, err := ioutil.ReadFile(tt.specPath)
			if err != nil {
				t.Errorf(err.Error())
			}
			var spec v1alpha1.ReportSpec
			err = yaml.Unmarshal(specData, &spec)
			if err != nil {
				t.Errorf(err.Error())
			}
			pd := mgr.populateSpecDataToMaps(spec)
			if len(pd.toolResourceListNames) > 0 && len(pd.controlCheckIds) > 0 {
				if !cmp.Equal(pd.controlCheckIds, tt.wantMappedData.controlCheckIds, option()) {
					t.Errorf("TestPopulateSpecDataToMaps want %v got %v", tt.wantMappedData.controlCheckIds, pd.controlCheckIds)
				}
				if !cmp.Equal(pd.controlIDControlObject, tt.wantMappedData.controlIDControlObject, option()) {
					t.Errorf("TestPopulateSpecDataToMaps want %v got %v", tt.wantMappedData.controlIDControlObject, pd.controlIDControlObject)
				}
			}
		})
	}
}

func option() cmp.Option {
	trans := cmp.Transformer("Sort", func(in []string) []string {
		out := append([]string(nil), in...) // Copy input to avoid mutating it
		sort.Strings(out)
		return out
	})
	return trans
}

func TestControlChecksByToolChecks(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name          string
		specPath      string
		mapToolResult map[string][]*ToolCheckResult
		want          []v1alpha1.ControlCheck
	}{
		{name: " control checks by tool checks", specPath: "./fixture/nsa-1.0.yaml", want: []v1alpha1.ControlCheck{{ID: "1.0", Name: "Non-root containers", PassTotal: 1, FailTotal: 0}, {ID: "8.1", Name: "Audit log path is configure", PassTotal: 0, FailTotal: 1}},
			mapToolResult: map[string][]*ToolCheckResult{
				"KSV012": {{ID: "1.0", Remediation: "aaa", Details: []ResultDetails{{Status: "pass"}}}},
				"1.2.22": {{ID: "2.0", Remediation: "bbb", Details: []ResultDetails{{Status: "fail"}}}},
			}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specData, err := ioutil.ReadFile(tt.specPath)
			if err != nil {
				t.Errorf(err.Error())
			}
			var spec v1alpha1.ReportSpec
			err = yaml.Unmarshal(specData, &spec)
			if err != nil {
				t.Errorf(err.Error())
			}
			sm := mgr.populateSpecDataToMaps(spec)
			controlChecks := mgr.controlChecksByToolChecks(sm, tt.mapToolResult)
			if !reflect.DeepEqual(controlChecks, tt.want) {
				t.Errorf("TestControlChecksByToolChecks want %v got %v", tt.want, controlChecks)
			}
		})
	}
}

func TestGetTotals(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name         string
		controlCheck []v1alpha1.ControlCheck
		want         summaryTotal
	}{
		{name: "get totals with data", controlCheck: []v1alpha1.ControlCheck{{ID: "1.0", Name: "Non-root containers", PassTotal: 1, FailTotal: 0}, {ID: "8.1", Name: "Audit log path is configure", PassTotal: 0, FailTotal: 1}},
			want: summaryTotal{pass: 1, fail: 1}},
		{name: "get totals with no data", controlCheck: []v1alpha1.ControlCheck{},
			want: summaryTotal{pass: 0, fail: 0}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := mgr.getTotals(tt.controlCheck)
			if !reflect.DeepEqual(sm, tt.want) {
				t.Errorf("TestGetTotals want %v got %v", tt.want, sm)
			}
		})
	}
}

func TestCheckIdsToResults(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name       string
		reportList map[string]map[string]client.ObjectList
		wantResult map[string][]*ToolCheckResult
	}{
		{name: "map check ids to results report", reportList: map[string]map[string]client.ObjectList{ConfigAudit: {"Pod": getConfAudit([]string{"KSV037", "KSV038"}, []bool{true, false}, []string{"aaa", "bbb"})}, KubeBench: {"Node": getCisInstance([]string{"1.1", "2.2"}, []string{"Pass", "Fail"}, []string{"aaa", "bbb"})}}, wantResult: getWantMapResults("./fixture/check_data_result.json")},
		{name: "map empty data ", reportList: map[string]map[string]client.ObjectList{}, wantResult: map[string][]*ToolCheckResult{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cct, err := mgr.checkIdsToResults(tt.reportList)
			if err != nil {
				t.Error(err)
			}
			b, err := json.Marshal(cct)
			if err != nil {
				t.Error(err)
			}
			fmt.Println(string(b))
			if !reflect.DeepEqual(cct, tt.wantResult) {
				t.Errorf("TestMapReportDataToMapConfxigAudit want %v got %v", tt.wantResult, cct)
			}
		})
	}
}
