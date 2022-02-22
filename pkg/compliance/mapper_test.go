package compliance

import (
	"encoding/json"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"io/ioutil"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"
)

func TestGetObjListByName(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     string
	}{
		{name: "kube bench tool name", toolName: KubeBench, want: "*v1alpha1.CISKubeBenchReportList"},
		{name: "conf audit tool name", toolName: ConfigAudit, want: "*v1alpha1.ConfigAuditReportList"},
		{name: "no tool name", toolName: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := getObjListByName(tt.toolName)
			if cl != nil {
				name := reflect.TypeOf(cl).String()
				if name != tt.want {
					t.Errorf("TestGetObjListByName() got = %v, want %v", name, tt.want)
				}
			}
		})
	}
}

func TestByTool(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     string
	}{
		{name: "kube bench tool name", toolName: KubeBench, want: "*compliance.kubeBench"},
		{name: "conf audit tool name", toolName: ConfigAudit, want: "*compliance.configAudit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl, err := byTool(tt.toolName)
			if err != nil {
				t.Error(err)
			}
			if cl != nil {
				name := reflect.TypeOf(cl).String()
				if name != tt.want {
					t.Errorf("TestByTool() got = %v, want %v", name, tt.want)
				}
			}
		})
	}
}

func TestMapReportDataToMap(t *testing.T) {
	tests := []struct {
		name       string
		objectType string
		mapfunc    func(objType string, objList client.ObjectList) map[string]*ToolCheckResult
		reportList client.ObjectList
		wantResult map[string]*ToolCheckResult
	}{
		{name: "map config audit report", objectType: "Pod", reportList: getConfAudit([]string{"KSV037", "KSV038"}, []bool{true, false}, []string{"aaa", "bbb"}), wantResult: getWantResults("./fixture/config_audit_check_result.json"), mapfunc: configAudit{}.mapReportData},
		{name: "map cis benchmark report", objectType: "Node", reportList: getCisInstance([]string{"1.1", "2.2"}, []string{"Pass", "Fail"}, []string{"aaa", "bbb"}), wantResult: getWantResults("./fixture/cis_bench_check_result.json"), mapfunc: kubeBench{}.mapReportData},
		{name: "map empty config report", objectType: "Pod", reportList: &v1alpha1.ConfigAuditReportList{}, wantResult: map[string]*ToolCheckResult{}, mapfunc: configAudit{}.mapReportData},
		{name: "map empty cis report ", objectType: "Node", reportList: &v1alpha1.CISKubeBenchReportList{}, wantResult: map[string]*ToolCheckResult{}, mapfunc: kubeBench{}.mapReportData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cct := tt.mapfunc(tt.objectType, tt.reportList)
			if !reflect.DeepEqual(cct, tt.wantResult) {
				t.Errorf("TestMapReportDataToMapConfxigAudit want %v got %v", tt.wantResult, cct)
			}
		})
	}
}

func getWantResults(filePath string) map[string]*ToolCheckResult {
	var tct map[string]*ToolCheckResult
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &tct)
	if err != nil {
		return nil
	}
	return tct
}

func getWantMapResults(filePath string) map[string][]*ToolCheckResult {
	var tct map[string][]*ToolCheckResult
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &tct)
	if err != nil {
		return nil
	}
	return tct
}

func getConfAudit(testIds []string, testStatus []bool, remediation []string) *v1alpha1.ConfigAuditReportList {
	return &v1alpha1.ConfigAuditReportList{Items: []v1alpha1.ConfigAuditReport{{Report: v1alpha1.ConfigAuditReportData{Checks: []v1alpha1.Check{{
		ID: testIds[0], Remediation: remediation[0], Success: testStatus[0]}, {
		ID: testIds[1], Remediation: remediation[1], Success: testStatus[1],
	}}}}}}
}

func getCisInstance(testIds []string, testStatus []string, remediation []string) *v1alpha1.CISKubeBenchReportList {
	return &v1alpha1.CISKubeBenchReportList{
		Items: []v1alpha1.CISKubeBenchReport{{Report: v1alpha1.CISKubeBenchReportData{Sections: []v1alpha1.CISKubeBenchSection{
			{Tests: []v1alpha1.CISKubeBenchTests{
				{Results: []v1alpha1.CISKubeBenchResult{
					{TestNumber: testIds[0], Status: testStatus[0], Remediation: remediation[0]},
					{TestNumber: testIds[1], Status: testStatus[1], Remediation: remediation[1]}}}},
			}}}}}}
}
