package compliance

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
)

type Mgr interface {
	GenerateComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec) (*v1alpha1.ClusterComplianceReport, error)
}

type cm struct {
	client client.Client
	log    logr.Logger
}

type ControlsSummary struct {
	ID    string
	Pass  float32
	Total float32
}

type SpecDataMapping struct {
	toolResourceListNames  map[string]*hashset.Set
	controlIDControlObject map[string]v1alpha1.Control
	controlCheckIds        map[string][]string
}

func (w *cm) GenerateComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec) (*v1alpha1.ClusterComplianceReport, error) {
	// map specs to key/value map for easy processing
	smd := w.populateSpecDataToMaps(spec)
	// map compliance tool to resource data
	toolResourceMap := mapComplianceToolToResource(w.client, ctx, smd.toolResourceListNames)
	// organized data by check id and it aggregated results
	checkIdsToResults, err := w.checkIdsToResults(toolResourceMap)
	if err != nil {
		return nil, err
	}
	// map tool checks results to control check results
	controlChecks := w.controlChecksByToolChecks(smd, checkIdsToResults)
	// publish compliance report
	return w.createComplianceReport(ctx, spec, controlChecks)

	/*controlCheckDetails := w.controlChecksDetailsByToolChecks(smd, checkIdsToResults)
	err = w.createComplianceDetailReport(ctx, spec, controlChecks, controlCheckDetails)
	if err != nil {
		return err
	}*/
}

func (w *cm) createComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec, controlChecks []v1alpha1.ControlCheck) (*v1alpha1.ClusterComplianceReport, error) {
	var totalFail, totalPass int
	if len(controlChecks) > 0 {
		for _, controlCheck := range controlChecks {
			totalFail = totalFail + controlCheck.FailTotal
			totalPass = totalPass + controlCheck.PassTotal
		}
	}
	summary := v1alpha1.ClusterComplianceSummary{PassCount: totalPass, FailCount: totalFail}
	report := v1alpha1.ClusterComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: strings.ToLower(spec.Name),
		},

		Status: v1alpha1.ReportStatus{UpdateTimestamp: metav1.NewTime(ext.NewSystemClock().Now()), Summary: summary, Type: v1alpha1.Compliance{Kind: strings.ToLower(spec.Kind), Name: strings.ToLower(spec.Name), Description: strings.ToLower(spec.Description), Version: spec.Version}, ControlChecks: controlChecks},
	}
	var existing v1alpha1.ClusterComplianceReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: strings.ToLower(spec.Name),
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Status = report.Status
		copied.Spec = spec
		copied.Status.UpdateTimestamp = metav1.NewTime(ext.NewSystemClock().Now())
		return copied, nil
	}

	if errors.IsNotFound(err) {
		return &report, nil
	}
	return nil, err
}

func (w *cm) createComplianceDetailReport(ctx context.Context, spec v1alpha1.ReportSpec, controlChecks []v1alpha1.ControlCheck, controlChecksDetails []v1alpha1.ControlCheckDetails) error {
	var totalFail, totalPass int
	if len(controlChecks) > 0 {
		for _, controlCheck := range controlChecks {
			totalFail = totalFail + controlCheck.FailTotal
			totalPass = totalPass + controlCheck.PassTotal
		}
	}
	name := strings.ToLower(fmt.Sprintf("%s-%s", spec.Name, "Details"))
	summary := v1alpha1.ClusterComplianceDetailSummary{PassCount: totalPass, FailCount: totalFail}
	report := v1alpha1.ClusterComplianceDetailReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Report: v1alpha1.ClusterComplianceDetailReportData{UpdateTimestamp: metav1.NewTime(ext.NewSystemClock().Now()), Summary: summary, Type: v1alpha1.Compliance{Kind: strings.ToLower(spec.Kind), Name: name, Description: strings.ToLower(spec.Description), Version: spec.Version}, ControlChecks: controlChecksDetails},
	}
	var existing v1alpha1.ClusterComplianceDetailReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: name,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = report.Report
		copied.Report.UpdateTimestamp = metav1.NewTime(ext.NewSystemClock().Now())
		return w.client.Update(ctx, copied)
	}

	if errors.IsNotFound(err) {
		return w.client.Create(ctx, &report)
	}
	return nil
}

func (w *cm) controlChecksByToolChecks(smd *SpecDataMapping, checkIdsToResults map[string][]*ToolCheckResult) []v1alpha1.ControlCheck {
	controlChecks := make([]v1alpha1.ControlCheck, 0)
	for controlID, checkIds := range smd.controlCheckIds {
		var passTotal, failTotal, total int
		for _, checkId := range checkIds {
			results, ok := checkIdsToResults[checkId]
			if ok {
				for _, checkResult := range results {
					for _, crd := range checkResult.Details {
						switch crd.Status {
						case Pass, Warn:
							passTotal++
						case Fail:
							failTotal++
						}
						total++
					}
				}
			}
		}
		control := smd.controlIDControlObject[controlID]
		controlChecks = append(controlChecks, v1alpha1.ControlCheck{ID: controlID, Name: control.Name, Description: control.Description, PassTotal: passTotal, FailTotal: failTotal})
	}
	return controlChecks
}

func (w *cm) controlChecksDetailsByToolChecks(smd *SpecDataMapping, checkIdsToResults map[string][]*ToolCheckResult) []v1alpha1.ControlCheckDetails {
	controlChecks := make([]v1alpha1.ControlCheckDetails, 0)
	for controlID, checkIds := range smd.controlCheckIds {
		for _, checkId := range checkIds {
			results, ok := checkIdsToResults[checkId]
			if ok {
				for _, checkResult := range results {
					var ctt v1alpha1.ToolCheckResult
					rds := make([]v1alpha1.ResultDetails, 0)
					for _, crd := range checkResult.Details {
						rds = append(rds, v1alpha1.ResultDetails{Name: crd.Name, Namespace: crd.Namespace, Status: crd.Status})
					}
					ctt = v1alpha1.ToolCheckResult{ID: checkResult.ID, ObjectType: checkResult.ObjectType, Remediation: checkResult.Remediation, Details: rds}
					control := smd.controlIDControlObject[controlID]
					controlChecks = append(controlChecks, v1alpha1.ControlCheckDetails{ID: controlID, Name: control.Name, Description: control.Description, ToolCheckResult: ctt})
				}
			}
		}
	}
	return controlChecks
}

func (w *cm) checkIdsToResults(toolResourceMap map[string]map[string]client.ObjectList) (map[string][]*ToolCheckResult, error) {
	checkIdsToResults := make(map[string][]*ToolCheckResult)
	for tool, resourceListMap := range toolResourceMap {
		for resourceName, resourceList := range resourceListMap {
			mapper, err := ByTool(tool)
			if err != nil {
				return nil, err
			}
			idCheckResultMap := mapper.MapReportDataToMap(resourceName, resourceList)
			if idCheckResultMap == nil {
				continue
			}
			for id, toolCheckResult := range idCheckResultMap {
				if _, ok := checkIdsToResults[id]; !ok {
					checkIdsToResults[id] = make([]*ToolCheckResult, 0)
				}
				checkIdsToResults[id] = append(checkIdsToResults[id], toolCheckResult)
			}
		}
	}
	return checkIdsToResults, nil
}

func (w *cm) populateSpecDataToMaps(spec v1alpha1.ReportSpec) *SpecDataMapping {
	//control to resource list map
	controlIDControlObject := make(map[string]v1alpha1.Control)
	//control to checks map
	controlCheckIds := make(map[string][]string)
	//tool to resource list map
	toolResourceListName := make(map[string]*hashset.Set)
	for _, control := range spec.Controls {
		control.Resources = MapResources(control)
		if _, ok := toolResourceListName[control.Mapping.Tool]; !ok {
			toolResourceListName[control.Mapping.Tool] = hashset.New()
		}
		for _, resource := range control.Resources {
			toolResourceListName[control.Mapping.Tool].Add(resource)
		}
		controlIDControlObject[control.ID] = control
		//update control resource list map
		for _, check := range control.Mapping.Checks {
			if _, ok := controlCheckIds[control.ID]; !ok {
				controlCheckIds[control.ID] = make([]string, 0)
			}
			controlCheckIds[control.ID] = append(controlCheckIds[control.ID], check.ID)
		}
	}
	return &SpecDataMapping{
		toolResourceListNames:  toolResourceListName,
		controlIDControlObject: controlIDControlObject,
		controlCheckIds:        controlCheckIds}
}

func NewMgr(client client.Client, log logr.Logger) Mgr {
	return &cm{
		client: client,
		log:    log,
	}
}

type ToolResource struct {
	ToolResource map[string]map[string]interface{}
}
