package controller

import (
	"fmt"
	"github.com/aquasecurity/starboard/pkg/compliance"
	"github.com/aquasecurity/starboard/pkg/operator/predicate"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"time"

	"context"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ClusterComplianceReportReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	compliance.Mgr
}

func (r *ClusterComplianceReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}
	err = ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterComplianceReport{}, builder.WithPredicates(
			predicate.Not(predicate.IsBeingTerminated),
			installModePredicate)).
		Complete(r.reconcileComplianceReport())
	if err != nil {
		return err
	}
	return nil
}

func (r *ClusterComplianceReportReconciler) reconcileComplianceReport() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("compliance report", req.NamespacedName)

		report := &v1alpha1.ClusterComplianceReport{}
		err := r.Client.Get(ctx, req.NamespacedName, report)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached report that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting report from cache: %w", err)
		}
		ReportNextGenerationAnnotationStr, ok := report.Annotations[v1alpha1.ComplianceReportNextGeneration]
		if !ok {
			log.V(1).Info("Ignoring compliance report without next generation param set")
			return ctrl.Result{}, nil
		}

		reportTTLTime, err := time.ParseDuration(ReportNextGenerationAnnotationStr)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed parsing %v with value %v %w", v1alpha1.ComplianceReportNextGeneration, ReportNextGenerationAnnotationStr, err)
		}
		creationTime := report.Report.UpdateTimestamp
		generateNewReport, durationToNextGeneration := intervalExceeded(reportTTLTime, creationTime.Time)
		if err != nil {
			return ctrl.Result{}, err
		}
		if generateNewReport {
			err := r.Mgr.GenerateComplianceReport(ctx, compliance.Spec{})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to generate new report %v", err)
			}
			return ctrl.Result{}, nil
		}
		log.V(1).Info("RequeueAfter", "durationToNextGeneration", durationToNextGeneration)
		return ctrl.Result{RequeueAfter: durationToNextGeneration}, nil
	}
}
