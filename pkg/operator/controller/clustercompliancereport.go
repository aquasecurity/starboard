package controller

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/compliance"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/predicate"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"
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
		Owns(&v1alpha1.ClusterComplianceDetailReport{}).
		Complete(r.reconcileComplianceReport())
	if err != nil {
		return err
	}
	return nil
}

func (r *ClusterComplianceReportReconciler) reconcileComplianceReport() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		return r.generateComplianceReport(ctx, req.NamespacedName)
	}
}

func (r *ClusterComplianceReportReconciler) generateComplianceReport(ctx context.Context, namespaceName types.NamespacedName) (ctrl.Result, error) {
	log := r.Logger.WithValues("compliance report", namespaceName)
	var report v1alpha1.ClusterComplianceReport
	err := r.Client.Get(ctx, namespaceName, &report)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Ignoring cached report that must have been deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting report from cache: %w", err)
	}
	durationToNextGeneration, err := nextCronDuration(report.Spec.Cron, r.reportLastUpdatedTime(&report))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to check report cron expression %w", err)
	}
	if durationExceeded(durationToNextGeneration) {
		report, err := r.Mgr.GenerateComplianceReport(ctx, report.Spec)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to generate new report %w", err)
		}
		// update compliance report status
		err = r.Status().Update(ctx, report)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update report status %w", err)
		}
		return ctrl.Result{}, nil
	}
	log.V(1).Info("RequeueAfter", "durationToNextGeneration", durationToNextGeneration)
	return ctrl.Result{RequeueAfter: durationToNextGeneration}, nil
}

func (r *ClusterComplianceReportReconciler) reportLastUpdatedTime(report *v1alpha1.ClusterComplianceReport) time.Time {
	updateTimeStamp := report.Status.UpdateTimestamp.Time
	lastUpdated := updateTimeStamp
	if updateTimeStamp.Before(report.ObjectMeta.CreationTimestamp.Time) {
		lastUpdated = report.ObjectMeta.CreationTimestamp.Time
	}
	return lastUpdated
}
