package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/predicate"
	"github.com/aquasecurity/starboard/pkg/utils"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type TTLReportReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	ext.Clock
}

func (r *TTLReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// watch reports for ttl
	type resource struct {
		forObject client.Object
	}
	ttlResources := make([]resource, 0)
	if r.Config.ConfigAuditScannerEnabled || r.Config.ConfigAuditScannerBuiltIn {
		ttlResources = append(ttlResources, resource{forObject: &v1alpha1.ConfigAuditReport{}})
	}
	if r.Config.VulnerabilityScannerEnabled {
		ttlResources = append(ttlResources, resource{forObject: &v1alpha1.VulnerabilityReport{}})
	}
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	for _, reportType := range ttlResources {
		err = ctrl.NewControllerManagedBy(mgr).
			For(reportType.forObject, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				installModePredicate)).
			Complete(r.reconcileReport(reportType.forObject))
	}
	if err != nil {
		return err
	}
	return nil
}

func (r *TTLReportReconciler) reconcileReport(reportType client.Object) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("report", req.NamespacedName)

		err := r.Client.Get(ctx, req.NamespacedName, reportType)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached report that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting report from cache: %w", err)
		}

		ttlReportAnnotationStr, ok := reportType.GetAnnotations()[v1alpha1.TTLReportAnnotation]
		if !ok {
			log.V(1).Info("Ignoring report without TTL set")
			return ctrl.Result{}, nil
		}

		reportTTLTime, err := time.ParseDuration(ttlReportAnnotationStr)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed parsing %v with value %v %w", v1alpha1.TTLReportAnnotation, ttlReportAnnotationStr, err)
		}
		ttlExpired, durationToTTLExpiration := utils.IsTTLExpired(reportTTLTime, reportType.GetCreationTimestamp().Time, r.Clock)
		if ttlExpired {
			log.V(1).Info("Removing vulnerabilityReport with expired TTL")
			err := r.Client.Delete(ctx, reportType, &client.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			// Since the report is deleted there is no reason to requeue
			return ctrl.Result{}, nil
		}
		log.V(1).Info("RequeueAfter", "durationToTTLExpiration", durationToTTLExpiration)
		return ctrl.Result{RequeueAfter: durationToTTLExpiration}, nil
	}
}
