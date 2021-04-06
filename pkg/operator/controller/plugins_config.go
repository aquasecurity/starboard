package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/predicate"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PluginsConfigReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	starboard.PluginContext
	configauditreport.Plugin
}

func (r *PluginsConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}, builder.WithPredicates(
			predicate.Not(predicate.IsBeingTerminated),
			predicate.InNamespace(r.Config.Namespace))).
		Complete(r)
}

func (r *PluginsConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Logger.WithValues("configMap", req.NamespacedName)

	// TODO Use Predicate instead
	if req.Name != strings.ToLower("starboard-"+r.PluginContext.GetName()+"config") {
		return ctrl.Result{}, nil
	}

	cm := &corev1.ConfigMap{}

	err := r.Client.Get(ctx, req.NamespacedName, cm)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Ignoring cached ConfigMap that must have been deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting ConfigMap from cache: %w", err)
	}

	configHash, err := r.Plugin.GetConfigHash(r.PluginContext)
	if err != nil {
		return ctrl.Result{}, err
	}

	labelSelector, err := labels.Parse(fmt.Sprintf("%s != %s", kube.LabelPluginConfigHash, configHash))
	if err != nil {
		return ctrl.Result{}, err
	}

	var reportList v1alpha1.ConfigAuditReportList
	err = r.Client.List(ctx, &reportList,
		client.Limit(r.Config.BatchDeleteLimit+1), // TODO The limit is not respected https://github.com/kubernetes-sigs/controller-runtime/issues/1422
		client.MatchingLabelsSelector{Selector: labelSelector})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("listing reports: %w", err)
	}

	log.V(1).Info("Listing ConfigAuditReports",
		"reportsCount", len(reportList.Items),
		"batchDeleteLimit", r.Config.BatchDeleteLimit)

	for i := 0; i < ext.MinInt(r.Config.BatchDeleteLimit, len(reportList.Items)); i++ {
		report := reportList.Items[i]
		log.V(1).Info("Deleting ConfigAuditReport", "report", report.Namespace+"/"+report.Name)
		err := r.Client.Delete(ctx, &report)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	if len(reportList.Items)-r.Config.BatchDeleteLimit > 0 {
		// TODO Calculate RequeueAfter based on average scan duration?
		return ctrl.Result{RequeueAfter: r.Config.BatchDeleteDelay}, nil
	}

	return ctrl.Result{}, nil
}
