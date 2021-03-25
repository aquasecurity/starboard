package predicate

import (
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// InstallModePredicate is a predicate.Predicate that determines whether to
// reconcile the specified client.Object based on the give etc.InstallMode.
//
// In the etc.SingleNamespace install mode we're configuring client.Client cache
// to watch the operator namespace, in which the operator runs scan jobs.
// However, we do not want to scan the workloads that might run in the
// operator namespace.
//
// Similarly, in the etc.MultiNamespace install mode we're configuring
// client.Client cache to watch the operator namespace, in which the operator
// runs scan jobs. However, we do not want to scan the workloads that might run
// in the operator namespace unless the operator namespace is added to the list
// of target namespaces.
var InstallModePredicate = func(config etc.Config) (predicate.Predicate, error) {
	mode, operatorNamespace, targetNamespaces, err := config.ResolveInstallMode()
	if err != nil {
		return nil, err
	}
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if mode == etc.SingleNamespace {
			return targetNamespaces[0] == obj.GetNamespace() &&
				operatorNamespace != obj.GetNamespace()
		}

		if mode == etc.MultiNamespace {
			return ext.SliceContainsString(targetNamespaces, obj.GetNamespace())
		}

		return true
	}), nil
}

// InNamespace is a predicate.Predicate that returns true if the
// specified client.Object is in the desired namespace.
var InNamespace = func(namespace string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return namespace == obj.GetNamespace()
	})
}

// ManagedByStarboardOperator is a predicate.Predicate that returns true if the
// specified client.Object is managed by the Starboard Operator.
//
// For example, pods controlled by jobs scheduled by Starboard Operator are
// labeled with `app.kubernetes.io/managed-by=starboard-operator`.
var ManagedByStarboardOperator = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if managedBy, ok := obj.GetLabels()["app.kubernetes.io/managed-by"]; ok {
		return managedBy == "starboard-operator"
	}
	return false
})

// IsBeingTerminated is a predicate.Predicate that returns true if the specified
// client.Object is being terminated, i.e. its DeletionTimestamp property is set to non nil value.
var IsBeingTerminated = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	return obj.GetDeletionTimestamp() != nil
})

// JobHasConditions is a predicate.Predicate that returns true if the
// specified client.Object is a batchv1.Job with any batchv1.JobConditionType.
var JobHasAnyCondition = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if job, ok := obj.(*batchv1.Job); ok {
		return len(job.Status.Conditions) > 0
	}
	return false
})

var IsVulnerabilityReportScan = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if _, ok := obj.GetLabels()[kube.LabelVulnerabilityReportScan]; ok {
		return true
	}
	return false
})

var IsConfigAuditReportScan = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if _, ok := obj.GetLabels()[kube.LabelConfigAuditReportScan]; ok {
		return true
	}
	return false
})

var IsKubeBenchReportScan = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if _, ok := obj.GetLabels()[kube.LabelKubeBenchReportScan]; ok {
		return true
	}
	return false
})

func Not(p predicate.Predicate) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			return !p.Create(event)
		},
		DeleteFunc: func(event event.DeleteEvent) bool {
			return !p.Delete(event)
		},
		UpdateFunc: func(event event.UpdateEvent) bool {
			return !p.Update(event)
		},
		GenericFunc: func(event event.GenericEvent) bool {
			return !p.Generic(event)
		},
	}
}
