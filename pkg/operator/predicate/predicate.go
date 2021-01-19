package predicate

import (
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

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

// PodHasContainersReadyCondition is a predicate.Predicate that returns true if the
// specified client.Object is a corev1.Pod with corev1.ContainersReady condition.
var PodHasContainersReadyCondition = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if pod, ok := obj.(*corev1.Pod); ok {
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.ContainersReady {
				return true
			}
		}
	}
	return false
})

// PodBeingTerminated is a predicate.Predicate that returns true if the specified
// client.Object is a corev1.Pod that is being terminated, i.e. its
// DeletionTimestamp property is set to non nil value.
var PodBeingTerminated = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if pod, ok := obj.(*corev1.Pod); ok {
		return pod.DeletionTimestamp != nil
	}
	return false
})

// JobHasConditions is a predicate.Predicate that returns true if the
// specified client.Object is a batchv1.Job with any batchv1.JobConditionType.
var JobHasAnyCondition = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if job, ok := obj.(*batchv1.Job); ok {
		return len(job.Status.Conditions) > 0
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
