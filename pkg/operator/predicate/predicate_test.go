package predicate_test

import (
	"time"

	"github.com/aquasecurity/starboard/pkg/operator/predicate"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	predicatex "sigs.k8s.io/controller-runtime/pkg/predicate"
)

var _ = Describe("Predicate", func() {

	Describe("When checking a InNamespace predicate", func() {

		Context("When object is in desired namespace", func() {

			It("Should return true", func() {
				instance := predicate.InNamespace("starboard-operator")
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "starboard-operator",
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})

		})

		Context("When object is not in desired namespace", func() {

			It("Should return false", func() {
				instance := predicate.InNamespace("starboard-operator")
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: corev1.NamespaceDefault,
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})

		})

	})

	Describe("When checking a ManagedByStarboardOperator predicate", func() {

		instance := predicate.ManagedByStarboardOperator

		Context("Where object is managed by Starboard operator", func() {
			It("Should return true", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app.kubernetes.io/managed-by": "starboard-operator",
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})

		Context("Where object is managed by foo app", func() {
			It("Should return false", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app.kubernetes.io/managed-by": "foo",
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})

		Context("Where object is not managed by any app", func() {
			It("Should return false", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a PodBeingTerminated predicate", func() {

		instance := predicate.PodBeingTerminated
		deletionTimestamp := metav1.NewTime(time.Now())

		Context("Where pod is being terminated", func() {
			It("Should return true", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						DeletionTimestamp: &deletionTimestamp,
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})

		Context("Where pod is not being terminated", func() {
			It("Should return false", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						DeletionTimestamp: nil,
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a PodHasContainersReadyCondition predicate", func() {

		instance := predicate.PodHasContainersReadyCondition

		Context("Where pod has ContainersReady condition", func() {
			It("Should return true", func() {
				obj := &corev1.Pod{
					Status: corev1.PodStatus{
						Conditions: []corev1.PodCondition{
							{Type: corev1.PodInitialized},
							{Type: corev1.PodReady},
							{Type: corev1.ContainersReady},
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})

		Context("Where pod doesn't have ContainersReady condition", func() {
			It("Should return false", func() {
				obj := &corev1.Pod{
					Status: corev1.PodStatus{
						Conditions: []corev1.PodCondition{
							{Type: corev1.PodInitialized},
							{Type: corev1.PodReady},
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a JobHasAnyCondition predicate", func() {
		instance := predicate.JobHasAnyCondition
		Context("Where job has any condition", func() {
			It("Should return true", func() {
				obj := &batchv1.Job{
					Status: batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{
								Type: batchv1.JobComplete,
							},
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})
		Context("Where job doesn't have condition", func() {
			It("Should return false", func() {
				obj := &batchv1.Job{
					Status: batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a Not predicate", func() {

		Context("Where input predicate returns true", func() {
			It("Should return false", func() {
				instance := predicate.Not(predicatex.NewPredicateFuncs(func(_ client.Object) bool {
					return true
				}))

				Expect(instance.Create(event.CreateEvent{})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{})).To(BeFalse())
			})
		})

	})
})
