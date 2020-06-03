package crd

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"

	"k8s.io/klog"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultHistoryLimit = 10
)

type writer struct {
	clock     ext.Clock
	clientset starboardapi.Interface
}

func NewWriter(clock ext.Clock, clientset starboardapi.Interface) kubebench.Writer {
	return &writer{
		clock:     clock,
		clientset: clientset,
	}
}

func (w *writer) Write(ctx context.Context, report starboard.CISKubeBenchOutput, node *core.Node) (err error) {
	reports, err := w.getReportsByNodeName(ctx, node.GetName())
	if err != nil {
		return
	}
	err = w.removeHistoryLatestLabel(ctx, reports)
	if err != nil {
		return
	}
	err = w.removeReportsWithHistoryLimitExceeded(ctx, reports)
	if err != nil {
		return
	}

	_, err = w.clientset.AquasecurityV1alpha1().CISKubeBenchReports().Create(ctx, &starboard.CISKubeBenchReport{
		ObjectMeta: meta.ObjectMeta{
			Name: fmt.Sprintf("%s-%d", node.Name, w.clock.Now().Unix()),
			Labels: map[string]string{
				kube.LabelResourceKind:  "Node", // TODO Why node.Kind is nil?
				kube.LabelResourceName:  node.Name,
				kube.LabelScannerName:   "kube-bench",
				kube.LabelScannerVendor: "aqua",
				kube.LabelHistoryLatest: "true",
			},
			Annotations: map[string]string{
				// TODO Make this history limit configurable somehow, e.g. $ starboard kube-bench --history-limit=7
				kube.AnnotationHistoryLimit: strconv.Itoa(10),
			},
			OwnerReferences: []meta.OwnerReference{
				{
					APIVersion: "v1",   // TODO Why node.APIVersion is nil?
					Kind:       "Node", // TODO Why node.Kind is nil?
					Name:       node.Name,
					UID:        node.UID,
					Controller: pointer.BoolPtr(false),
				},
			},
		},
		Report: report,
	}, meta.CreateOptions{})
	return
}

func (w *writer) getReportsByNodeName(ctx context.Context, name string) (reports []starboard.CISKubeBenchReport, err error) {
	list, err := w.clientset.AquasecurityV1alpha1().CISKubeBenchReports().List(ctx, meta.ListOptions{
		LabelSelector: labels.Set{
			kube.LabelResourceKind: "Node",
			kube.LabelResourceName: name,
		}.String(),
	})
	if err != nil {
		return
	}
	reports = list.Items
	return
}

func (w *writer) removeHistoryLatestLabel(ctx context.Context, reports []starboard.CISKubeBenchReport) (err error) {
	for _, report := range reports {
		if value, ok := report.Labels[kube.LabelHistoryLatest]; !ok || value != "true" {
			continue
		}
		clone := report.DeepCopy()
		delete(clone.Labels, kube.LabelHistoryLatest)
		klog.V(3).Infof("Removing %s label from %s report", kube.LabelHistoryLatest, clone.Name)
		_, err = w.clientset.AquasecurityV1alpha1().CISKubeBenchReports().Update(ctx, clone, meta.UpdateOptions{})
		if err != nil {
			return
		}
	}
	return
}

func (w *writer) removeReportsWithHistoryLimitExceeded(ctx context.Context, reports []starboard.CISKubeBenchReport) (err error) {
	limit := w.getHistoryLimit(reports)
	diff := len(reports) - limit
	if diff < 0 {
		return
	}
	for _, r := range reports[0 : diff+1] {
		klog.V(3).Infof("Removing %s report which exceeded history limit of %d", r.GetName(), limit)
		err = w.clientset.AquasecurityV1alpha1().CISKubeBenchReports().Delete(ctx, r.GetName(), meta.DeleteOptions{
			GracePeriodSeconds: pointer.Int64Ptr(0),
		})
		if err != nil {
			return
		}
	}
	return
}

func (w *writer) getHistoryLimit(reports []starboard.CISKubeBenchReport) int {
	if len(reports) == 0 {
		return defaultHistoryLimit
	}
	latestReport := reports[len(reports)-1]
	if value, ok := latestReport.Annotations[kube.AnnotationHistoryLimit]; ok {
		limit, err := strconv.Atoi(value)
		if err != nil {
			klog.V(3).Infof("Error while parsing value %s of %s annotation", value, kube.AnnotationHistoryLimit)
			return defaultHistoryLimit
		}
		return limit
	}
	return defaultHistoryLimit
}
