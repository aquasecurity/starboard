package controller

import (
	"context"
	"fmt"
	"reflect"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Analyzer interface {
	HasVulnerabilityReports(ctx context.Context, owner kube.Object, images kube.ContainerImages, hash string) (bool, error)
	GetActiveScanJob(ctx context.Context, owner kube.Object, hash string) (*batchv1.Job, error)
	IsConcurrentScanJobsLimitExceeded(ctx context.Context) (bool, int, error)
}

func NewAnalyzer(config etc.Operator, store vulnerabilityreport.StoreInterface, client client.Client) Analyzer {
	return &analyzer{
		config: config,
		store:  store,
		client: client,
	}
}

type analyzer struct {
	config etc.Operator
	client client.Client
	store  vulnerabilityreport.StoreInterface
}

func (a *analyzer) HasVulnerabilityReports(ctx context.Context, owner kube.Object, images kube.ContainerImages, hash string) (bool, error) {
	list, err := a.store.FindByOwner(ctx, owner)
	if err != nil {
		return false, err
	}

	actual := map[string]bool{}
	for _, report := range list {
		if containerName, ok := report.Labels[kube.LabelContainerName]; ok {
			if hash == report.Labels[kube.LabelPodSpecHash] {
				actual[containerName] = true
			}
		}
	}

	expected := map[string]bool{}
	for containerName, _ := range images {
		expected[containerName] = true
	}

	return reflect.DeepEqual(actual, expected), nil
}

func (a *analyzer) GetActiveScanJob(ctx context.Context, owner kube.Object, hash string) (*batchv1.Job, error) {
	jobList := &batchv1.JobList{}
	err := a.client.List(ctx, jobList, client.MatchingLabels{
		kube.LabelResourceNamespace: owner.Namespace,
		kube.LabelResourceKind:      string(owner.Kind),
		kube.LabelResourceName:      owner.Name,
		kube.LabelPodSpecHash:       hash,
	}, client.InNamespace(a.config.Namespace))
	if err != nil {
		return nil, fmt.Errorf("listing scan jobs: %w", err)
	}
	if len(jobList.Items) > 0 {
		return jobList.Items[0].DeepCopy(), nil
	}
	return nil, nil
}

func (a *analyzer) IsConcurrentScanJobsLimitExceeded(ctx context.Context) (bool, int, error) {
	scanJobsCount, err := a.countScanJobs(ctx)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= a.config.ConcurrentScanJobsLimit, scanJobsCount, nil
}

func (a *analyzer) countScanJobs(ctx context.Context) (int, error) {
	var scanJobs batchv1.JobList
	err := a.client.List(ctx, &scanJobs, client.MatchingLabels{
		kube.LabelK8SAppManagedBy: kube.AppStarboardOperator,
	}, client.InNamespace(a.config.Namespace))
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}
