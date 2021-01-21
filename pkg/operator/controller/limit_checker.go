package controller

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type LimitChecker interface {
	Check(ctx context.Context) (bool, int, error)
}

func NewLimitChecker(config etc.Config, client client.Client) LimitChecker {
	return &checker{
		config: config,
		client: client,
	}
}

type checker struct {
	config etc.Config
	client client.Client
}

func (c *checker) Check(ctx context.Context) (bool, int, error) {
	scanJobsCount, err := c.countScanJobs(ctx)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentScanJobsLimit, scanJobsCount, nil
}

func (c *checker) countScanJobs(ctx context.Context) (int, error) {
	var scanJobs batchv1.JobList
	err := c.client.List(ctx, &scanJobs, client.MatchingLabels{
		kube.LabelK8SAppManagedBy: kube.AppStarboardOperator,
	}, client.InNamespace(c.config.Namespace))
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}
