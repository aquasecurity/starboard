package controller

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type LimitChecker interface {
	Check(ctx context.Context) (bool, int, error)
}

func NewLimitChecker(config etc.Config, client client.Client, starboardConfig starboard.ConfigData) LimitChecker {
	return &checker{
		config:          config,
		client:          client,
		starboardConfig: starboardConfig,
	}
}

type checker struct {
	config          etc.Config
	client          client.Client
	starboardConfig starboard.ConfigData
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
	listOptions := []client.ListOption{client.MatchingLabels{
		starboard.LabelK8SAppManagedBy: starboard.AppStarboard,
	}}
	if !c.starboardConfig.VulnerabilityScanJobsInSameNamespace() {
		// scan jobs are running in only starboard operator namespace
		listOptions = append(listOptions, client.InNamespace(c.config.Namespace))
	}
	err := c.client.List(ctx, &scanJobs, listOptions...)
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}
