package controller

import (
	"context"
	batchv1 "k8s.io/api/batch/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func findJob(ctx context.Context, req ctrl.Request, c client.Client) (*batchv1.Job, error) {
	job := &batchv1.Job{}
	err := c.Get(ctx, req.NamespacedName, job)
	if err != nil {
		return nil, err
	}
	return job, nil
}
