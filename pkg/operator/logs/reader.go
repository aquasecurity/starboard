package logs

import (
	"context"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reader wraps kubernetes.Interface to access Pod logs.
type Reader struct {
	clientset kubernetes.Interface
}

// NewReader constructs a new Reader with the specified kubernetes.Interface.
func NewReader(clientset kubernetes.Interface) *Reader {
	return &Reader{
		clientset: clientset,
	}
}

func (r *Reader) GetLogsForPod(ctx context.Context, key client.ObjectKey, options *corev1.PodLogOptions) (io.ReadCloser, error) {
	return r.clientset.CoreV1().Pods(key.Namespace).GetLogs(key.Name, options).Stream(ctx)
}
