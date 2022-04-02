package configauditreport

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/policy"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type AdmissionHandler struct {
	Config  etc.Config
	Client  client.Client
	Decoder *admission.Decoder
}

func (h *AdmissionHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}

	err := h.Decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	policies, err := h.policies(ctx)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	results, err := policies.Eval(ctx, pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	for _, result := range results {
		if !result.Success {
			admission.Denied(fmt.Sprintf("configuration audit policy failed: %s", result.Metadata.Title))
		}
	}

	return admission.Allowed("")
}

func (h *AdmissionHandler) policies(ctx context.Context) (*policy.Policies, error) {
	cm := &corev1.ConfigMap{}

	err := h.Client.Get(ctx, client.ObjectKey{
		Namespace: h.Config.Namespace,
		Name:      starboard.PoliciesConfigMapName,
	}, cm)
	if err != nil {
		return nil, fmt.Errorf("failed getting policies from configmap: %s/%s: %w", h.Config.Namespace, starboard.PoliciesConfigMapName, err)
	}
	return policy.NewPolicies(cm.Data), nil
}

// InjectDecoder injects the Decoder.
func (h *AdmissionHandler) InjectDecoder(decoder *admission.Decoder) error {
	h.Decoder = decoder
	return nil
}
