package webhook

import (
	"context"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apiserver/pkg/admission"
)

// TODO: Implement the validations in a separate package.

type AdmissionValidator struct {
}

func NewAdmissionValidator() *AdmissionValidator {
	return &AdmissionValidator{}
}

// We are implementing the Validate method from the ValidationInterface interface.
func (av *AdmissionValidator) Validate(ctx context.Context, attrs admission.Attributes, o admission.ObjectInterfaces) (err error) {
	// Check if the request is for a pod
	if attrs.GetKind().GroupKind().Kind == "Pod" {
		// If the request is for a pod, we call the validatePods function to validate the request.
		return validatePods(attrs)
	}

	return nil
}

// We are implementing the Handles method from the ValidationInterface interface.
// This method returns true if this admission controller can handle the given operation, we accept all operations.
func (av *AdmissionValidator) Handles(operation admission.Operation) bool {
	return true
}

func validatePods(attrs admission.Attributes) error {
	var err error

	// Check if the request is for pod exec or attach.
	if attrs.GetSubresource() == "exec" || attrs.GetSubresource() == "attach" {
		attrs.AddAnnotation("admission-message", "exec/attach audit")
		return admission.NewForbidden(attrs, err)
	}

	// Check if the request is for privileged container creation.
	if attrs.GetOperation() == admission.Create {
		// Get the pod object from the request.
		pod := attrs.GetObject().(*v1.Pod)
		for _, container := range pod.Spec.Containers {
			// If a container is privileged, return an error.
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				attrs.AddAnnotation("admission-message", "privileged container creation")
				return admission.NewForbidden(attrs, err)
			}
		}
	}

	// Check if the request is for pod with hostMounts.
	if attrs.GetOperation() == admission.Create {
		// Get the pod object from the request.
		pod := attrs.GetObject().(*v1.Pod)
		for _, volume := range pod.Spec.Volumes {
			// If a volume is a hostPath, return an error.
			if volume.HostPath != nil {
				attrs.AddAnnotation("admission-message", "hostPath volume creation")
				return admission.NewForbidden(attrs, err)
			}
		}
	}

	return nil
}
