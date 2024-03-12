package webhook

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"

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
	if attrs.GetKind().GroupKind().Kind == "Pod" || attrs.GetResource().Resource == "pods" {
		// If the request is for a pod, we call the validatePods function to validate the request.
		return validatePods(attrs)
	} else if attrs.GetKind().GroupKind().Kind == "ClusterRoleBinding" || attrs.GetResource().Resource == "clusterrolebindings" {
		// If the request is for a clusterRoleBinding, we call the validateClusterRoleBinding function to validate the request.
		return validateClusterRoleBinding(attrs)
	}

	return nil
}

// We are implementing the Handles method from the ValidationInterface interface.
// This method returns true if this admission controller can handle the given operation, we accept all operations.
func (av *AdmissionValidator) Handles(operation admission.Operation) bool {
	return true
}

func validateClusterRoleBinding(attrs admission.Attributes) error {
	// Check if the request is for clusterRoleBinding creation.
	if attrs.GetOperation() == admission.Create {
		clusterRoleBinding := attrs.GetObject().(*rbac.ClusterRoleBinding)
		// If the clusterRoleBinding has a roleRef with a name that contains the string "admin", return an error.
		if clusterRoleBinding.RoleRef.Name == "admin" {
			return admission.NewForbidden(attrs, fmt.Errorf("clusterRoleBinding with admin role is audited"))
		}
	}

	return nil
}

func validatePods(attrs admission.Attributes) error {
	// Check if the request is for pod exec or attach.
	if attrs.GetSubresource() == "exec" || attrs.GetSubresource() == "attach" {
		return admission.NewForbidden(attrs, fmt.Errorf("exec/attach to pod is audited"))
	}

	// Check if the request is for privileged container creation.
	if attrs.GetOperation() == admission.Create {
		pod := attrs.GetObject().(*v1.Pod)
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				return admission.NewForbidden(attrs, fmt.Errorf("privileged container creation is audited"))
			}
		}
	}

	// Check if the request is for pod with insecure capabilities (SYS_ADMIN, SYS_MODULE, NET_ADMIN, NET_RAW, SYS_PTRACE, SYS_BOOT, SYS_RAWIO, BPF).
	if attrs.GetOperation() == admission.Create {
		pod := attrs.GetObject().(*v1.Pod)
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
				for _, capability := range container.SecurityContext.Capabilities.Add {
					if capability == "SYS_ADMIN" || capability == "SYS_MODULE" || capability == "NET_ADMIN" || capability == "NET_RAW" || capability == "SYS_PTRACE" || capability == "SYS_BOOT" || capability == "SYS_RAWIO" || capability == "BPF" {
						return admission.NewForbidden(attrs, fmt.Errorf("insecure capability is audited"))
					}
				}
			}
		}
	}

	// Check if the request is for pod with hostMounts.
	if attrs.GetOperation() == admission.Create {
		pod := attrs.GetObject().(*v1.Pod)
		for _, volume := range pod.Spec.Volumes {
			// If a volume is a hostPath, return an error.
			if volume.HostPath != nil {
				return admission.NewForbidden(attrs, fmt.Errorf("hostPath volume is audited"))
			}
		}
	}

	// Check if the request is for port-forwarding.
	if attrs.GetSubresource() == "portforward" {
		return admission.NewForbidden(attrs, fmt.Errorf("port-forwarding is audited"))
	}

	return nil
}
