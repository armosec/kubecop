package webhook

import (
	"context"
	"fmt"
	"slices"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes"
)

// TODO: Implement the validations in a separate package.

type AdmissionValidator struct {
	kubernetesClient *kubernetes.Clientset
}

func NewAdmissionValidator(kubernetesClient *kubernetes.Clientset) *AdmissionValidator {
	return &AdmissionValidator{
		kubernetesClient: kubernetesClient,
	}
}

// We are implementing the Validate method from the ValidationInterface interface.
func (av *AdmissionValidator) Validate(ctx context.Context, attrs admission.Attributes, o admission.ObjectInterfaces) (err error) {
	if attrs.GetKind().GroupKind().Kind == "Pod" || attrs.GetResource().Resource == "pods" {
		// If the request is for a pod, we call the validatePods function to validate the request.
		return av.validatePods(attrs)
	} else if attrs.GetKind().GroupKind().Kind == "ClusterRoleBinding" || attrs.GetResource().Resource == "clusterrolebindings" {
		// If the request is for a clusterRoleBinding, we call the validateClusterRoleBinding function to validate the request.
		return av.validateAdminClusterRoleBinding(attrs)
	} else if attrs.GetKind().GroupKind().Kind == "RoleBinding" || attrs.GetResource().Resource == "rolebindings" {
		// If the request is for a roleBinding, we call the validateRoleBinding function to validate the request.
		return av.validateAdminRoleBinding(attrs)
	}

	return nil
}

// We are implementing the Handles method from the ValidationInterface interface.
// This method returns true if this admission controller can handle the given operation, we accept all operations.
func (av *AdmissionValidator) Handles(operation admission.Operation) bool {
	return true
}

func (av *AdmissionValidator) validateAdminRoleBinding(attrs admission.Attributes) error {
	// Check if the request is for roleBinding creation.
	if attrs.GetOperation() == admission.Create {
		var roleBinding *rbac.RoleBinding
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(attrs.GetObject().(*unstructured.Unstructured).Object, &roleBinding)
		if err != nil {
			return nil
		}

		// Fetch the role from the k8s API.
		role, err := av.kubernetesClient.RbacV1().Roles(roleBinding.GetNamespace()).Get(context.Background(), roleBinding.RoleRef.Name, metav1.GetOptions{})
		if err != nil {
			log.Debugf("Error fetching role: %v", err)
			return nil
		}

		// If the role has * in the verbs, resources or apiGroups, return an error.
		for _, rule := range role.Rules {
			if slices.Contains(rule.Verbs, "*") && slices.Contains(rule.Resources, "*") && (slices.Contains(rule.APIGroups, "*") || slices.Contains(rule.APIGroups, "")) {
				return admission.NewForbidden(attrs, fmt.Errorf("roleBinding with wildcard role is audited"))
			}
		}
	}

	return nil
}

func (av *AdmissionValidator) validateAdminClusterRoleBinding(attrs admission.Attributes) error {
	// Check if the request is for clusterRoleBinding creation.
	if attrs.GetOperation() == admission.Create {
		var clusterRoleBinding *rbac.ClusterRoleBinding
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(attrs.GetObject().(*unstructured.Unstructured).Object, &clusterRoleBinding)
		if err != nil {
			return nil
		}

		// Fetch the role from the k8s API.
		role, err := av.kubernetesClient.RbacV1().ClusterRoles().Get(context.Background(), clusterRoleBinding.RoleRef.Name, metav1.GetOptions{})
		if err != nil {
			log.Debugf("Error fetching role: %v", err)
			return nil
		}

		// If the role has * in the verbs, resources or apiGroups, return an error.
		for _, rule := range role.Rules {
			if slices.Contains(rule.Verbs, "*") && slices.Contains(rule.Resources, "*") && (slices.Contains(rule.APIGroups, "*") || slices.Contains(rule.APIGroups, "")) {
				return admission.NewForbidden(attrs, fmt.Errorf("clusterRoleBinding with wildcard role is audited"))
			}
		}
	}

	return nil
}

func (av *AdmissionValidator) validatePods(attrs admission.Attributes) error {
	// Check if the request is for pod exec or attach.
	if attrs.GetSubresource() == "exec" || attrs.GetSubresource() == "attach" {
		return admission.NewForbidden(attrs, fmt.Errorf("exec/attach to pod is audited"))
	}

	// Check if the request is for privileged container creation.
	if attrs.GetOperation() == admission.Create {
		pod, ok := attrs.GetObject().(*v1.Pod)
		if !ok {
			return nil
		}

		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				return admission.NewForbidden(attrs, fmt.Errorf("privileged container creation is audited"))
			}
		}
	}

	// Check if the request is for pod with insecure capabilities (SYS_ADMIN, SYS_MODULE, NET_ADMIN, NET_RAW, SYS_PTRACE, SYS_BOOT, SYS_RAWIO, BPF).
	if attrs.GetOperation() == admission.Create {
		pod, ok := attrs.GetObject().(*v1.Pod)
		if !ok {
			return nil
		}

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
		pod, ok := attrs.GetObject().(*v1.Pod)
		if !ok {
			return nil
		}

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
