package common

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metav1apply "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// ControllerOwnerReference builds an apply configuration owner reference for controller ownership.
func ControllerOwnerReference(owner metav1.Object, scheme *runtime.Scheme) (*metav1apply.OwnerReferenceApplyConfiguration, error) {
	ro, ok := owner.(runtime.Object)
	if !ok {
		return nil, fmt.Errorf("%T is not a runtime.Object", owner)
	}

	gvk, err := apiutil.GVKForObject(ro, scheme)
	if err != nil {
		return nil, err
	}

	return metav1apply.OwnerReference().
		WithAPIVersion(gvk.GroupVersion().String()).
		WithKind(gvk.Kind).
		WithName(owner.GetName()).
		WithUID(owner.GetUID()).
		WithController(true).
		WithBlockOwnerDeletion(true), nil
}
