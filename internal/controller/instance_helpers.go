package controller

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

var (
	errNoInstance       = errors.New("no PocketIDInstance found")
	errMultipleInstance = errors.New("multiple PocketIDInstances found")
)

func selectInstance(ctx context.Context, c client.Client, selector *metav1.LabelSelector) (*pocketidinternalv1alpha1.PocketIDInstance, error) {
	instances := &pocketidinternalv1alpha1.PocketIDInstanceList{}
	listOpts := []client.ListOption{}

	selectorString := "default instance"
	if selector != nil {
		parsed, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return nil, fmt.Errorf("invalid instanceSelector: %w", err)
		}
		selectorString = parsed.String()
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: parsed})
	}

	if err := c.List(ctx, instances, listOpts...); err != nil {
		return nil, err
	}

	if len(instances.Items) == 0 {
		return nil, fmt.Errorf("%w for selector %q", errNoInstance, selectorString)
	}
	if len(instances.Items) > 1 {
		return nil, fmt.Errorf("%w for selector %q", errMultipleInstance, selectorString)
	}

	return &instances.Items[0], nil
}

func instanceReady(instance *pocketidinternalv1alpha1.PocketIDInstance) bool {
	for _, cond := range instance.Status.Conditions {
		if cond.Type == "Ready" && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// internalServiceURL returns the internal Kubernetes service URL for the instance
func internalServiceURL(instanceName, namespace string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:1411", instanceName, namespace)
}
