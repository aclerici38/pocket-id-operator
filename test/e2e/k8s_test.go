//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This file replaces the kubectl subprocess layer with typed API calls. Specs still name
// resources the way kubectl does ("pocketiduser", "secret"), so the strings they already
// pass keep working; resourceGVK is what turns those names into something the client can
// address.

const fieldOwner = client.FieldOwner("pocket-id-e2e")

var resourceGVK = map[string]schema.GroupVersionKind{
	"pocketiduser":       {Group: "pocketid.internal", Version: "v1alpha1", Kind: "PocketIDUser"},
	"pocketidusergroup":  {Group: "pocketid.internal", Version: "v1alpha1", Kind: "PocketIDUserGroup"},
	"pocketidoidcclient": {Group: "pocketid.internal", Version: "v1alpha1", Kind: "PocketIDOIDCClient"},
	"pocketidapi":        {Group: "pocketid.internal", Version: "v1alpha1", Kind: "PocketIDAPI"},
	"pocketidinstance":   {Group: "pocketid.internal", Version: "v1alpha1", Kind: "PocketIDInstance"},
	"secret":             {Version: "v1", Kind: "Secret"},
	"pod":                {Version: "v1", Kind: "Pod"},
	"service":            {Version: "v1", Kind: "Service"},
	"pvc":                {Version: "v1", Kind: "PersistentVolumeClaim"},
	"configmap":          {Version: "v1", Kind: "ConfigMap"},
	"deployment":         {Group: "apps", Version: "v1", Kind: "Deployment"},
	"statefulset":        {Group: "apps", Version: "v1", Kind: "StatefulSet"},
	"httproute":          {Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"},
	"crd":                {Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"},
}

// newObjectFor returns an empty object addressed at the given resource name.
func newObjectFor(resource string) *unstructured.Unstructured {
	GinkgoHelper()
	gvk, ok := resourceGVK[strings.ToLower(resource)]
	Expect(ok).To(BeTrue(), "no GVK registered for resource %q — add it to resourceGVK", resource)
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	return obj
}

// getObject reads one object. A missing object is reported through the error, so callers
// can tell "absent" from "failed to look up" — which the old kubectlGet, returning "" for
// both, could not.
func getObject(resource, name, namespace string) (*unstructured.Unstructured, error) {
	obj := newObjectFor(resource)
	err := k8sClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: namespace}, obj)
	return obj, err
}

// splitPath breaks a field path into segments on dots that are neither inside brackets
// nor escaped, so a filter's interior (@.key) and an escaped key (annotations.a\.b/c)
// both stay with the segment they belong to.
func splitPath(path string) []string {
	var out []string
	depth, escaped, current := 0, false, strings.Builder{}
	for _, r := range strings.TrimPrefix(path, ".") {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '[':
			depth++
			current.WriteRune(r)
		case r == ']':
			depth--
			current.WriteRune(r)
		case r == '.' && depth == 0:
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

// pathSegment splits one step into its field name and optional subscript: an index ([0]),
// a wildcard ([*]) or a filter over a list of objects ([?(@.key=='value')]).
var pathSegment = regexp.MustCompile(`^([^\[]+)(?:\[(\d+)\]|(\[\*\])|\[\?\(@\.([a-zA-Z0-9_]+)==['"]([^'"]*)['"]\)\])?$`)

// fieldString evaluates the jsonpath subset these specs use and renders the result the way
// kubectl did: scalars plain, a [*] wildcard space-joined, and anything structural as JSON.
// An absent field — or an empty list — renders as "", which is what the specs assert when
// they expect nothing to be there.
func fieldString(obj *unstructured.Unstructured, path string) string {
	GinkgoHelper()

	var current any = obj.Object
	wildcard := false

	for _, segment := range splitPath(path) {
		parent, ok := current.(map[string]any)
		if !ok {
			return ""
		}

		match := pathSegment.FindStringSubmatch(segment)
		Expect(match).NotTo(BeNil(), "unsupported path segment %q in %q", segment, path)
		name, index, star, filterKey, filterValue := match[1], match[2], match[3], match[4], match[5]

		value, present := parent[name]
		if !present || value == nil {
			return ""
		}

		switch {
		case index != "":
			items, ok := value.([]any)
			i, _ := strconv.Atoi(index)
			if !ok || i >= len(items) {
				return ""
			}
			current = items[i]
		case star != "":
			if _, ok := value.([]any); !ok {
				return ""
			}
			wildcard = true
			current = value
		case filterKey != "":
			items, ok := value.([]any)
			if !ok {
				return ""
			}
			current = nil
			for _, item := range items {
				if entry, ok := item.(map[string]any); ok && fmt.Sprint(entry[filterKey]) == filterValue {
					current = entry
					break
				}
			}
			if current == nil {
				return ""
			}
		default:
			current = value
		}
	}

	return renderValue(current, wildcard)
}

// renderValue reproduces kubectl's jsonpath output for one resolved value.
func renderValue(value any, wildcard bool) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []any:
		if len(typed) == 0 {
			return ""
		}
		if wildcard {
			parts := make([]string, 0, len(typed))
			for _, item := range typed {
				parts = append(parts, renderValue(item, false))
			}
			return strings.Join(parts, " ")
		}
		return asJSON(typed)
	case map[string]any:
		if len(typed) == 0 {
			return ""
		}
		return asJSON(typed)
	default:
		return fmt.Sprint(typed)
	}
}

func asJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}

// conditionField returns one field of a named condition, or "" when the condition is absent.
func conditionField(obj *unstructured.Unstructured, conditionType, field string) string {
	conditions, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil || !found {
		return ""
	}
	for _, entry := range conditions {
		condition, ok := entry.(map[string]any)
		if !ok || condition["type"] != conditionType {
			continue
		}
		if value, present := condition[field]; present && value != nil {
			return fmt.Sprint(value)
		}
	}
	return ""
}

// applyYAML applies one or more manifests, the way `kubectl apply -f -` did. Server-side
// apply is used so a re-apply of the same document reconciles fields this suite owns
// rather than colliding with the operator's.
func applyYAML(yaml string) {
	GinkgoHelper()
	Expect(applyYAMLErr(yaml)).To(Succeed())
}

// applyYAMLErr is applyYAML for callers that assert on the failure, such as the specs that
// require admission to reject a manifest.
func applyYAMLErr(yaml string) error {
	decoder := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(yaml), 4096)
	for {
		obj := &unstructured.Unstructured{}
		if err := decoder.Decode(obj); err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return fmt.Errorf("decoding manifest: %w", err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		if err := k8sClient.Apply(context.Background(),
			client.ApplyConfigurationFromUnstructured(obj), fieldOwner, client.ForceOwnership); err != nil {
			return err
		}
	}
}

func deleteObject(resource, name, namespace string) {
	obj := newObjectFor(resource)
	obj.SetName(name)
	obj.SetNamespace(namespace)
	_ = k8sClient.Delete(context.Background(), obj)
}

// deleteObjectAndWait deletes and waits for the object to actually go away, so a finalizer
// that never releases surfaces here rather than in a later spec.
func deleteObjectAndWait(resource, name, namespace string, timeout time.Duration) error {
	deleteObject(resource, name, namespace)

	deadline := time.Now().Add(timeout)
	for {
		if _, err := getObject(resource, name, namespace); isGone(err) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s/%s in %s still exists after %s", resource, name, namespace, timeout)
		}
		time.Sleep(time.Second)
	}
}

// patchObject applies a merge patch, replacing `kubectl patch --type=merge`.
func patchObject(resource, name, namespace, patch string) error {
	obj := newObjectFor(resource)
	obj.SetName(name)
	obj.SetNamespace(namespace)
	return k8sClient.Patch(context.Background(), obj, client.RawPatch(types.MergePatchType, []byte(patch)))
}

// annotateObject sets one "key=value" annotation, replacing `kubectl annotate --overwrite`.
func annotateObject(resource, name, namespace, annotation string) error {
	key, value, found := strings.Cut(annotation, "=")
	if !found {
		return fmt.Errorf("annotation %q is not key=value", annotation)
	}
	return patchObject(resource, name, namespace,
		fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, key, value))
}

// getField reads one field of an object, returning "" when either the object or the field
// is absent. This is the direct replacement for a kubectlGet with a jsonpath output.
func getField(resource, name, namespace, path string) string {
	GinkgoHelper()
	obj, err := getObject(resource, name, namespace)
	if err != nil {
		return ""
	}
	return fieldString(obj, path)
}

// getFieldBySelector reads a field from the first object matching a label selector, the way
// `kubectl get -l ... -o jsonpath={.items[0]...}` did. Callers pass the path relative to the
// item, without the ".items[0]" prefix.
func getFieldBySelector(resource, namespace, selector, path string) string {
	GinkgoHelper()

	parsed, err := labels.Parse(selector)
	Expect(err).NotTo(HaveOccurred(), "parsing selector %q", selector)

	list := &unstructured.UnstructuredList{}
	gvk := resourceGVK[strings.ToLower(resource)]
	gvk.Kind += "List"
	list.SetGroupVersionKind(gvk)

	if err := k8sClient.List(context.Background(), list,
		client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: parsed}); err != nil {
		return ""
	}
	if len(list.Items) == 0 {
		return ""
	}
	return fieldString(&list.Items[0], path)
}

// objectExists reports whether a single object is present. A missing kind counts as absent,
// which matters for the httproute specs that uninstall the Gateway API CRD.
func objectExists(resource, name, namespace string) bool {
	_, err := getObject(resource, name, namespace)
	return err == nil
}

// listNames returns the names of every object of a kind in a namespace.
func listNames(resource, namespace string) []string {
	GinkgoHelper()

	list := &unstructured.UnstructuredList{}
	gvk := resourceGVK[strings.ToLower(resource)]
	gvk.Kind += "List"
	list.SetGroupVersionKind(gvk)

	if err := k8sClient.List(context.Background(), list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	names := make([]string, 0, len(list.Items))
	for i := range list.Items {
		names = append(names, list.Items[i].GetName())
	}
	return names
}

// getClusterField reads a field from a cluster-scoped object, such as a CRD.
func getClusterField(resource, name, path string) string {
	GinkgoHelper()
	return getField(resource, name, "", path)
}
