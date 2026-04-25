package instance

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildPodTemplate_NoPodTemplate(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Image = "ghcr.io/pocket-id/pocket-id:v2.0.0"

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if len(pt.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(pt.Spec.Containers))
	}
	if pt.Spec.Containers[0].Name != "pocket-id" {
		t.Errorf("container name: got %q, want %q", pt.Spec.Containers[0].Name, "pocket-id")
	}
	if pt.Spec.Containers[0].Image != "ghcr.io/pocket-id/pocket-id:v2.0.0" {
		t.Errorf("image: got %q, want %q", pt.Spec.Containers[0].Image, "ghcr.io/pocket-id/pocket-id:v2.0.0")
	}
}

func TestBuildPodTemplate_PocketIDContainerAlwaysFirst(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.PodTemplate = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "sidecar", Image: "sidecar:latest"},
			},
		},
	}

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if pt.Spec.Containers[0].Name != "pocket-id" {
		t.Errorf("expected pocket-id to be first container, got %q", pt.Spec.Containers[0].Name)
	}
	if len(pt.Spec.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(pt.Spec.Containers))
	}
	if pt.Spec.Containers[1].Name != "sidecar" {
		t.Errorf("expected sidecar second, got %q", pt.Spec.Containers[1].Name)
	}
}

func TestBuildPodTemplate_InitContainersPassThrough(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.PodTemplate = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{
					Name:  "init-db",
					Image: "ghcr.io/home-operations/postgres-init:18",
				},
			},
		},
	}

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if len(pt.Spec.InitContainers) != 1 {
		t.Fatalf("expected 1 init container, got %d", len(pt.Spec.InitContainers))
	}
	if pt.Spec.InitContainers[0].Name != "init-db" {
		t.Errorf("init container name: got %q, want %q", pt.Spec.InitContainers[0].Name, "init-db")
	}
}

func TestBuildPodTemplate_PodSpecFieldsPassThrough(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.PodTemplate = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Tolerations: []corev1.Toleration{
				{Key: "node-role", Operator: corev1.TolerationOpEqual, Value: "storage", Effect: corev1.TaintEffectNoSchedule},
			},
			NodeSelector:      map[string]string{"kubernetes.io/arch": "amd64"},
			PriorityClassName: "high-priority",
		},
	}

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if len(pt.Spec.Tolerations) != 1 || pt.Spec.Tolerations[0].Key != "node-role" {
		t.Errorf("tolerations not passed through: %+v", pt.Spec.Tolerations)
	}
	if pt.Spec.NodeSelector["kubernetes.io/arch"] != "amd64" {
		t.Errorf("nodeSelector not passed through: %+v", pt.Spec.NodeSelector)
	}
	if pt.Spec.PriorityClassName != "high-priority" {
		t.Errorf("priorityClassName: got %q, want %q", pt.Spec.PriorityClassName, "high-priority")
	}
}

func TestBuildPodTemplate_LabelsIgnoredFromPodTemplate(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Labels = map[string]string{"env": "prod"}
	inst.Spec.PodTemplate = &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{"env": "should-be-ignored", "other": "also-ignored"},
			Annotations: map[string]string{"pod-annotation": "also-ignored"},
		},
	}

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if pt.Labels["env"] != "prod" {
		t.Errorf("label 'env': got %q, want %q", pt.Labels["env"], "prod")
	}
	if _, ok := pt.Labels["other"]; ok {
		t.Error("podTemplate label 'other' should not be present")
	}
	if _, ok := pt.Annotations["pod-annotation"]; ok {
		t.Error("podTemplate annotation should not be present")
	}
}

func TestBuildPodTemplate_OperatorLabelsAlwaysSet(t *testing.T) {
	inst := minimalInstance()

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if pt.Labels["app.kubernetes.io/name"] != "pocket-id" {
		t.Errorf("missing app.kubernetes.io/name label")
	}
	if pt.Labels["app.kubernetes.io/instance"] != inst.Name {
		t.Errorf("missing app.kubernetes.io/instance label")
	}
}

func TestBuildPodTemplate_StaticAPIKeyHashAnnotation(t *testing.T) {
	inst := minimalInstance()

	pt := (&Reconciler{}).buildPodTemplate(inst, "abc123hash")

	if pt.Annotations["pocketid.internal/static-api-key-hash"] != "abc123hash" {
		t.Errorf("hash annotation: got %q, want %q", pt.Annotations["pocketid.internal/static-api-key-hash"], "abc123hash")
	}
}

func TestBuildPodTemplate_UserVolumesPreserved(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.PodTemplate = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "custom-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-config"},
						},
					},
				},
			},
		},
	}

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	volumeNames := make(map[string]bool)
	for _, v := range pt.Spec.Volumes {
		volumeNames[v.Name] = true
	}
	if !volumeNames["data"] {
		t.Error("operator's 'data' volume missing")
	}
	if !volumeNames["custom-config"] {
		t.Error("user's 'custom-config' volume missing")
	}
}

func TestBuildPodTemplate_OperatorFieldsNotOverriddenByPodTemplate(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Image = "ghcr.io/pocket-id/pocket-id:v2.0.0"
	inst.Spec.Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}
	inst.Spec.PodTemplate = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			// A "pocket-id" container here should be ignored — operator builds it fresh
			Containers: []corev1.Container{
				{Name: "pocket-id", Image: "attacker/malicious:latest"},
			},
		},
	}

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if pt.Spec.Containers[0].Image != "ghcr.io/pocket-id/pocket-id:v2.0.0" {
		t.Errorf("operator image should win, got %q", pt.Spec.Containers[0].Image)
	}
	// The podTemplate "pocket-id" container becomes a sidecar since we prepend
	if len(pt.Spec.Containers) != 2 {
		t.Errorf("expected 2 containers (operator's + podTemplate's pocket-id treated as sidecar), got %d", len(pt.Spec.Containers))
	}
}
