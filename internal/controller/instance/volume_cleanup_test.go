package instance

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

func volumeTestReconciler(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	s := externalTestScheme(t)
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return &Reconciler{Client: fc, APIReader: fc, Scheme: s}
}

const (
	volumeTestInstance = "inst"
	volumeTestPVCName  = volumeTestInstance + "-data"
)

func dataPVC(managed bool) *corev1.PersistentVolumeClaim {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      volumeTestPVCName,
			Namespace: "default",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
			},
		},
	}
	if managed {
		pvc.Labels = map[string]string{common.ManagedByLabelKey: common.ManagedByLabelValue}
	}
	return pvc
}

func pvcExists(t *testing.T, r *Reconciler) bool {
	t.Helper()
	err := r.Get(context.Background(), types.NamespacedName{Name: volumeTestPVCName, Namespace: "default"}, &corev1.PersistentVolumeClaim{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("unexpected error getting pvc %s: %v", volumeTestPVCName, err)
	return false
}

// --- deleteIfManaged ---

func TestDeleteIfManaged_DeletesManagedObject(t *testing.T) {
	pvc := dataPVC(true)
	r := volumeTestReconciler(t, pvc)

	if err := r.deleteIfManaged(context.Background(), pvc.DeepCopy(), "deleting test PVC"); err != nil {
		t.Fatalf("deleteIfManaged returned error: %v", err)
	}
	if pvcExists(t, r) {
		t.Fatal("expected managed PVC to be deleted")
	}
}

func TestDeleteIfManaged_PreservesUnmanagedObject(t *testing.T) {
	pvc := dataPVC(false)
	r := volumeTestReconciler(t, pvc)

	if err := r.deleteIfManaged(context.Background(), pvc.DeepCopy(), "deleting test PVC"); err != nil {
		t.Fatalf("deleteIfManaged returned error: %v", err)
	}
	if !pvcExists(t, r) {
		t.Fatal("expected unmanaged (user-owned) PVC to be preserved")
	}
}

func TestDeleteIfManaged_MissingObjectIsNoOp(t *testing.T) {
	r := volumeTestReconciler(t)
	if err := r.deleteIfManaged(context.Background(), dataPVC(true), "deleting test PVC"); err != nil {
		t.Fatalf("deleteIfManaged returned error for missing object: %v", err)
	}
}

// --- reconcileVolume cleanup branches must not delete user-owned PVCs ---

func instanceForVolume(mutate func(*pocketidinternalv1alpha1.PocketIDInstanceSpec)) *pocketidinternalv1alpha1.PocketIDInstance {
	inst := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: volumeTestInstance, Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Persistence: pocketidinternalv1alpha1.PersistenceConfig{
				Enabled: true,
				Size:    resource.MustParse("1Gi"),
			},
		},
	}
	mutate(&inst.Spec)
	return inst
}

func TestReconcileVolume_PersistenceDisabledPreservesUserPVC(t *testing.T) {
	inst := instanceForVolume(func(s *pocketidinternalv1alpha1.PocketIDInstanceSpec) {
		s.Persistence.Enabled = false
	})
	userPVC := dataPVC(false)
	r := volumeTestReconciler(t, inst, userPVC)

	if err := r.reconcileVolume(context.Background(), inst); err != nil {
		t.Fatalf("reconcileVolume returned error: %v", err)
	}
	if !pvcExists(t, r) {
		t.Fatal("expected user-owned PVC to be preserved when persistence is disabled")
	}
}

func TestReconcileVolume_PersistenceDisabledDeletesManagedPVC(t *testing.T) {
	inst := instanceForVolume(func(s *pocketidinternalv1alpha1.PocketIDInstanceSpec) {
		s.Persistence.Enabled = false
	})
	managedPVC := dataPVC(true)
	r := volumeTestReconciler(t, inst, managedPVC)

	if err := r.reconcileVolume(context.Background(), inst); err != nil {
		t.Fatalf("reconcileVolume returned error: %v", err)
	}
	if pvcExists(t, r) {
		t.Fatal("expected operator-managed PVC to be deleted when persistence is disabled")
	}
}

func TestReconcileVolume_StatefulSetPreservesUserPVC(t *testing.T) {
	inst := instanceForVolume(func(s *pocketidinternalv1alpha1.PocketIDInstanceSpec) {
		s.DeploymentType = "StatefulSet"
	})
	userPVC := dataPVC(false)
	r := volumeTestReconciler(t, inst, userPVC)

	if err := r.reconcileVolume(context.Background(), inst); err != nil {
		t.Fatalf("reconcileVolume returned error: %v", err)
	}
	if !pvcExists(t, r) {
		t.Fatal("expected user-owned PVC to be preserved for StatefulSet deployment")
	}
}

func TestReconcileVolume_DifferentExistingClaimPreservesUserPVC(t *testing.T) {
	inst := instanceForVolume(func(s *pocketidinternalv1alpha1.PocketIDInstanceSpec) {
		s.Persistence.ExistingClaim = "some-other-claim"
	})
	userPVC := dataPVC(false)
	r := volumeTestReconciler(t, inst, userPVC)

	if err := r.reconcileVolume(context.Background(), inst); err != nil {
		t.Fatalf("reconcileVolume returned error: %v", err)
	}
	if !pvcExists(t, r) {
		t.Fatal("expected user-owned default-named PVC to be preserved when a different existingClaim is set")
	}
}
