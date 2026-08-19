package instance

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// versionServer serves a fixed currentVersion, standing in for a running pocket-id.
func versionServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"currentVersion":"` + version + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// errHalted stands in for process termination. The injected Exit panics with it rather
// than returning, so tests model os.Exit faithfully: nothing after the halt runs. A fake
// Exit that returned would let the rest of the reconcile proceed and mask an ordering bug.
var errHalted = errors.New("halted")

// runReconcile drives a full Reconcile, reporting whether the operator halted partway
// through instead of completing.
func runReconcile(t *testing.T, r *Reconciler, inst *pocketidinternalv1alpha1.PocketIDInstance) (halted bool) {
	t.Helper()
	defer func() {
		if rec := recover(); rec != nil {
			if rec != errHalted {
				panic(rec)
			}
			halted = true
		}
	}()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: inst.Name, Namespace: inst.Namespace},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return false
}

// newManagedReconciler wires a Reconciler over a fake cluster for a managed (non-external)
// instance, reporting reportedVersion from the API and halting via panic instead of exiting.
func newManagedReconciler(t *testing.T, inst *pocketidinternalv1alpha1.PocketIDInstance, reportedVersion string) *Reconciler {
	t.Helper()
	s := externalTestScheme(t)
	if err := gatewayv1.Install(s); err != nil {
		t.Fatalf("add gateway scheme: %v", err)
	}
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(inst).
		WithStatusSubresource(inst).
		Build()
	srv := versionServer(t, reportedVersion)
	return &Reconciler{
		Client:    fc,
		APIReader: fc,
		Scheme:    s,
		NewAPIClient: func(context.Context, client.Client, client.Reader, *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
			return pocketid.NewClient(srv.URL, "test-api-key")
		},
		Exit: func(int) { panic(errHalted) },
	}
}

func managedInstance(image string) *pocketidinternalv1alpha1.PocketIDInstance {
	inst := minimalInstance()
	inst.Namespace = "default"
	inst.Spec.Image = image
	return inst
}

// A managed instance running a too-old pocket-id must still get its Deployment patched
// with the new spec.image before the operator halts. Otherwise bumping spec.image could
// never take effect: the operator is the only thing that writes the Deployment, so a halt
// that preempted the workload apply would wedge the instance on the unsupported version
// with no way out through the CR.
func TestReconcile_AppliesImageBeforeHaltingOnOldVersion(t *testing.T) {
	ctx := context.Background()
	const newImage = "ghcr.io/pocket-id/pocket-id:v2.14.0-distroless"

	inst := managedInstance(newImage)
	r := newManagedReconciler(t, inst, "2.13.0")

	if !runReconcile(t, r, inst) {
		t.Error("expected the operator to halt on an unsupported version")
	}

	deploy := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: inst.Name, Namespace: inst.Namespace}, deploy); err != nil {
		t.Fatalf("deployment was never applied, so bumping spec.image could not recover: %v", err)
	}
	got := deploy.Spec.Template.Spec.Containers[0].Image
	if got != newImage {
		t.Errorf("deployment image = %q, want %q; the halt preempted the workload apply", got, newImage)
	}
}

// Once the rollout lands and the instance reports a supported version, reconciles proceed
// without halting. This is the other half of the recovery path.
func TestReconcile_NoHaltOnceVersionIsSupported(t *testing.T) {
	ctx := context.Background()

	inst := managedInstance("ghcr.io/pocket-id/pocket-id:v2.14.0-distroless")
	r := newManagedReconciler(t, inst, "2.14.0")

	if runReconcile(t, r, inst) {
		t.Error("a supported version must not halt")
	}

	got := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(inst), got); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if got.Status.Version != "2.14.0" {
		t.Errorf("status.version = %q, want %q", got.Status.Version, "2.14.0")
	}
}

// External instances have no operator-managed workload, so the halt is the whole story:
// the user must upgrade pocket-id out of band. Recorded so the asymmetry is deliberate.
func TestReconcileExternal_HaltsOnOldVersionWithNoWorkloadToPatch(t *testing.T) {
	ctx := context.Background()
	srv := versionServer(t, "2.13.0")

	halted := 0
	inst := newExternalInstance(srv.URL)
	r := newReconcilerFor(t, inst, apiKeySecret())
	r.Exit = func(int) { halted++ }

	if _, err := r.reconcileExternal(ctx, inst); err != nil {
		t.Fatalf("reconcileExternal: %v", err)
	}

	if halted != 1 {
		t.Errorf("halt count = %d, want 1", halted)
	}

	// The detected version is persisted before halting so operators can see why.
	got := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(inst), got); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if got.Status.Version != "2.13.0" {
		t.Errorf("status.version = %q, want %q", got.Status.Version, "2.13.0")
	}
}
