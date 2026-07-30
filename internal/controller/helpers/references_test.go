package helpers

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// fakeUserGroupLookup serves user groups from a fixed set, mimicking Pocket-ID's
// substring search.
type fakeUserGroupLookup struct {
	groups   []*pocketid.UserGroup
	listErr  error
	listCall int
}

func (f *fakeUserGroupLookup) ListUserGroups(_ context.Context, search string) ([]*pocketid.UserGroup, error) {
	f.listCall++
	if f.listErr != nil {
		return nil, f.listErr
	}
	var matches []*pocketid.UserGroup
	for _, group := range f.groups {
		if strings.Contains(group.Name, search) {
			matches = append(matches, group)
		}
	}
	return matches, nil
}

func readyConditions() []metav1.Condition {
	return []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		LastTransitionTime: metav1.Now(),
	}}
}

func notReadyConditions() []metav1.Condition {
	return []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "ReconcileError",
		LastTransitionTime: metav1.Now(),
	}}
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pocketidv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// --- IsResourceReady ---

func TestIsResourceReady_True(t *testing.T) {
	if !IsResourceReady(readyConditions()) {
		t.Error("expected ready=true for ConditionTrue")
	}
}

func TestIsResourceReady_False(t *testing.T) {
	if IsResourceReady(notReadyConditions()) {
		t.Error("expected ready=false for ConditionFalse")
	}
}

func TestIsResourceReady_NoConditions(t *testing.T) {
	if IsResourceReady(nil) {
		t.Error("expected ready=false with no conditions")
	}
}

// --- ResolveOIDCClientReferences ---

func TestResolveOIDCClientReferences_Ready(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	oidcClient := &pocketidv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-a", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "cid-a",
			Conditions: readyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(oidcClient).Build()

	ids, err := ResolveOIDCClientReferences(ctx, fc,
		[]pocketidv1alpha1.NamespacedOIDCClientReference{{Name: "client-a"}}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "cid-a" {
		t.Errorf("expected [cid-a], got %v", ids)
	}
}

func TestResolveOIDCClientReferences_NotReady(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	oidcClient := &pocketidv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-b", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "cid-b",
			Conditions: notReadyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(oidcClient).Build()

	_, err := ResolveOIDCClientReferences(ctx, fc,
		[]pocketidv1alpha1.NamespacedOIDCClientReference{{Name: "client-b"}}, "default")
	if err == nil {
		t.Fatal("expected error for not-ready OIDC client")
	}
}

func TestResolveOIDCClientReferences_NotFound(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, err := ResolveOIDCClientReferences(ctx, fc,
		[]pocketidv1alpha1.NamespacedOIDCClientReference{{Name: "does-not-exist"}}, "default")
	if err == nil {
		t.Fatal("expected error for missing OIDC client")
	}
}

func TestResolveOIDCClientReferences_MissingClientID(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	// Ready condition set but ClientID not yet populated (e.g. mid-reconcile edge case)
	oidcClient := &pocketidv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-c", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "",
			Conditions: readyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(oidcClient).Build()

	_, err := ResolveOIDCClientReferences(ctx, fc,
		[]pocketidv1alpha1.NamespacedOIDCClientReference{{Name: "client-c"}}, "default")
	if err == nil {
		t.Fatal("expected error for empty ClientID")
	}
}

// --- ResolveUserGroupReferences ---

func TestResolveUserGroupReferences_Ready(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-a", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID:    "gid-a",
			Conditions: readyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(group).Build()

	ids, err := ResolveUserGroupReferences(ctx, fc, nil,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{Name: "group-a"}}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "gid-a" {
		t.Errorf("expected [gid-a], got %v", ids)
	}
}

func TestResolveUserGroupReferences_NotReady(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-b", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID:    "gid-b",
			Conditions: notReadyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(group).Build()

	_, err := ResolveUserGroupReferences(ctx, fc, nil,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{Name: "group-b"}}, "default")
	if err == nil {
		t.Fatal("expected error for not-ready user group")
	}
}

func TestResolveUserGroupReferences_NotFound(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, err := ResolveUserGroupReferences(ctx, fc, nil,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{Name: "does-not-exist"}}, "default")
	if err == nil {
		t.Fatal("expected error for missing user group")
	}
}

func TestResolveUserGroupReferences_MissingGroupID(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-c", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID:    "",
			Conditions: readyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(group).Build()

	_, err := ResolveUserGroupReferences(ctx, fc, nil,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{Name: "group-c"}}, "default")
	if err == nil {
		t.Fatal("expected error for empty GroupID")
	}
}

// --- ResolveUserGroupReferences: groups with no CR in this cluster ---

func TestResolveUserGroupReferences_ByGroupName(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	lookup := &fakeUserGroupLookup{groups: []*pocketid.UserGroup{
		{ID: "gid-dev", Name: "developers"},
		{ID: "gid-ops", Name: "operators"},
	}}

	ids, err := ResolveUserGroupReferences(ctx, fc, lookup,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{GroupName: "developers"}}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "gid-dev" {
		t.Errorf("expected [gid-dev], got %v", ids)
	}
}

func TestResolveUserGroupReferences_ByGroupNameRequiresExactMatch(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	// Pocket-ID search is a substring match, so "dev" returns "developers".
	// Only an exact name may resolve, otherwise a prefix would grant the wrong group.
	lookup := &fakeUserGroupLookup{groups: []*pocketid.UserGroup{{ID: "gid-dev", Name: "developers"}}}

	_, err := ResolveUserGroupReferences(ctx, fc, lookup,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{GroupName: "dev"}}, "default")
	if !stderrors.Is(err, ErrUserGroupNotFound) {
		t.Fatalf("expected ErrUserGroupNotFound, got %v", err)
	}
}

func TestResolveUserGroupReferences_ByGroupNameListError(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	lookup := &fakeUserGroupLookup{listErr: stderrors.New("boom")}

	// A failed lookup is transient and must not be reported as a missing group.
	_, err := ResolveUserGroupReferences(ctx, fc, lookup,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{GroupName: "developers"}}, "default")
	if err == nil {
		t.Fatal("expected error when the lookup fails")
	}
	if stderrors.Is(err, ErrUserGroupNotFound) {
		t.Error("expected a transient error, not ErrUserGroupNotFound")
	}
}

func TestResolveUserGroupReferences_ByGroupIDIsPassedThrough(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	lookup := &fakeUserGroupLookup{}

	// An ID needs no resolution: it is handed to Pocket-ID as-is, which rejects it
	// on the allowed-groups write if it does not exist.
	ids, err := ResolveUserGroupReferences(ctx, fc, lookup,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{GroupID: "gid-dev"}}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "gid-dev" {
		t.Errorf("expected [gid-dev], got %v", ids)
	}
	if lookup.listCall != 0 {
		t.Errorf("expected no API calls when resolving by ID, got %d", lookup.listCall)
	}
}

func TestResolveUserGroupReferences_MixedCRAndExternalRefs(t *testing.T) {
	ctx := context.Background()
	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "local-admins", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID:    "gid-admins",
			Conditions: readyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(group).Build()
	lookup := &fakeUserGroupLookup{groups: []*pocketid.UserGroup{{ID: "gid-dev", Name: "developers"}}}

	ids, err := ResolveUserGroupReferences(ctx, fc, lookup, []pocketidv1alpha1.NamespacedUserGroupReference{
		{Name: "local-admins"},
		{GroupName: "developers"},
	}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 || ids[0] != "gid-admins" || ids[1] != "gid-dev" {
		t.Errorf("expected [gid-admins gid-dev], got %v", ids)
	}
}

func TestResolveUserGroupReferences_EmptyRef(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()

	// CEL rejects this at admission; the resolver must not silently skip it.
	_, err := ResolveUserGroupReferences(ctx, fc, nil,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{}}, "default")
	if err == nil {
		t.Fatal("expected error for a reference with no name, groupName, or groupID")
	}
}

func TestResolveUserGroupReferences_ByGroupNamePicksExactMatchAmongResults(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	// Search for "devs" also matches "platform-devs" and "devs-readonly", and the
	// exact match is not first in the result set.
	lookup := &fakeUserGroupLookup{groups: []*pocketid.UserGroup{
		{ID: "gid-platform", Name: "platform-devs"},
		{ID: "gid-devs", Name: "devs"},
		{ID: "gid-readonly", Name: "devs-readonly"},
	}}

	ids, err := ResolveUserGroupReferences(ctx, fc, lookup,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{GroupName: "devs"}}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "gid-devs" {
		t.Errorf("expected [gid-devs], got %v", ids)
	}
}

func TestResolveUserGroupReferences_ByGroupNameNoResults(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()

	_, err := ResolveUserGroupReferences(ctx, fc, &fakeUserGroupLookup{},
		[]pocketidv1alpha1.NamespacedUserGroupReference{{GroupName: "developers"}}, "default")
	if !stderrors.Is(err, ErrUserGroupNotFound) {
		t.Fatalf("expected ErrUserGroupNotFound, got %v", err)
	}
}

func TestResolveUserGroupReferences_ByGroupNameWithoutLookup(t *testing.T) {
	ctx := context.Background()
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()

	// A nil lookup is a programming error, not a missing group: it must not be
	// reported as ErrUserGroupNotFound, which callers treat as a spec problem.
	_, err := ResolveUserGroupReferences(ctx, fc, nil,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{GroupName: "developers"}}, "default")
	if err == nil {
		t.Fatal("expected error when resolving by name with no lookup")
	}
	if stderrors.Is(err, ErrUserGroupNotFound) {
		t.Error("expected a non-ErrUserGroupNotFound error for a nil lookup")
	}
}

func TestResolveUserGroupReferences_CRRefUsesExplicitNamespace(t *testing.T) {
	ctx := context.Background()
	// Two groups with the same name in different namespaces: the ref's namespace
	// must win over defaultNamespace.
	local := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "admins", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID: "gid-default", Conditions: readyConditions(),
		},
	}
	other := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "admins", Namespace: "other"},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID: "gid-other", Conditions: readyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(local, other).Build()

	ids, err := ResolveUserGroupReferences(ctx, fc, nil,
		[]pocketidv1alpha1.NamespacedUserGroupReference{{Name: "admins", Namespace: "other"}}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "gid-other" {
		t.Errorf("expected [gid-other], got %v", ids)
	}
}

func TestResolveUserGroupReferences_KeepsDuplicates(t *testing.T) {
	ctx := context.Background()
	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "devs", Namespace: "default"},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID: "gid-dev", Conditions: readyConditions(),
		},
	}
	fc := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(group).Build()
	lookup := &fakeUserGroupLookup{groups: []*pocketid.UserGroup{{ID: "gid-dev", Name: "developers"}}}

	// The same group named three ways. The resolver is deliberately not responsible
	// for deduplication; aggregateAllowedUserGroupIDs collapses the set.
	ids, err := ResolveUserGroupReferences(ctx, fc, lookup, []pocketidv1alpha1.NamespacedUserGroupReference{
		{Name: "devs"},
		{GroupName: "developers"},
		{GroupID: "gid-dev"},
	}, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 entries before dedup, got %v", ids)
	}
	for _, id := range ids {
		if id != "gid-dev" {
			t.Errorf("expected every entry to be gid-dev, got %v", ids)
		}
	}
}
