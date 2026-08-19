package api

import (
	"reflect"
	"slices"
	"testing"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

func TestPermissionsEqual(t *testing.T) {
	current := []pocketid.APIPermission{
		{ID: "1", Key: "a", Name: "A", Description: "d"},
		{ID: "2", Key: "b", Name: "B"},
	}
	tests := []struct {
		name    string
		desired []pocketid.APIPermissionInput
		want    bool
	}{
		{"equal ignoring order/id", []pocketid.APIPermissionInput{{Key: "b", Name: "B"}, {Key: "a", Name: "A", Description: "d"}}, true},
		{"different length", []pocketid.APIPermissionInput{{Key: "a", Name: "A", Description: "d"}}, false},
		{"different name", []pocketid.APIPermissionInput{{Key: "a", Name: "changed", Description: "d"}, {Key: "b", Name: "B"}}, false},
		{"different description", []pocketid.APIPermissionInput{{Key: "a", Name: "A"}, {Key: "b", Name: "B"}}, false},
		{"missing key", []pocketid.APIPermissionInput{{Key: "a", Name: "A", Description: "d"}, {Key: "c", Name: "C"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := permissionsEqual(tc.desired, current); got != tc.want {
				t.Fatalf("permissionsEqual = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildPermissionInputs(t *testing.T) {
	spec := []pocketidinternalv1alpha1.APIPermission{
		{Key: "read:orders", Name: "Read", Description: "desc"},
		{Key: "write:orders", Name: "Write"},
	}
	got := buildPermissionInputs(spec)
	want := []pocketid.APIPermissionInput{
		{Key: "read:orders", Name: "Read", Description: "desc"},
		{Key: "write:orders", Name: "Write"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildPermissionInputs = %+v, want %+v", got, want)
	}
}

func TestObservedPermissions(t *testing.T) {
	if observedPermissions(nil) != nil {
		t.Fatal("observedPermissions(nil) should be nil")
	}
	got := observedPermissions([]pocketid.APIPermission{{ID: "1", Key: "k", Name: "N", Description: "ignored"}})
	if len(got) != 1 || got[0].ID != "1" || got[0].Key != "k" || got[0].Name != "N" {
		t.Fatalf("observedPermissions unexpected: %+v", got)
	}
}

func TestCIMDAccessDrift(t *testing.T) {
	current := &pocketid.API{
		AllowCIMDClients: true,
		Permissions: []pocketid.APIPermission{
			{ID: "p-read", Key: "read", AllowedForCIMDClients: true},
			{ID: "p-write", Key: "write"},
		},
	}

	yes, no := true, false
	tests := []struct {
		name        string
		enabled     *bool
		cimd        []string
		want        bool
		wantEnabled bool
		wantIDs     []string
	}{
		{name: "derived on, in sync", cimd: []string{"read"}, want: false, wantEnabled: true, wantIDs: []string{"p-read"}},
		{name: "permission added", cimd: []string{"read", "write"}, want: true, wantEnabled: true, wantIDs: []string{"p-read", "p-write"}},
		{name: "permission dropped", want: true, wantIDs: []string{}},
		{name: "explicit true with no permissions", enabled: &yes, want: true, wantEnabled: true, wantIDs: []string{}},
		{name: "explicit false keeps marks", enabled: &no, cimd: []string{"read"}, want: true, wantIDs: []string{"p-read"}},
		{name: "nothing marked means off", want: true, wantIDs: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &pocketidinternalv1alpha1.PocketIDAPI{
				Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
					CIMDAccess:  tt.enabled,
					Permissions: apiPermissions(tt.cimd, "read", "write"),
				},
			}
			drift, enabled, ids := cimdAccessDrift(api, current)
			if drift != tt.want {
				t.Errorf("drift = %v, want %v", drift, tt.want)
			}
			if enabled != tt.wantEnabled {
				t.Errorf("enabled = %v, want %v", enabled, tt.wantEnabled)
			}
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("permissionIDs = %v, want %v", ids, tt.wantIDs)
			}
		})
	}
}

// A permission marked for CIMD but not yet created in Pocket-ID contributes no ID, so the
// push has to wait for the permission update rather than resolving against stale state.
func TestCIMDAccessDrift_IgnoresPermissionNotYetCreated(t *testing.T) {
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
			Permissions: apiPermissions([]string{"sync"}, "sync"),
		},
	}
	drift, _, ids := cimdAccessDrift(api, &pocketid.API{AllowCIMDClients: true})
	if drift || len(ids) != 0 {
		t.Fatalf("drift = %v, ids = %v; want no push until the permission exists", drift, ids)
	}
}

// apiPermissions builds spec permissions for keys, marking those listed in cimd.
func apiPermissions(cimd []string, keys ...string) []pocketidinternalv1alpha1.APIPermission {
	perms := make([]pocketidinternalv1alpha1.APIPermission, 0, len(keys))
	for _, key := range keys {
		perms = append(perms, pocketidinternalv1alpha1.APIPermission{
			Key:        key,
			Name:       key,
			CIMDAccess: slices.Contains(cimd, key),
		})
	}
	return perms
}

// The marks are pushed while access is off but never diffed, so the operator settles whether
// Pocket-ID keeps them or clears them. Diffing them would re-push forever against a server
// that clears the marks whenever access is disabled.
func TestCIMDAccessDrift_SettlesWhileDisabled(t *testing.T) {
	no := false
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
			CIMDAccess:  &no,
			Permissions: apiPermissions([]string{"read"}, "read", "write"),
		},
	}

	for _, tt := range []struct {
		name    string
		current *pocketid.API
	}{
		{
			name: "server cleared the marks",
			current: &pocketid.API{Permissions: []pocketid.APIPermission{
				{ID: "p-read", Key: "read"},
				{ID: "p-write", Key: "write"},
			}},
		},
		{
			name: "server kept the marks",
			current: &pocketid.API{Permissions: []pocketid.APIPermission{
				{ID: "p-read", Key: "read", AllowedForCIMDClients: true},
				{ID: "p-write", Key: "write"},
			}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			drift, enabled, _ := cimdAccessDrift(api, tt.current)
			if drift {
				t.Error("drift = true, want false: access is already off, so there is nothing to push")
			}
			if enabled {
				t.Error("enabled = true, want false")
			}
		})
	}
}

// Turning access back on pushes the marks from spec, so it does not matter whether Pocket-ID
// retained them while access was off.
func TestCIMDAccessDrift_RepushesMarksOnReenable(t *testing.T) {
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
			Permissions: apiPermissions([]string{"read"}, "read", "write"),
		},
	}
	current := &pocketid.API{Permissions: []pocketid.APIPermission{
		{ID: "p-read", Key: "read"},
		{ID: "p-write", Key: "write"},
	}}

	drift, enabled, ids := cimdAccessDrift(api, current)
	if !drift || !enabled {
		t.Fatalf("drift = %v, enabled = %v; want both true", drift, enabled)
	}
	if !reflect.DeepEqual(ids, []string{"p-read"}) {
		t.Errorf("permissionIDs = %v, want [p-read]", ids)
	}
}
