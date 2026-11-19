package api

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// The inputs replace the API's full permission set, so an empty spec has to go out as [] and an
// empty description as null.
func TestBuildPermissionInputs(t *testing.T) {
	for name, tt := range map[string]struct {
		spec []pocketidinternalv1alpha1.APIPermission
		want string
	}{
		"empty spec clears":   {want: `[]`},
		"description is kept": {spec: []pocketidinternalv1alpha1.APIPermission{{Key: "read", Name: "Read", Description: "d"}}, want: `[{"description":"d","key":"read","name":"Read"}]`},
		"empty description":   {spec: []pocketidinternalv1alpha1.APIPermission{{Key: "read", Name: "Read"}}, want: `[{"description":null,"key":"read","name":"Read"}]`},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := json.Marshal(buildPermissionInputs(tt.spec))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

// Pocket-ID returns permissions unordered, so status is sorted to stay stable.
func TestObservedPermissions(t *testing.T) {
	if observedPermissions(nil) != nil {
		t.Fatal("observedPermissions(nil) should be nil")
	}
	got := observedPermissions([]pid.APIPermissionResponseDto{
		{ID: "2", Key: "write", Name: "W", AllowedForCIMDClients: true},
		{ID: "1", Key: "read", Name: "R", Description: "ignored"},
	})
	want := []pocketidinternalv1alpha1.ObservedAPIPermission{
		{ID: "1", Key: "read", Name: "R"},
		{ID: "2", Key: "write", Name: "W", CIMDAccess: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("observedPermissions = %+v, want %+v", got, want)
	}
}

func TestCIMDAccess(t *testing.T) {
	current := pid.APIResponseDto{Permissions: []pid.APIPermissionResponseDto{
		{ID: "p-read", Key: "read"},
		{ID: "p-write", Key: "write"},
	}}

	yes, no := true, false
	tests := []struct {
		name        string
		enabled     *bool
		cimd        []string
		wantEnabled bool
		wantIDs     []string
	}{
		{name: "marked permission turns access on", cimd: []string{"read"}, wantEnabled: true, wantIDs: []string{"p-read"}},
		{name: "every marked permission", cimd: []string{"read", "write"}, wantEnabled: true, wantIDs: []string{"p-read", "p-write"}},
		{name: "nothing marked means off", wantIDs: []string{}},
		{name: "explicit true with no permissions", enabled: &yes, wantEnabled: true, wantIDs: []string{}},
		// The marks are sent while access is off, so turning it back on needs only spec.
		{name: "explicit false keeps marks", enabled: &no, cimd: []string{"read"}, wantIDs: []string{"p-read"}},
		// A permission not yet created in Pocket-ID has no ID to send.
		{name: "permission not yet created", cimd: []string{"sync"}, wantEnabled: true, wantIDs: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &pocketidinternalv1alpha1.PocketIDAPI{
				Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
					CIMDAccess:  tt.enabled,
					Permissions: apiPermissions(tt.cimd, "read", "write", "sync"),
				},
			}
			enabled, ids := cimdAccess(api, current)
			if enabled != tt.wantEnabled {
				t.Errorf("enabled = %v, want %v", enabled, tt.wantEnabled)
			}
			if !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("permissionIDs = %v, want %v", ids, tt.wantIDs)
			}
		})
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
