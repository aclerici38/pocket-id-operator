package api

import (
	"reflect"
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
