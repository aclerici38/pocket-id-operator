package usergroup

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid/pocketidtest"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func page(data any) map[string]any {
	return map[string]any{"data": data, "pagination": map[string]int{"currentPage": 1, "totalPages": 1}}
}

// fakeGroups serves user groups and users the way Pocket-ID does, recording every call it gets.
type fakeGroups struct {
	groups []map[string]any
	users  []map[string]any
	// createStatus and listUsersStatus, when set, answer every create and user search.
	createStatus, listUsersStatus int

	calls   []string
	patches []map[string]any
	bodies  map[string]string
}

func (f *fakeGroups) find(id string) map[string]any {
	for _, g := range f.groups {
		if g["id"] == id {
			return g
		}
	}
	return nil
}

// write records a write's raw body, answering 404 for a group that doesn't exist.
func (f *fakeGroups) write(w http.ResponseWriter, r *http.Request, call string) (map[string]any, string, bool) {
	f.calls = append(f.calls, call)
	body, _ := io.ReadAll(r.Body)
	if f.bodies == nil {
		f.bodies = map[string]string{}
	}
	f.bodies[call] = strings.TrimSpace(string(body))
	g := f.find(r.PathValue("id"))
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "User group not found", "code": "not_found"})
	}
	return g, string(body), g != nil
}

func (f *fakeGroups) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/user-groups", func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		f.calls = append(f.calls, "list groups "+search)
		matches := []map[string]any{}
		for _, g := range f.groups {
			if strings.Contains(g["name"].(string), search) {
				matches = append(matches, g)
			}
		}
		writeJSON(w, http.StatusOK, page(matches))
	})
	mux.HandleFunc("POST /api/admin/user-groups", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "create")
		if f.createStatus != 0 {
			writeJSON(w, f.createStatus, map[string]string{"error": "Name is already in use", "code": "already_in_use"})
			return
		}
		var g map[string]any
		_ = json.NewDecoder(r.Body).Decode(&g)
		g["id"] = "new-group-id"
		f.groups = append(f.groups, g)
		writeJSON(w, http.StatusCreated, g)
	})
	mux.HandleFunc("PATCH /api/admin/user-groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		if g, body, ok := f.write(w, r, "patch"); ok {
			var patch map[string]any
			_ = json.Unmarshal([]byte(body), &patch)
			f.patches = append(f.patches, patch)
			maps.Copy(g, patch)
			writeJSON(w, http.StatusOK, g)
		}
	})
	mux.HandleFunc("PUT /api/admin/custom-claims/user-group/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, body, ok := f.write(w, r, "claims"); ok {
			writeJSON(w, http.StatusOK, json.RawMessage(body))
		}
	})
	mux.HandleFunc("PUT /api/admin/user-groups/{id}/users", func(w http.ResponseWriter, r *http.Request) {
		if g, body, ok := f.write(w, r, "members"); ok {
			var members struct {
				UserIDs []string `json:"userIds"`
			}
			_ = json.Unmarshal([]byte(body), &members)
			users := []map[string]any{}
			for _, id := range members.UserIDs {
				users = append(users, map[string]any{"id": id})
			}
			g["users"] = users
			writeJSON(w, http.StatusOK, g)
		}
	})
	mux.HandleFunc("GET /api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		f.calls = append(f.calls, "list users "+search)
		if f.listUsersStatus != 0 {
			writeJSON(w, f.listUsersStatus, map[string]string{"error": "failed"})
			return
		}
		matches := []map[string]any{}
		for _, u := range f.users {
			if strings.Contains(u["username"].(string), search) {
				matches = append(matches, u)
			}
		}
		writeJSON(w, http.StatusOK, page(matches))
	})
	return mux
}

func (f *fakeGroups) client(t *testing.T) *pocketid.Client {
	return pocketidtest.NewClient(t, f.handler())
}

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

func TestFindExistingUserGroup(t *testing.T) {
	tests := []struct {
		name   string
		groups []map[string]any
		wantID string
	}{
		{name: "no match"},
		{name: "matches by name", groups: []map[string]any{{"id": "gid", "name": "admins"}}, wantID: "gid"},
		// The search is server-side and partial, so only an exact name is adopted.
		{name: "picks the exact name among partial matches",
			groups: []map[string]any{{"id": "other", "name": "admins-old"}, {"id": "gid", "name": "admins"}}, wantID: "gid"},
		{name: "ignores partial matches only", groups: []map[string]any{{"id": "other", "name": "admins-old"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeGroups{groups: tt.groups}
			found, err := (&Reconciler{}).FindExistingUserGroup(context.Background(), f.client(t), "admins")
			if err != nil {
				t.Fatalf("FindExistingUserGroup: %v", err)
			}
			gotID := ""
			if found != nil {
				gotID = found.ID
			}
			if gotID != tt.wantID {
				t.Errorf("found ID = %q, want %q", gotID, tt.wantID)
			}
		})
	}
}

func TestCreateOrAdoptUserGroup(t *testing.T) {
	tests := []struct {
		name         string
		groups       []map[string]any
		createStatus int
		wantID       string
		wantCalls    []string
		wantCreated  map[string]any
	}{
		{name: "creates the group with its names", wantID: "new-group-id", wantCalls: []string{"create"},
			wantCreated: map[string]any{"id": "new-group-id", "name": "admins", "friendlyName": "Administrators"}},
		{name: "adopts by name when the create conflicts", createStatus: http.StatusConflict,
			groups: []map[string]any{{"id": "existing-id", "name": "admins"}}, wantID: "existing-id",
			wantCalls: []string{"create", "list groups admins"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "admins", Namespace: testNamespace},
				Spec:       pocketidinternalv1alpha1.PocketIDUserGroupSpec{FriendlyName: "Administrators"},
			}
			fc := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(group).WithStatusSubresource(group).Build()
			f := &fakeGroups{groups: tt.groups, createStatus: tt.createStatus}

			requeue, err := (&Reconciler{Client: fc}).createOrAdoptUserGroup(context.Background(), group, f.client(t))
			if err != nil || !requeue {
				t.Fatalf("createOrAdoptUserGroup = %v, %v; want a requeue", requeue, err)
			}
			if !slices.Equal(f.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", f.calls, tt.wantCalls)
			}
			if tt.wantCreated != nil && !maps.Equal(f.groups[0], tt.wantCreated) {
				t.Errorf("created group = %v, want %v", f.groups[0], tt.wantCreated)
			}
			latest := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			if err := fc.Get(context.Background(), client.ObjectKeyFromObject(group), latest); err != nil {
				t.Fatalf("get group: %v", err)
			}
			if latest.Status.GroupID != tt.wantID {
				t.Errorf("status.groupID = %q, want %q", latest.Status.GroupID, tt.wantID)
			}
		})
	}
}

func TestResolveUsername(t *testing.T) {
	tests := []struct {
		name       string
		users      []map[string]any
		listStatus int
		wantID     string
		wantErr    bool
	}{
		{name: "exact match", users: []map[string]any{{"id": "user-123", "username": "john.doe"}}, wantID: "user-123"},
		// The search may return partial matches, so only the exact one counts.
		{name: "picks the exact match among partial ones", wantID: "user-123", users: []map[string]any{
			{"id": "user-456", "username": "john.doe.smith"}, {"id": "user-123", "username": "john.doe"},
		}},
		{name: "no exact match", users: []map[string]any{{"id": "user-456", "username": "john.doe.smith"}}, wantErr: true},
		{name: "API error", listStatus: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeGroups{users: tt.users, listUsersStatus: tt.listStatus}
			id, err := (&Reconciler{}).resolveUsername(context.Background(), f.client(t), "john.doe")
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if id != tt.wantID {
				t.Errorf("ID = %q, want %q", id, tt.wantID)
			}
		})
	}
}
