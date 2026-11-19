package user

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

const declaredUserID = "18f3c2f6-2c4b-4f26-9d1c-4b7f6e0a1b2c"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "User not found", "code": "user_not_found"})
}

func pocketIDUser(id, username, email string) map[string]any {
	return map[string]any{"id": id, "username": username, "email": email}
}

// fakeUsers serves users the way Pocket-ID does, recording every call it gets.
type fakeUsers struct {
	users []map[string]any
	// getStatus, when set, answers every lookup by ID.
	getStatus int
	// createStatus, when set, answers every create.
	createStatus int

	calls      []string
	created    map[string]any
	tokenTTL   any
	patches    []map[string]any
	claimsBody []string
}

func (f *fakeUsers) find(id string) map[string]any {
	for _, u := range f.users {
		if u["id"] == id {
			return u
		}
	}
	return nil
}

func (f *fakeUsers) client(t *testing.T) *pocketid.Client {
	return pocketidtest.NewClient(t, f.handler())
}

func (f *fakeUsers) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		f.calls = append(f.calls, "list "+search)
		matches := []map[string]any{}
		for _, u := range f.users {
			username, _ := u["username"].(string)
			email, _ := u["email"].(string)
			if strings.Contains(username, search) || strings.Contains(email, search) {
				matches = append(matches, u)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": matches, "pagination": map[string]int{"currentPage": 1, "totalPages": 1}})
	})
	mux.HandleFunc("GET /api/admin/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "get "+r.PathValue("id"))
		if f.getStatus != 0 {
			writeJSON(w, f.getStatus, map[string]string{"error": "failed"})
			return
		}
		if u := f.find(r.PathValue("id")); u != nil {
			writeJSON(w, http.StatusOK, u)
			return
		}
		notFound(w)
	})
	mux.HandleFunc("POST /api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "create")
		_ = json.NewDecoder(r.Body).Decode(&f.created)
		if f.createStatus != 0 {
			writeJSON(w, f.createStatus, map[string]string{"error": "Username is already in use", "code": "already_in_use"})
			return
		}
		u := maps.Clone(f.created)
		if u["id"] == nil {
			u["id"] = "generated-id"
		}
		f.users = append(f.users, u)
		writeJSON(w, http.StatusCreated, u)
	})
	mux.HandleFunc("PATCH /api/admin/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "patch "+r.PathValue("id"))
		u := f.find(r.PathValue("id"))
		if u == nil {
			notFound(w)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.patches = append(f.patches, body)
		maps.Copy(u, body)
		writeJSON(w, http.StatusOK, u)
	})
	mux.HandleFunc("PUT /api/admin/custom-claims/user/{userId}", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "claims "+r.PathValue("userId"))
		body, _ := io.ReadAll(r.Body)
		f.claimsBody = append(f.claimsBody, strings.TrimSpace(string(body)))
		writeJSON(w, http.StatusOK, json.RawMessage(body))
	})
	mux.HandleFunc("POST /api/admin/users/{id}/one-time-access-token", func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, "token "+r.PathValue("id"))
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.tokenTTL = body["ttl"]
		writeJSON(w, http.StatusCreated, map[string]string{"token": "one-time-token"})
	})
	return mux
}

func userTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

func TestFindExistingUserAcrossPages(t *testing.T) {
	var pages []string
	api := pocketidtest.NewClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("pagination[page]")
		pages = append(pages, page)
		if r.URL.Query().Get("search") != "bob" {
			t.Errorf("unexpected search: %s", r.URL.RawQuery)
		}
		switch page {
		case "1":
			writeJSON(w, http.StatusOK, map[string]any{"data": []any{pocketIDUser("other", "bobby", "")}, "pagination": map[string]int{"currentPage": 1, "totalPages": 3}})
		case "2":
			writeJSON(w, http.StatusOK, map[string]any{"data": []any{pocketIDUser("bob-id", "bob", "")}, "pagination": map[string]int{"currentPage": 2, "totalPages": 3}})
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	found, err := (&Reconciler{}).FindExistingUser(t.Context(), api, "", "bob", "")
	if err != nil || found == nil || found.ID != "bob-id" || !slices.Equal(pages, []string{"1", "2"}) {
		t.Fatalf("found = %v, pages = %v, err = %v", found, pages, err)
	}
}

func TestFindExistingUser(t *testing.T) {
	bob := pocketIDUser("bob-id", "bob", "bob@gmail.com")
	tests := []struct {
		name                string
		users               []map[string]any
		getStatus           int
		id, username, email string
		wantID              string
		wantCalls           []string
		wantErr             bool
	}{
		{name: "no match searches username then email", username: "bob", email: "bob@gmail.com",
			wantCalls: []string{"list bob", "list bob@gmail.com"}},
		{name: "matches by username", users: []map[string]any{bob}, username: "bob", email: "other@example.com",
			wantID: "bob-id", wantCalls: []string{"list bob"}},
		{name: "matches by email", users: []map[string]any{pocketIDUser("bob-id", "robert", "bob@gmail.com")}, username: "bob", email: "bob@gmail.com",
			wantID: "bob-id", wantCalls: []string{"list bob", "list bob@gmail.com"}},
		{name: "picks the exact username among partial matches",
			users:    []map[string]any{pocketIDUser("other", "bobby", "x@example.com"), bob},
			username: "bob", wantID: "bob-id", wantCalls: []string{"list bob"}},
		{name: "skips an empty email", username: "bob", wantCalls: []string{"list bob"}},
		{name: "looks up a declared ID without listing", users: []map[string]any{bob}, id: "bob-id", username: "bob",
			wantID: "bob-id", wantCalls: []string{"get bob-id"}},
		// Falling back to the username would adopt a user with a different ID than the one declared.
		{name: "an unknown declared ID does not fall back to the username", users: []map[string]any{bob}, id: declaredUserID, username: "bob",
			wantCalls: []string{"get " + declaredUserID}},
		{name: "a failed ID lookup is an error", getStatus: http.StatusInternalServerError, id: declaredUserID,
			wantCalls: []string{"get " + declaredUserID}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeUsers{users: tt.users, getStatus: tt.getStatus}
			found, err := (&Reconciler{}).FindExistingUser(context.Background(), f.client(t), tt.id, tt.username, tt.email)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			gotID := ""
			if found != nil {
				gotID = found.ID
			}
			if gotID != tt.wantID {
				t.Errorf("found ID = %q, want %q", gotID, tt.wantID)
			}
			if !slices.Equal(f.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", f.calls, tt.wantCalls)
			}
		})
	}
}

func TestCreateOrAdoptUser(t *testing.T) {
	tests := []struct {
		name         string
		declaredID   string
		users        []map[string]any
		createStatus int
		wantID       string
		wantCalls    []string
		wantToken    bool
	}{
		// Creating would be rejected as a duplicate primary key.
		{name: "adopts the user carrying the declared ID", declaredID: declaredUserID,
			users:  []map[string]any{pocketIDUser(declaredUserID, "renamed-alice", "")},
			wantID: declaredUserID, wantCalls: []string{"get " + declaredUserID}},
		{name: "creates with the declared ID when absent", declaredID: declaredUserID,
			wantID: declaredUserID, wantCalls: []string{"get " + declaredUserID, "create", "token " + declaredUserID}, wantToken: true},
		{name: "creates without an ID lookup when none is declared",
			wantID: "generated-id", wantCalls: []string{"create", "token generated-id"}, wantToken: true},
		{name: "adopts by username when the create conflicts", createStatus: http.StatusConflict,
			users:  []map[string]any{pocketIDUser("existing-id", "alice", "alice@example.com")},
			wantID: "existing-id", wantCalls: []string{"create", "list alice"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					UserID: tt.declaredID,
					Email:  pocketidinternalv1alpha1.StringValue{Value: "alice@example.com"},
				},
			}
			fc := fake.NewClientBuilder().WithScheme(userTestScheme()).WithObjects(user).WithStatusSubresource(user).Build()
			r := &Reconciler{Client: fc, APIReader: fc}
			f := &fakeUsers{users: tt.users, createStatus: tt.createStatus}
			instance := &pocketidinternalv1alpha1.PocketIDInstance{ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: "default"}}

			requeue, err := r.createOrAdoptUser(context.Background(), user, f.client(t), instance)
			if err != nil || !requeue {
				t.Fatalf("createOrAdoptUser = %v, %v; want a requeue", requeue, err)
			}
			if !slices.Equal(f.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", f.calls, tt.wantCalls)
			}
			if f.created != nil && f.created["id"] != nil != (tt.declaredID != "") {
				t.Errorf("create body id = %v, want present only when declared", f.created["id"])
			}

			latest := &pocketidinternalv1alpha1.PocketIDUser{}
			if err := fc.Get(context.Background(), client.ObjectKeyFromObject(user), latest); err != nil {
				t.Fatalf("get user: %v", err)
			}
			if latest.Status.UserID != tt.wantID {
				t.Errorf("status.userID = %q, want %q", latest.Status.UserID, tt.wantID)
			}
			if got := latest.Status.OneTimeLoginToken != ""; got != tt.wantToken {
				t.Errorf("one-time login token set = %v, want %v", got, tt.wantToken)
			}
			// The TTL is in seconds.
			if tt.wantToken && f.tokenTTL != float64(DefaultLoginTokenExpiryMin*60) {
				t.Errorf("token ttl = %v, want %d", f.tokenTTL, DefaultLoginTokenExpiryMin*60)
			}
		})
	}
}
