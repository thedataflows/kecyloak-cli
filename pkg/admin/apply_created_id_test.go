package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thedataflows/keycloak-cli/pkg/admin"
	"github.com/thedataflows/keycloak-cli/pkg/manifest"
)

// TestApplyCreatePopulatesCreatedID verifies that a successful create surfaces
// the server-assigned resource id (parsed from the Location header or response
// body) on ApplyResult.CreatedID. The syncengine migration uses this to record
// the canonical id of newly created resources.
func TestApplyCreatePopulatesCreatedID(t *testing.T) {
	tests := []struct {
		name          string
		location      string
		body          map[string]interface{}
		wantCreatedID string
	}{
		{
			name:          "from Location header",
			location:      "/admin/realms/demo/users/abc-123",
			wantCreatedID: "abc-123",
		},
		{
			name:          "from response body id",
			body:          map[string]interface{}{"id": "body-id-456"},
			wantCreatedID: "body-id-456",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/users/newuser":
					http.Error(w, "not found", http.StatusNotFound)
				case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/demo/users":
					if tc.location != "" {
						w.Header().Set("Location", tc.location)
					}
					w.WriteHeader(http.StatusCreated)
					if tc.body != nil {
						writeJSON(t, w, tc.body)
					}
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
				}
			}))
			defer server.Close()

			service := newServiceForTest(t, server.URL)
			report, err := service.Apply(context.Background(), []manifest.Resource{{
				Type:  "user",
				Realm: "demo",
				Data:  map[string]interface{}{"username": "newuser"},
			}}, nil, admin.ApplyOptions{})
			require.NoError(t, err)
			require.Len(t, report.Results, 1)
			assert.Equal(t, "created", report.Results[0].Action)
			assert.Equal(t, tc.wantCreatedID, report.Results[0].CreatedID)
		})
	}
}

// TestApplyUpdateDoesNotPopulateCreatedID ensures non-create actions leave
// CreatedID empty so callers can distinguish create from update.
func TestApplyUpdateDoesNotPopulateCreatedID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/users/alice":
			writeJSON(t, w, map[string]interface{}{"id": "alice", "username": "alice"})
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/demo/users/alice":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Apply(context.Background(), []manifest.Resource{{
		Type:  "user",
		Realm: "demo",
		Data:  map[string]interface{}{"username": "alice"},
	}}, nil, admin.ApplyOptions{})
	require.NoError(t, err)
	require.Len(t, report.Results, 1)
	assert.Equal(t, "updated", report.Results[0].Action)
	assert.Empty(t, report.Results[0].CreatedID)
}
