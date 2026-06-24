package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thedataflows/keycloak-cli/pkg/admin"
	"github.com/thedataflows/keycloak-cli/pkg/manifest"
)

// TestApplyReturnsTypedError verifies that when Apply fails without
// ContinueOnError, the returned error unwraps to *admin.Error via errors.As.
// This is what the syncengine migration relies on to distinguish conflict
// (retry) from validation (fail) errors.
func TestApplyReturnsTypedError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantKind   admin.ErrorKind
		wantStatus int
	}{
		{name: "validation failure 400", status: http.StatusBadRequest, wantKind: admin.ErrorValidation, wantStatus: http.StatusBadRequest},
		{name: "unauthorized 401", status: http.StatusUnauthorized, wantKind: admin.ErrorUnauthorized, wantStatus: http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/users/alice":
					http.Error(w, "not found", http.StatusNotFound)
				case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/demo/users":
					http.Error(w, "bad payload", tc.status)
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
				}
			}))
			defer server.Close()

			service := newServiceForTest(t, server.URL)
			_, err := service.Apply(context.Background(), []manifest.Resource{{
				Type:  "user",
				Realm: "demo",
				Data:  map[string]interface{}{"username": "alice"},
			}}, nil, admin.ApplyOptions{})
			require.Error(t, err)

			var ae *admin.Error
			require.True(t, errors.As(err, &ae), "err should unwrap to *admin.Error; got %T: %v", err, err)
			require.NotNil(t, ae)
			assert.Equal(t, tc.wantStatus, ae.StatusCode)
			assert.Equal(t, tc.wantKind, ae.Kind)
		})
	}
}

// TestApplyReturnsTypedConflictErrorOnUpdate covers the conflict kind surfacing
// via the update (PUT) path, since a POST 409 triggers Keycloak's
// fallback-to-update semantics rather than a direct failure.
func TestApplyReturnsTypedConflictErrorOnUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/users/alice":
			writeJSON(t, w, map[string]interface{}{"id": "alice", "username": "alice"})
		case r.Method == http.MethodPut && r.URL.Path == "/admin/realms/demo/users/alice":
			http.Error(w, "conflict", http.StatusConflict)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	_, err := service.Apply(context.Background(), []manifest.Resource{{
		Type:  "user",
		Realm: "demo",
		Data:  map[string]interface{}{"username": "alice"},
	}}, nil, admin.ApplyOptions{})
	require.Error(t, err)

	var ae *admin.Error
	require.True(t, errors.As(err, &ae), "err should unwrap to *admin.Error; got %T: %v", err, err)
	require.NotNil(t, ae)
	assert.Equal(t, http.StatusConflict, ae.StatusCode)
	assert.Equal(t, admin.ErrorConflict, ae.Kind)
}

// TestApplyErrorStringFormatPreserved locks the backward-compatible .Error()
// text produced when ContinueOnError keeps the result in the report. The
// syncengine migration must not change this string (admin_test.go:93 canary).
func TestApplyErrorStringFormatPreserved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/users/alice":
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/demo/users":
			http.Error(w, "bad payload", http.StatusBadRequest)
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
	}}, nil, admin.ApplyOptions{ContinueOnError: true})
	require.NoError(t, err)
	require.Len(t, report.Results, 1)
	assert.Equal(t, "apply user: validation failure (400): bad payload\n", report.Results[0].Error)
}
