package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/keycloak-cli/pkg/auth"
)

func TestServicePasswordToken(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse map[string]interface{}
		serverStatus   int
		wantErr        bool
		errContains    string
	}{
		{
			name: "successful token exchange",
			serverResponse: map[string]interface{}{
				"access_token":  "access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "refresh-token",
			},
			serverStatus: http.StatusOK,
		},
		{
			name: "missing refresh token",
			serverResponse: map[string]interface{}{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			},
			serverStatus: http.StatusOK,
			wantErr:      true,
			errContains:  "no refresh token returned",
		},
	}

	service := auth.New()
	for _, testCase := range tests {
		t.Run(testCase.name, func(test *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(test, http.MethodPost, r.Method)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(testCase.serverStatus)
				require.NoError(test, json.NewEncoder(w).Encode(testCase.serverResponse))
			}))
			defer server.Close()

			response, err := service.PasswordToken(context.Background(), server.URL, "master", "admin", "admin")
			if testCase.wantErr {
				require.Error(test, err)
				assert.Contains(test, err.Error(), testCase.errContains)
				return
			}

			require.NoError(test, err)
			assert.Equal(test, "access-token", response.AccessToken)
			assert.Equal(test, "refresh-token", response.RefreshToken)
		})
	}
}

func TestServiceSetEnvToken(t *testing.T) {
	service := auth.New()
	envFile := filepath.Join(t.TempDir(), ".env")

	err := service.SetEnvToken("TEST_AUTH_TOKEN", "value", envFile)
	require.NoError(t, err)

	content, err := os.ReadFile(envFile)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(content), "TEST_AUTH_TOKEN=value"))
	assert.Equal(t, "value", os.Getenv("TEST_AUTH_TOKEN"))
}

func TestServiceClientCredentialsToken(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse map[string]interface{}
		serverStatus   int
		wantErr        bool
		errContains    string
	}{
		{
			name: "successful client_credentials exchange",
			serverResponse: map[string]interface{}{
				"access_token": "cc-access-token",
				"token_type":   "Bearer",
				"expires_in":   300,
			},
			serverStatus: http.StatusOK,
		},
		{
			name:           "missing access token",
			serverResponse: map[string]interface{}{"token_type": "Bearer"},
			serverStatus:   http.StatusOK,
			wantErr:        true,
			errContains:    "no access token returned",
		},
		{
			name:           "non-ok status",
			serverResponse: map[string]interface{}{"error": "invalid_client"},
			serverStatus:   http.StatusUnauthorized,
			wantErr:        true,
			errContains:    "401",
		},
	}

	service := auth.New()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				assert.Equal(t, "client_credentials", r.FormValue("grant_type"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.serverStatus)
				require.NoError(t, json.NewEncoder(w).Encode(tc.serverResponse))
			}))
			defer server.Close()

			token, err := service.ClientCredentialsToken(context.Background(), server.URL, "master", "my-client", "secret")
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "cc-access-token", token.AccessToken)
		})
	}
}
