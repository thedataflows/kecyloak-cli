package auth

import (
	"context"

	"github.com/thedataflows/keycloak-cli/pkg/auth/internal"
	"golang.org/x/oauth2"
)

const (
	AccessTokenEnvVar  = "KEYCLOAK_ACCESS_TOKEN"
	RefreshTokenEnvVar = "KEYCLOAK_REFRESH_TOKEN"
)

// Service is the public API for Keycloak admin token acquisition and refresh.
type Service interface {
	PasswordToken(ctx context.Context, baseURL, realm, username, password string) (oauth2.Token, error)
	ClientCredentialsToken(ctx context.Context, baseURL, realm, clientID, clientSecret string) (oauth2.Token, error)
	AccessToken(ctx context.Context, baseURL, accessToken, refreshToken string) (string, error)
	SetEnvToken(key, value, envFile string) error
}

// New returns a production-ready auth service.
func New() Service {
	return internal.New()
}
