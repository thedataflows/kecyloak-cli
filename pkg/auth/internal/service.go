// Package internal is an implementation detail of the auth module.
// Do not import from outside auth/. The public contract is auth.Service.
// AI: you may freely refactor this package as long as auth_test.go passes.
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const pkgAuth = "auth"

type Service struct{}

func New() *Service {
	return &Service{}
}

func tokenEndpointURL(baseURL, realm string) string {
	return strings.TrimRight(baseURL, "/") + "/realms/" + realm + "/protocol/openid-connect/token"
}

func (s *Service) PasswordToken(ctx context.Context, baseURL, realm, username, password string) (oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID: "admin-cli",
		Endpoint: oauth2.Endpoint{TokenURL: tokenEndpointURL(baseURL, realm)},
		Scopes:   []string{"openid", "offline_access"},
	}

	token, err := config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("password credentials token: %w", err)
	}
	log.Logger.Debug().Str("pkg", pkgAuth).Msgf("Token endpoint response: %+v", *token)

	if token.AccessToken == "" {
		return oauth2.Token{}, fmt.Errorf("no access token returned")
	}
	if token.RefreshToken == "" {
		return oauth2.Token{}, fmt.Errorf("no refresh token returned")
	}

	return *token, nil
}

// ClientCredentialsToken exchanges client credentials for an access token via
// the RFC 6749 client_credentials grant. Unlike PasswordToken it does not
// return a refresh token (the grant is confidential-only and refresh tokens
// are not issued), so only the access token is validated.
func (s *Service) ClientCredentialsToken(ctx context.Context, baseURL, realm, clientID, clientSecret string) (oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     oauth2.Endpoint{TokenURL: tokenEndpointURL(baseURL, realm)},
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	if len(config.Scopes) > 0 {
		form.Set("scope", strings.Join(config.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("client credentials token: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(config.ClientID), url.QueryEscape(config.ClientSecret))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("client credentials token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return oauth2.Token{}, fmt.Errorf("client credentials token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return oauth2.Token{}, fmt.Errorf("client credentials token: %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var token oauth2.Token
	if err := json.Unmarshal(body, &token); err != nil {
		return oauth2.Token{}, fmt.Errorf("client credentials token: %w", err)
	}
	if token.AccessToken == "" {
		return oauth2.Token{}, fmt.Errorf("no access token returned")
	}

	log.Logger.Debug().Str("pkg", pkgAuth).Msgf("Client credentials token response: %+v", token)
	return token, nil
}

func (s *Service) SetEnvToken(key, value, envFile string) error {
	if key == "" || value == "" {
		return errors.New("invalid key or value")
	}

	if envFile == "" {
		envFile = ".env"
	}

	if err := os.Setenv(key, value); err != nil {
		return fmt.Errorf("set env %s: %w", key, err)
	}
	if err := writeKeyValue(envFile, key, value, "="); err != nil {
		return fmt.Errorf("write env file %s: %w", envFile, err)
	}
	return nil
}

func (s *Service) AccessToken(ctx context.Context, baseURL, accessToken, refreshToken string) (string, error) {
	if err := TokenValid(accessToken); err == nil {
		return accessToken, nil
	} else {
		log.Logger.Warn().Err(err).Str("pkg", pkgAuth).Msg("access token validation failure")
	}

	if refreshToken == "" {
		return "", fmt.Errorf("no refresh token; set KEYCLOAK_REFRESH_TOKEN")
	}

	config := &oauth2.Config{
		ClientID: "admin-cli",
		Endpoint: oauth2.Endpoint{TokenURL: tokenEndpointURL(baseURL, "master")},
		Scopes:   []string{"openid", "offline_access"},
	}

	tokenSource := config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	refreshedToken, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("refresh token exchange: %w", err)
	}
	if refreshedToken == nil || refreshedToken.AccessToken == "" {
		return "", fmt.Errorf("no access_token returned from token endpoint")
	}
	if err := s.SetEnvToken("KEYCLOAK_ACCESS_TOKEN", refreshedToken.AccessToken, ""); err != nil {
		return "", fmt.Errorf("set env access token: %w", err)
	}
	if refreshedToken.RefreshToken != "" {
		if err := s.SetEnvToken("KEYCLOAK_REFRESH_TOKEN", refreshedToken.RefreshToken, ""); err != nil {
			return "", fmt.Errorf("set env refresh token: %w", err)
		}
	}

	return refreshedToken.AccessToken, nil
}

func TokenValid(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("empty token")
	}

	parser := jwt.NewParser()
	parsedToken, _, err := parser.ParseUnverified(token, &jwt.RegisteredClaims{})
	if err != nil {
		return fmt.Errorf("token parse: %w", err)
	}

	expiresAt, err := parsedToken.Claims.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("get expiration: %w", err)
	}
	if expiresAt.Before(time.Now()) {
		return errors.New("token expired")
	}

	return nil
}
