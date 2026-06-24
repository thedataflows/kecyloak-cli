package admin

import (
	"context"
	"time"

	"github.com/thedataflows/keycloak-cli/pkg/auth"
	"github.com/thedataflows/keycloak-cli/pkg/catalog"
	"github.com/thedataflows/keycloak-cli/pkg/manifest"
)

type Config struct {
	BaseURL  string
	SpecPath string
	Timeout  time.Duration

	// Auth optionally injects a custom auth.Service. When nil, admin.New
	// falls back to auth.New() (the password-grant default), preserving
	// backward compatibility. The syncengine migration injects a
	// client_credentials provider here.
	Auth auth.Service
}

// Service is the public admin API used by command handlers.
type Service interface {
	Spec() *catalog.Spec
	Fetch(ctx context.Context, query FetchQuery) (FetchReport, error)
	Apply(ctx context.Context, resources []manifest.Resource, relationships []manifest.RelationshipOperation, options ApplyOptions) (ApplyReport, error)
}

func New(config Config) (Service, error) {
	return newService(config)
}
