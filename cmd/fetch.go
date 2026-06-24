package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog/log"
	"github.com/thedataflows/keycloak-cli/pkg/admin"
	"github.com/thedataflows/keycloak-cli/pkg/manifest"
	"github.com/thedataflows/keycloak-cli/pkg/output"
)

// FetchCmd gets objects
type FetchCmd struct {
	Long          bool     `short:"l" help:"Show detailed information about objects" default:"false"`
	Format        string   `short:"f" default:"table" enum:"table,json,yaml,toml" help:"Output format"`
	Output        string   `short:"o" help:"Output file or directory for fetched resources (ends with / for directory)"`
	Force         bool     `help:"Force overwrite of output file if it exists" default:"false"`
	ExcludeFields []string `short:"e" help:"Comma-separated list of fields to exclude from output" default:"containerId"`
	Realm         string   `short:"r" help:"Realm to scope the resource fetch to. If not provided, all realms will be used."`
	Resources     string   `arg:"" optional:"" help:"Comma-separated resource types to fetch (default: realm,user,client,group,role)" default:"realm,user,client,group,role"`
	Filter        string   `arg:"" optional:"" name:"filter" help:"Filter fetched resources by exact name or id (case-insensitive)"`
	Search        string   `short:"s" help:"Search parameter for filtering resources"`
	Max           int      `help:"Maximum number of results to return"`
	Depth         int      `help:"Fetch child resources up to N levels deep" default:"1"`
	Parent        string   `short:"p" help:"Parent resource identifier for nested resources (e.g. authentication flow alias for executions)"`
	Relationships bool     `help:"Fetch supported relationship state in addition to resources" default:"false"`
	Canonicalize  bool     `help:"Strip server-managed fields and write a clean manifest suitable for re-apply" default:"false"`
}

func (c *FetchCmd) Run(ctx *kong.Context, cli *CLI) error {
	log.Logger.Info().Str("pkg", PKG_CMD).Msg("Fetch resources")
	log.Logger.Debug().Str("pkg", PKG_CMD).Msgf("Fetch command options: %+v; context: %+v", cli, ctx.Args)

	specClient, err := cli.adminClient()
	if err != nil {
		return err
	}

	commandCtx, cancel := cli.CreateContextWithTimeout()
	defer cancel()

	report, err := specClient.Fetch(commandCtx, admin.FetchQuery{
		Realm:                c.Realm,
		Resources:            c.Resources,
		Filter:               c.Filter,
		Search:               c.Search,
		Max:                  c.Max,
		Depth:                c.Depth,
		Parent:               c.Parent,
		IncludeRelationships: c.Relationships,
	})
	if err != nil {
		return err
	}

	if err := c.outputResources(report); err != nil {
		return err
	}

	if len(report.Failures) > 0 {
		var realFailures []string
		notFound := make(map[string]int)
		for _, f := range report.Failures {
			if f.NotFound {
				notFound[f.Resource]++
				continue
			}
			realFailures = append(realFailures, f.String())
		}
		if len(realFailures) > 0 {
			log.Logger.Warn().Str("pkg", PKG_CMD).Msgf("Resources failed: %s", strings.Join(realFailures, ", "))
		}
		if len(notFound) > 0 {
			keys := make([]string, 0, len(notFound))
			for k := range notFound {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s (%d)", k, notFound[k]))
			}
			log.Logger.Info().Str("pkg", PKG_CMD).Msgf("Optional resources not found: %s", strings.Join(parts, ", "))
		}
	}
	return nil
}

func (c *FetchCmd) outputResources(report admin.FetchReport) error {
	resources := report.Resources
	relationships := report.Relationships
	if c.Canonicalize {
		resources, relationships = manifest.NormalizeForApply(resources, relationships)
	}
	sanitized := output.SanitizeResources(resources, c.ExcludeFields)

	if isDirTarget(c.Output) {
		if c.Format == "table" {
			return fmt.Errorf("directory output requires a structured format (json|yaml|toml), got %q", c.Format)
		}
		return output.WriteResourcesToDir(c.Output, sanitized, relationships, c.Format, c.Force)
	}
	dest, shouldClose, err := output.Destination(c.Output, c.Force)
	if err != nil {
		return err
	}
	if shouldClose {
		defer dest.Close()
		log.Logger.Info().Str("pkg", PKG_CMD).Msgf("Writing to file '%s'", c.Output)
	}

	switch c.Format {
	case "json", "yaml", "toml":
		return output.WritePayload(dest, fetchOutputPayload(sanitized, relationships), c.Format)
	case "table":
		if len(sanitized) > 0 {
			if err := output.WriteResourceTable(dest, sanitized, c.Long); err != nil {
				return err
			}
		}
		if len(relationships) > 0 {
			if len(sanitized) > 0 {
				if _, err := fmt.Fprintln(dest); err != nil {
					return err
				}
			}
			return output.WriteRelationshipTable(dest, relationships)
		}
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", c.Format)
	}
}

func fetchOutputPayload(resources []manifest.Resource, relationships []manifest.RelationshipOperation) map[string]interface{} {
	switch {
	case len(resources) == 0 && len(relationships) > 0:
		return map[string]interface{}{"relationships": relationships}
	case len(relationships) == 0:
		return map[string]interface{}{"resources": resources}
	default:
		return map[string]interface{}{"resources": resources, "relationships": relationships}
	}
}

func filterResources(resources []manifest.Resource, filter string) []manifest.Resource {
	needle := strings.ToLower(strings.TrimSpace(filter))
	out := make([]manifest.Resource, 0, len(resources))
	for _, r := range resources {
		if strings.ToLower(r.Name()) == needle || strings.ToLower(r.Identifier()) == needle {
			out = append(out, r)
		}
	}
	return out
}
