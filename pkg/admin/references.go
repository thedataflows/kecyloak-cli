package admin

import (
	"context"
	"strings"

	"github.com/thedataflows/keycloak-cli/pkg/manifest"
)

// resolveReferences scans the provided resources for UUID-shaped string values
// and fetches any referenced resources that are not already present in the
// result set. This makes manifests self-contained when importing into a
// different Keycloak server.
func (s *service) resolveReferences(ctx context.Context, realmNames []string, resources []manifest.Resource) ([]manifest.Resource, []FetchFailure) {
	if len(resources) == 0 || len(realmNames) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	for _, r := range resources {
		seen[resourceKey(r)] = struct{}{}
	}

	idsByType := extractReferencedIDs(resources, seen)
	if len(idsByType) == 0 {
		return nil, nil
	}

	var results []manifest.Resource
	var failures []FetchFailure

	for _, realm := range realmNames {
		for resourceType, ids := range idsByType {
			fetched, err := s.fetchResourcesByIDs(ctx, resourceType, realm, ids)
			if err != nil {
				failures = append(failures, fetchFailure(resourceType, realm, err))
				continue
			}
			for i := range fetched {
				fetched[i].Realm = realm
				key := resourceKey(fetched[i])
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				results = append(results, fetched[i])
			}
		}
	}

	return results, failures
}

// extractReferencedIDs walks all resource Data maps and returns, per resource
// type, the IDs that appear as UUID-shaped strings but whose target resource is
// not already present in the result set.
func extractReferencedIDs(resources []manifest.Resource, seen map[string]struct{}) map[string]map[string]struct{} {
	idsByType := make(map[string]map[string]struct{})

	for _, r := range resources {
		collectUUIDs(r.Data, func(value string) {
			for _, candidateType := range candidateResourceTypes(value, r.Type) {
				key := strings.Join([]string{candidateType, r.Realm, value}, "|")
				if _, ok := seen[key]; ok {
					continue
				}
				if _, ok := idsByType[candidateType]; !ok {
					idsByType[candidateType] = make(map[string]struct{})
				}
				idsByType[candidateType][value] = struct{}{}
			}
		})
	}

	return idsByType
}

// collectUUIDs recursively walks a value and calls visitor for every UUID-shaped string.
func collectUUIDs(value interface{}, visitor func(string)) {
	switch typed := value.(type) {
	case string:
		if looksLikeUUID(typed) {
			visitor(typed)
		}
	case map[string]interface{}:
		for _, v := range typed {
			collectUUIDs(v, visitor)
		}
	case []interface{}:
		for _, v := range typed {
			collectUUIDs(v, visitor)
		}
	}
}

// candidateResourceTypes returns possible resource types for a referenced ID.
// For now we consider all top-level realm-scoped resource types that can be
// looked up by ID. This is intentionally broad so the fetch can discover
// references without hardcoding field names.
func candidateResourceTypes(value, sourceType string) []string {
	return []string{
		"authenticationflow",
		"clientscope",
		"client",
		"group",
		"role",
		"user",
		"identityprovider",
		"organization",
		"component",
	}
}

// fetchResourcesByIDs fetches resources of the given type in the realm and
// returns only those whose ID is in the requested set. It avoids fetching the
// same collection multiple times by caching per realm.
func (s *service) fetchResourcesByIDs(ctx context.Context, resourceType, realm string, ids map[string]struct{}) ([]manifest.Resource, error) {
	all, err := s.fetchResourceCollection(ctx, resourceType, map[string]string{"realm": realm}, "")
	if err != nil {
		return nil, err
	}

	var results []manifest.Resource
	for _, r := range all {
		id := fetchStringID(r.Data, "id")
		if id == "" {
			continue
		}
		if _, ok := ids[id]; ok {
			results = append(results, r)
		}
	}
	return results, nil
}

func fetchStringID(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if s, ok := data[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}
