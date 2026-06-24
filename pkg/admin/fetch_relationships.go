package admin

import (
	"context"
	"strings"

	"github.com/thedataflows/keycloak-cli/pkg/catalog"
	"github.com/thedataflows/keycloak-cli/pkg/manifest"
)

// fetchRelationships retrieves relationship state for the supplied realms. When
// parentTypes is non-empty, only relationship kinds whose ResourceA is in the
// set are fetched. A nil or empty parentTypes map fetches all known kinds.
func (s *service) fetchRelationships(ctx context.Context, realms []string, parentTypes map[string]struct{}) ([]manifest.RelationshipOperation, []FetchFailure) {
	var results []manifest.RelationshipOperation
	var failures []FetchFailure

	for _, realm := range realms {
		realmRelationships, err := s.fetchRelationshipsForRealm(ctx, realm, parentTypes)
		if err != nil {
			failures = append(failures, FetchFailure{Resource: "relationships", Detail: realm, Err: err})
			continue
		}
		results = append(results, realmRelationships...)
	}

	if err := catalog.ValidateRelationshipOperations(s.Spec(), results); err != nil {
		failures = append(failures, FetchFailure{Resource: "relationships", Detail: "validation", Err: err})
	}

	return results, failures
}

func (s *service) fetchRelationshipsForRealm(ctx context.Context, realm string, parentTypes map[string]struct{}) ([]manifest.RelationshipOperation, error) {
	patterns, err := s.Spec().DiscoverRelationshipPatterns()
	if err != nil {
		return nil, err
	}

	placeholderMap, err := s.Spec().PlaceholderToResourceType()
	if err != nil {
		return nil, err
	}

	var results []manifest.RelationshipOperation

	for _, pattern := range patterns {
		if len(parentTypes) > 0 {
			if _, ok := parentTypes[pattern.ResourceA]; !ok {
				continue
			}
		}

		parentTypesList, err := pattern.ParentResourceTypes(placeholderMap)
		if err != nil {
			continue
		}

		parentIndexes, err := s.buildParentIndexes(ctx, realm, parentTypesList)
		if err != nil {
			continue
		}
		if len(parentTypesList) > 0 && len(parentIndexes) == 0 {
			continue
		}

		patternResults, patternErr := s.fetchRelationshipsForPattern(ctx, realm, pattern, parentIndexes, placeholderMap)
		if patternErr != nil {
			continue
		}
		results = append(results, patternResults...)
	}

	return results, nil
}

// fetchRelationshipsForResources fetches relationship kinds whose ResourceA is in
// parentTypes, but only for the supplied resources. Parent indexes are built from
// those resources instead of re-fetching whole collections from the server.
func (s *service) fetchRelationshipsForResources(ctx context.Context, realms []string, parentTypes map[string]struct{}, resources []manifest.Resource) ([]manifest.RelationshipOperation, []FetchFailure) {
	var results []manifest.RelationshipOperation
	var failures []FetchFailure

	for _, realm := range realms {
		realmRelationships, err := s.fetchRelationshipsForRealmFromResources(ctx, realm, parentTypes, resources)
		if err != nil {
			failures = append(failures, FetchFailure{Resource: "relationships", Detail: realm, Err: err})
			continue
		}
		results = append(results, realmRelationships...)
	}

	if err := catalog.ValidateRelationshipOperations(s.Spec(), results); err != nil {
		failures = append(failures, FetchFailure{Resource: "relationships", Detail: "validation", Err: err})
	}

	return results, failures
}

func (s *service) fetchRelationshipsForRealmFromResources(ctx context.Context, realm string, parentTypes map[string]struct{}, resources []manifest.Resource) ([]manifest.RelationshipOperation, error) {
	patterns, err := s.Spec().DiscoverRelationshipPatterns()
	if err != nil {
		return nil, err
	}

	placeholderMap, err := s.Spec().PlaceholderToResourceType()
	if err != nil {
		return nil, err
	}

	index := indexResourcesByTypeRealm(resources)
	var results []manifest.RelationshipOperation

	for _, pattern := range patterns {
		if _, ok := parentTypes[pattern.ResourceA]; !ok {
			continue
		}

		parentTypesList, err := pattern.ParentResourceTypes(placeholderMap)
		if err != nil {
			continue
		}

		parentIndexes := buildParentIndexesFromResources(index, realm, parentTypesList)
		if len(parentTypesList) > 0 && len(parentIndexes) == 0 {
			continue
		}

		patternResults, patternErr := s.fetchRelationshipsForPattern(ctx, realm, pattern, parentIndexes, placeholderMap)
		if patternErr != nil {
			continue
		}
		results = append(results, patternResults...)
	}

	return results, nil
}

func buildParentIndexesFromResources(index map[string]map[string][]manifest.Resource, realm string, parentTypes []string) []map[string]manifest.Resource {
	indexes := make([]map[string]manifest.Resource, 0, len(parentTypes))
	for _, resourceType := range parentTypes {
		resources := index[resourceType][realm]
		if len(resources) == 0 {
			return nil
		}
		m := make(map[string]manifest.Resource, len(resources))
		for _, r := range resources {
			m[r.Identifier()] = r
		}
		indexes = append(indexes, m)
	}
	return indexes
}

func (s *service) buildParentIndexes(ctx context.Context, realm string, parentTypes []string) ([]map[string]manifest.Resource, error) {
	indexes := make([]map[string]manifest.Resource, 0, len(parentTypes))
	for _, resourceType := range parentTypes {
		resources, err := s.fetchResourceCollection(ctx, resourceType, map[string]string{"realm": realm}, "")
		if err != nil {
			return nil, err
		}
		index := make(map[string]manifest.Resource, len(resources))
		for _, r := range resources {
			index[r.Identifier()] = r
		}
		indexes = append(indexes, index)
	}
	return indexes, nil
}

func (s *service) fetchRelationshipsForPattern(ctx context.Context, realm string, pattern catalog.RelationshipOperationPattern, parentIndexes []map[string]manifest.Resource, placeholderMap map[string]string) ([]manifest.RelationshipOperation, error) {
	var results []manifest.RelationshipOperation

	parentTypes, _ := pattern.ParentResourceTypes(placeholderMap)

	var iterate func(depth int, params map[string]string)
	iterate = func(depth int, params map[string]string) {
		if depth == len(parentIndexes) {
			results = append(results, s.fetchRelationshipsForPatternInstance(ctx, realm, pattern, params)...)
			return
		}
		paramName := paramNameForResourceType(pattern.PathParams, parentTypes[depth])
		if paramName == "" {
			return
		}
		for id, resource := range parentIndexes[depth] {
			value := resolveParentParamValue(paramName, id, resource)
			iterate(depth+1, copyParams(params, map[string]string{paramName: value}))
		}
	}

	iterate(0, map[string]string{"realm": realm})
	return results, nil
}

var paramNameByResourceType = map[string][]string{
	"client":                  {"client-uuid", "client"},
	"clientscope":             {"client-scope-id"},
	"group":                   {"group-id"},
	"user":                    {"user-id"},
	"role":                    {"role-name", "role-id"},
	"organization":            {"org-id"},
	"identityprovider":        {"alias"},
	"authenticationflow":      {"flowAlias"},
	"authenticationexecution": {"executionId"},
}

func paramNameForResourceType(pathParams []string, resourceType string) string {
	candidates, ok := paramNameByResourceType[resourceType]
	if !ok {
		return ""
	}
	paramSet := make(map[string]struct{}, len(pathParams))
	for _, param := range pathParams {
		if param != "realm" {
			paramSet[param] = struct{}{}
		}
	}
	for _, candidate := range candidates {
		if _, ok := paramSet[candidate]; ok {
			return candidate
		}
	}
	return ""
}

func resolveParentParamValue(paramName, identifier string, resource manifest.Resource) string {
	if paramName != "role-id" {
		return identifier
	}
	if idField, ok := resource.Data["id"].(string); ok && idField != "" {
		return idField
	}
	return identifier
}

func (s *service) fetchRelationshipsForPatternInstance(ctx context.Context, realm string, pattern catalog.RelationshipOperationPattern, params map[string]string) []manifest.RelationshipOperation {
	var results []manifest.RelationshipOperation

	payload, err := s.specClient.FetchPathCollection(ctx, pattern.Path, params)
	if err != nil {
		return results
	}

	if pattern.BulkPayload {
		if len(payload) == 0 {
			return results
		}
		rel := s.buildRelationship(pattern, params, params, payload)
		if rel != nil {
			results = append(results, *rel)
		}
		return results
	}

	for _, item := range payload {
		itemParams := copyParams(params, nil)
		itemValue := extractItemValue(pattern.ItemParamName, item)
		if pattern.ItemParamName != "" {
			if itemValue == "" {
				continue
			}
			if leaf := extractLeafParam(pattern.RelationshipTemplate); leaf != "" {
				itemParams[leaf] = itemValue
			}
		}

		data := relationshipPayload(pattern, item)
		rel := s.buildRelationship(pattern, params, itemParams, data)
		if rel != nil {
			results = append(results, *rel)
		}
	}

	return results
}

func (s *service) buildRelationship(pattern catalog.RelationshipOperationPattern, baseParams, itemParams map[string]string, data interface{}) *manifest.RelationshipOperation {
	relPath := catalog.RenderPath(pattern.RelationshipTemplate, itemParams)
	rel, err := manifest.NewRelationshipOperation(pattern.RelationshipTemplate, pattern.RelationshipMethod, itemParams, data)
	if err != nil {
		return nil
	}
	rel.Path = relPath
	if rel.Path == "" {
		rel.Path = catalog.RenderPath(pattern.RelationshipTemplate, baseParams)
	}
	return &rel
}

func extractItemValue(paramName string, item map[string]interface{}) string {
	if paramName == "" {
		return ""
	}
	if paramName == "identityProvider" {
		if v := stringValue(item, "identityProvider"); v != "" {
			return v
		}
		return stringValue(item, "provider")
	}
	return stringValue(item, paramName)
}

func relationshipPayload(pattern catalog.RelationshipOperationPattern, item map[string]interface{}) interface{} {
	if pattern.PayloadField != "" {
		return stringValue(item, pattern.PayloadField)
	}
	if pattern.ItemParamName == "" {
		return item
	}
	return nil
}

func extractLeafParam(template string) string {
	last := strings.LastIndex(template, "{")
	if last == -1 {
		return ""
	}
	end := strings.Index(template[last:], "}")
	if end == -1 {
		return ""
	}
	return template[last+1 : last+end]
}

func copyParams(base, extra map[string]string) map[string]string {
	result := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		result[k] = v
	}
	for k, v := range extra {
		result[k] = v
	}
	return result
}

func stringValue(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if s, ok := data[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}
