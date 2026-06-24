package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	admininternal "github.com/thedataflows/keycloak-cli/pkg/admin/internal"
	"github.com/thedataflows/keycloak-cli/pkg/catalog"
	"github.com/thedataflows/keycloak-cli/pkg/manifest"
)

// conflictResolutionMaxResults is the page size used when fetching a collection
// to locate an existing resource by name. Keycloak collection endpoints default
// to small pages (e.g. 20 clients), which is too small for bulk uploads.
const conflictResolutionMaxResults = "10000"

type ApplyOptions struct {
	DryRun          bool
	Delete          bool
	ContinueOnError bool
	Reconcile       bool
}
type ApplyReport struct {
	Results []ApplyResult
	Failed  int
}

type ApplyResult struct {
	Resource string `json:"resource"`
	Realm    string `json:"realm,omitempty"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Status   int    `json:"status"`
	Error    string `json:"error,omitempty"`
}

func (s *service) Apply(ctx context.Context, resources []manifest.Resource, relationships []manifest.RelationshipOperation, options ApplyOptions) (ApplyReport, error) {
	realmFinalization := make([]manifest.Resource, 0)
	for i := range resources {
		if resources[i].Type == "realm" && realmHasDeferredConfig(resources[i].Data) {
			realmFinalization = append(realmFinalization, resources[i])
		}
		resources[i].Data = sanitizeResourceData(resources[i].Type, resources[i].Data)
	}
	validationResources := make([]manifest.Resource, len(resources))
	for i, r := range resources {
		validationResources[i] = manifest.StripVolatileFields(r)
	}
	if err := s.Spec().ValidateManifest(validationResources, relationships, options.Delete); err != nil {
		return ApplyReport{}, err
	}
	contracts, _ := s.Spec().ResourceContracts()
	specGraph, _ := s.Spec().BuildDependencyGraph()
	priorityMap, err := priorityMapWithInlineReferences(resources, specGraph)
	if err != nil {
		return ApplyReport{}, fmt.Errorf("compute apply order: %w", err)
	}
	sorted := manifest.SortResources(resources, priorityMap)
	report := ApplyReport{
		Results: make([]ApplyResult, 0, len(sorted)+len(relationships)+len(realmFinalization)),
	}
	idMap := make(map[string]string)
	resourceIndex := buildResourceIdentityIndex(sorted)

	for _, resource := range sorted {
		result := s.applyResource(ctx, resource, contracts, idMap, resourceIndex, options)
		report.Results = append(report.Results, result)
		if err := accumulateApplyResult(&report, result, options, "upload failed"); err != nil {
			return report, err
		}
	}

	// Realm config references resources (authentication flows, default role)
	// that are only created during the main apply loop. Re-apply realm resources
	// last so their full config (flows, defaultRole, etc.) can be resolved.
	realmResults := s.applyRealmsLast(ctx, realmFinalization, contracts, idMap, resourceIndex, options)
	report.Results = append(report.Results, realmResults...)
	for _, result := range realmResults {
		if err := accumulateApplyResult(&report, result, options, "realm finalization failed"); err != nil {
			return report, err
		}
	}

	if len(relationships) == 0 {
		return report, nil
	}

	relationships = rewriteRelationshipIDs(relationships, idMap)

	if options.Reconcile {
		actual, fetchFailures := s.fetchRelationships(ctx, relationshipRealms(relationships), nil)
		if len(fetchFailures) > 0 {
			for _, failure := range fetchFailures {
				report.Results = append(report.Results, ApplyResult{
					Resource: "relationship",
					Action:   "failed",
					Status:   http.StatusInternalServerError,
					Error:    failure.String(),
				})
				report.Failed++
			}
			if !options.ContinueOnError {
				return report, fmt.Errorf("fetch relationships for reconciliation: %s", fetchFailures[0])
			}
		}

		toAdd, toRemove := reconcileRelationshipSets(relationships, actual)
		relationships = append(toRemove, toAdd...)
	}

	relationshipResults := s.applyRelationships(ctx, relationships, options)
	report.Results = append(report.Results, relationshipResults...)

	for _, result := range relationshipResults {
		if err := accumulateApplyResult(&report, result, options, "relationship upload failed"); err != nil {
			return report, err
		}
	}

	return report, nil
}

func accumulateApplyResult(report *ApplyReport, result ApplyResult, options ApplyOptions, prefix string) error {
	if result.Status < 400 {
		return nil
	}
	report.Failed++
	if !options.ContinueOnError {
		return fmt.Errorf("%s: %s", prefix, result.Error)
	}
	return nil
}

func realmHasDeferredConfig(data map[string]interface{}) bool {
	for key, value := range data {
		if !isRealmDeferredConfigField(key) {
			continue
		}
		if value == nil {
			continue
		}
		if s, ok := value.(string); ok && s == "" {
			continue
		}
		if m, ok := value.(map[string]interface{}); ok && len(m) == 0 {
			continue
		}
		return true
	}
	return false
}

func (s *service) applyRealmsLast(ctx context.Context, resources []manifest.Resource, contracts map[string]catalog.ResourceContract, idMap map[string]string, index resourceIdentityIndex, options ApplyOptions) []ApplyResult {
	var results []ApplyResult
	for _, resource := range resources {
		if resource.Type != "realm" {
			continue
		}
		result := s.applyResource(ctx, resource, contracts, idMap, index, options)
		results = append(results, result)
	}
	return results
}

type resourceIdentityIndex struct {
	byTypeRealm   map[string]map[string][]manifest.Resource
	byTypeRealmID map[string]map[string]manifest.Resource
	resolvedCache map[string]string
}

func buildResourceIdentityIndex(resources []manifest.Resource) resourceIdentityIndex {
	index := resourceIdentityIndex{
		byTypeRealm:   make(map[string]map[string][]manifest.Resource),
		byTypeRealmID: make(map[string]map[string]manifest.Resource),
		resolvedCache: make(map[string]string),
	}
	for _, r := range resources {
		byRealm, ok := index.byTypeRealm[r.Type]
		if !ok {
			byRealm = make(map[string][]manifest.Resource)
			index.byTypeRealm[r.Type] = byRealm
		}
		byRealm[r.Realm] = append(byRealm[r.Realm], r)

		if id := stringID(r.Data, "id"); id != "" {
			byRealmID, ok := index.byTypeRealmID[r.Type]
			if !ok {
				byRealmID = make(map[string]manifest.Resource)
				index.byTypeRealmID[r.Type] = byRealmID
			}
			byRealmID[id] = r
		}
	}
	return index
}

func (i resourceIdentityIndex) lookup(parentType, realm, identifier string) manifest.Resource {
	byRealm, ok := i.byTypeRealm[parentType]
	if !ok {
		return manifest.Resource{}
	}
	for _, r := range byRealm[realm] {
		if r.Identifier() == identifier || r.Name() == identifier {
			return r
		}
	}
	return manifest.Resource{}
}

func (i resourceIdentityIndex) lookupByID(parentType, id string) manifest.Resource {
	byRealmID, ok := i.byTypeRealmID[parentType]
	if !ok {
		return manifest.Resource{}
	}
	return byRealmID[id]
}

func (i resourceIdentityIndex) cacheKey(parentType, realm, identifier string) string {
	return strings.Join([]string{parentType, realm, identifier}, "|")
}

func (s *service) applyRelationships(ctx context.Context, relationships []manifest.RelationshipOperation, options ApplyOptions) []ApplyResult {
	results := make([]ApplyResult, 0, len(relationships))
	for _, rel := range relationships {
		result := ApplyResult{
			Resource: "relationship",
			Realm:    rel.PathParams["realm"],
			Name:     fmt.Sprintf("%s %s", strings.ToUpper(rel.Method), rel.Path),
		}

		if options.DryRun {
			result.Action = "dry-run"
			result.Status = http.StatusOK
			results = append(results, result)
			continue
		}
		operationCtx, cancel := s.operationContext(ctx)
		status, err := s.specClient.ExecuteRelationship(operationCtx, rel)
		cancel()

		switch {
		case err == nil:
			result.Action = "applied"
			result.Status = status
		case status == http.StatusConflict:
			log.Logger.Debug().Str("pkg", "admin").Msgf("relationship already satisfied: %s", result.Name)
			result.Action = "unchanged"
			result.Status = http.StatusOK
		default:
			if status == 0 {
				status = http.StatusInternalServerError
			}
			typedErr := classifyError(err, status, "apply", "relationship")
			result.Action = "failed"
			result.Status = status
			result.Error = typedErr.Error()
		}

		results = append(results, result)
	}

	return results
}

func (s *service) resourceName(resource manifest.Resource) string {
	if identity, ok := s.resourceIdentity(resource.Type); ok {
		if name := catalog.NameOf(resource, identity); name != "" {
			return name
		}
	}
	return resource.Name()
}

func (s *service) resourceDisplayName(resource manifest.Resource) string {
	if identity, ok := s.resourceIdentity(resource.Type); ok {
		if name := catalog.DisplayNameOf(resource, identity); name != "" {
			return name
		}
	}
	return resource.DisplayName()
}

func (s *service) applyResource(ctx context.Context, resource manifest.Resource, contracts map[string]catalog.ResourceContract, idMap map[string]string, index resourceIdentityIndex, options ApplyOptions) ApplyResult {
	resource.Data = stripUnresolvedClientFlowBindingOverrides(resource.Data, idMap)
	resource.Data = remapResourceDataIDs(resource.Data, idMap)
	s.resolveParentReferences(ctx, &resource, index, idMap)

	result := ApplyResult{
		Resource: resource.Type,
		Realm:    resource.Realm,
		Name:     s.resourceDisplayName(resource),
	}

	// Keycloak auto-creates a default authorization resource for clients with
	// authorization enabled. Re-creating it fails because the request must
	// include a valid owner id, so skip it and leave the auto-created resource
	// in place.
	if resource.Type == "resource" && resource.Name() == "Default Resource" {
		result.Action = "skipped"
		result.Status = http.StatusOK
		return result
	}

	if options.Delete {
		resource.Delete = true
	}

	if options.DryRun {
		result.Action = "dry-run"
		result.Status = http.StatusOK
		return result
	}

	operationCtx, cancel := s.operationContext(ctx)
	defer cancel()

	resolver := s.Spec().Resolver()
	originalID := stringID(resource.Data, "id")

	resourceExists := s.locateExistingResource(operationCtx, &resource, idMap)

	hasDelete := operationExists(resolver, resource, http.MethodDelete, catalog.OperationSingle)
	hasPost := operationExists(resolver, resource, http.MethodPost, catalog.OperationAny)

	if resource.Delete {
		return s.applyDelete(operationCtx, resource, hasDelete, resourceExists, idMap)
	}

	if !resourceExists && hasPost {
		created, ok := s.tryCreate(operationCtx, resource, originalID, idMap)
		if ok {
			return created
		}
	}

	return s.applyUpdate(operationCtx, resource)
}

func (s *service) resolveParentReferences(ctx context.Context, resource *manifest.Resource, index resourceIdentityIndex, idMap map[string]string) {
	if resource == nil || resource.ParentType == "" || len(resource.Data) == 0 {
		return
	}
	resolver := s.Spec().Resolver()
	contract, err := resolver.ResolveResourceOperation(resource.Type, resource.ParentType, http.MethodPost, catalog.OperationCollection)
	if err != nil {
		return
	}
	for field, parentType := range resolver.ParentReferenceFieldTypes(resource.Type, contract) {
		value, ok := resource.Data[field].(string)
		if !ok || value == "" {
			continue
		}
		resolved := s.resolveParentIdentifier(ctx, parentType, resource.Realm, value, index, idMap)
		if resolved != "" {
			resource.Data[field] = resolved
		}
	}
}

func (s *service) resolveParentIdentifier(ctx context.Context, parentType, realm, identifier string, index resourceIdentityIndex, idMap map[string]string) string {
	cacheKey := index.cacheKey(parentType, realm, identifier)
	if resolved, ok := index.resolvedCache[cacheKey]; ok {
		return resolved
	}
	if targetID := idMap[identifier]; targetID != "" {
		index.resolvedCache[cacheKey] = targetID
		return targetID
	}
	if looksLikeUUID(identifier) {
		if parent := index.lookupByID(parentType, identifier); parent.Data != nil {
			if sourceID := stringID(parent.Data, "id"); sourceID != "" {
				if targetID := idMap[sourceID]; targetID != "" {
					index.resolvedCache[cacheKey] = targetID
					return targetID
				}
			}
		}
		operationCtx, cancel := s.operationContext(ctx)
		defer cancel()
		parentResource := manifest.Resource{Type: parentType, Realm: realm, Data: map[string]interface{}{"id": identifier}}
		fetched, exists, err := s.specClient.FetchResource(operationCtx, parentResource)
		if err == nil && exists {
			if id := stringID(fetched.Data, "id"); looksLikeUUID(id) {
				index.resolvedCache[cacheKey] = id
				return id
			}
		}
	}
	if parent := index.lookup(parentType, realm, identifier); parent.Data != nil {
		if sourceID := stringID(parent.Data, "id"); sourceID != "" {
			if targetID := idMap[sourceID]; targetID != "" {
				index.resolvedCache[cacheKey] = targetID
				return targetID
			}
			if looksLikeUUID(sourceID) {
				index.resolvedCache[cacheKey] = sourceID
				return sourceID
			}
		}
	}
	operationCtx, cancel := s.operationContext(ctx)
	defer cancel()
	fetched, err := s.specClient.FetchResources(operationCtx, parentType, map[string]string{"realm": realm}, map[string]string{"max": conflictResolutionMaxResults})
	if err != nil {
		log.Logger.Debug().Str("pkg", "admin").Msgf("resolve %s %q in realm %s failed: %v", parentType, identifier, realm, err)
		index.resolvedCache[cacheKey] = ""
		return ""
	}
	for _, item := range fetched {
		if item.Identifier() != identifier && item.Name() != identifier {
			continue
		}
		if id := stringID(item.Data, "id"); looksLikeUUID(id) {
			index.resolvedCache[cacheKey] = id
			return id
		}
	}
	index.resolvedCache[cacheKey] = ""
	return ""
}

func remapResourceDataIDs(data map[string]interface{}, idMap map[string]string) map[string]interface{} {
	if len(idMap) == 0 {
		return data
	}
	remapped := remapIDs(data, idMap)
	if asMap, ok := remapped.(map[string]interface{}); ok {
		return asMap
	}
	return data
}

// sanitizeResourceData recursively removes nil values and empty maps from
// resource payloads before validation and upload. Keycloak frequently returns
// null for optional fields, but its own Admin API rejects those same nulls on
// create/update. It also strips a few copy-incompatible client attributes whose
// values depend on the target realm's session timeouts.
func sanitizeResourceData(resourceType string, data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}
	cleaned := make(map[string]interface{}, len(data))
	for key, value := range data {
		if resourceType == "client" && key == "attributes" {
			value = stripClientTimeoutAttributes(value)
		}
		if resourceType == "realm" && isRealmDeferredConfigField(key) {
			continue
		}
		if key == "realm" && resourceType != "realm" {
			continue
		}
		sanitized := sanitizeValue(value)
		if isEmptyValue(sanitized) {
			continue
		}
		cleaned[key] = sanitized
	}
	return cleaned
}

func isRealmDeferredConfigField(key string) bool {
	switch key {
	case "defaultRole", "browserFlow", "registrationFlow", "directGrantFlow",
		"resetCredentialsFlow", "clientAuthenticationFlow", "dockerAuthenticationFlow":
		return true
	}
	return false
}

// sanitizeMap performs generic nil/empty-map removal on any nested map. It is
// used by sanitizeValue so nested structures are cleaned without reapplying
// resource-type-specific rules.
func sanitizeMap(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}
	cleaned := make(map[string]interface{}, len(data))
	for key, value := range data {
		sanitized := sanitizeValue(value)
		if isEmptyValue(sanitized) {
			continue
		}
		cleaned[key] = sanitized
	}
	return cleaned
}

// stripClientTimeoutAttributes removes client-specific session timeout
// attributes that are tied to the source realm's SSO session settings. When
// those attributes are copied to a realm with stricter timeouts, Keycloak
// rejects the client create/update request.
func stripClientTimeoutAttributes(value interface{}) interface{} {
	attrs, ok := value.(map[string]interface{})
	if !ok {
		return value
	}
	cleaned := make(map[string]interface{}, len(attrs))
	for k, v := range attrs {
		if k == "client.session.idle.timeout" || k == "client.session.max.lifespan" {
			continue
		}
		cleaned[k] = v
	}
	return cleaned
}

// stripUnresolvedClientFlowBindingOverrides removes per-client authentication
// flow binding overrides whose target flow IDs are not present in the idMap.
// Keycloak throws an uncaught 500 when a client references a missing flow, so
// unresolved overrides are dropped and the client falls back to realm defaults.
func stripUnresolvedClientFlowBindingOverrides(data map[string]interface{}, idMap map[string]string) map[string]interface{} {
	if data == nil {
		return nil
	}
	overrides, ok := data["authenticationFlowBindingOverrides"].(map[string]interface{})
	if !ok {
		return data
	}
	cleaned := make(map[string]interface{}, len(overrides))
	for binding, value := range overrides {
		flowID, ok := value.(string)
		if !ok || flowID == "" {
			continue
		}
		if !looksLikeUUID(flowID) {
			cleaned[binding] = value
			continue
		}
		if _, resolved := idMap[flowID]; resolved {
			cleaned[binding] = value
		}
	}
	if len(cleaned) == 0 {
		delete(data, "authenticationFlowBindingOverrides")
	} else {
		data["authenticationFlowBindingOverrides"] = cleaned
	}
	return data
}

func sanitizeValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		return sanitizeMap(typed)
	case []interface{}:
		cleaned := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			sanitized := sanitizeValue(item)
			if sanitized != nil {
				cleaned = append(cleaned, sanitized)
			}
		}
		return cleaned
	default:
		return value
	}
}

func isEmptyValue(value interface{}) bool {
	if value == nil {
		return true
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		return len(typed) == 0
	default:
		return false
	}
}

func operationExists(resolver *catalog.Resolver, resource manifest.Resource, method string, shape catalog.OperationShape) bool {
	_, err := resolver.ResolveResourceOperation(resource.Type, resource.ParentType, method, shape)
	return err == nil
}

func (s *service) newResourceResult(resource manifest.Resource, action string, status int, err error) ApplyResult {
	result := ApplyResult{
		Resource: resource.Type,
		Realm:    resource.Realm,
		Name:     s.resourceDisplayName(resource),
		Action:   action,
		Status:   status,
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func (s *service) applyDelete(ctx context.Context, resource manifest.Resource, hasDelete, resourceExists bool, idMap map[string]string) ApplyResult {
	if !hasDelete {
		return s.newResourceResult(resource, "not-supported", http.StatusOK, nil)
	}
	if !resourceExists && stringID(resource.Data, "id") == "" {
		return s.newResourceResult(resource, "not-found", http.StatusOK, nil)
	}

	status, err := s.specClient.DeleteResource(ctx, resource)
	if err == nil {
		return s.newResourceResult(resource, "deleted", status, nil)
	}
	if status == http.StatusNotFound {
		return s.newResourceResult(resource, "not-found", http.StatusOK, nil)
	}
	return s.newResourceResult(resource, "failed", status, classifyError(err, status, "delete", resource.Type))
}

func isOrganizationDisabledError(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *admininternal.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusBadRequest && strings.Contains(httpErr.Body, "Organizations not enabled")
	}
	return false
}

func (s *service) tryCreate(ctx context.Context, resource manifest.Resource, originalID string, idMap map[string]string) (ApplyResult, bool) {
	status, createdID, err := s.specClient.CreateResource(ctx, resource)
	if err == nil && status < 300 {
		if originalID != "" && idMap != nil {
			serverID := s.resolveCreatedID(ctx, resource, createdID)
			if serverID != "" && originalID != serverID {
				idMap[originalID] = serverID
			}
		}
		return s.newResourceResult(resource, "created", status, nil), true
	}
	if status == http.StatusConflict {
		log.Logger.Debug().Str("pkg", "admin").Str("type", resource.Type).Str("name", s.resourceName(resource)).Int("status", status).Msg("create conflict; falling back to update")
		if resolveErr := s.resolveExistingResourceID(ctx, &resource, idMap); resolveErr == nil {
			return ApplyResult{}, false
		}
	}
	if err != nil {
		if resource.Type == "organization" && isOrganizationDisabledError(err) {
			return s.newResourceResult(resource, "skipped", http.StatusOK, nil), true
		}
		return s.newResourceResult(resource, "failed", status, classifyError(err, status, "apply", resource.Type)), true
	}
	return s.newResourceResult(resource, "failed", status, fmt.Errorf("unknown error")), true
}

func (s *service) applyUpdate(ctx context.Context, resource manifest.Resource) ApplyResult {
	status, err := s.specClient.UpdateResource(ctx, resource)
	if err == nil {
		return s.newResourceResult(resource, "updated", status, nil)
	}
	if resource.Type == "organization" && isOrganizationDisabledError(err) {
		return s.newResourceResult(resource, "skipped", http.StatusOK, nil)
	}
	return s.newResourceResult(resource, "failed", status, classifyError(err, status, "apply", resource.Type))
}

func (s *service) resolveCreatedID(ctx context.Context, resource manifest.Resource, createdID string) string {
	if createdID != "" && looksLikeUUID(createdID) {
		return createdID
	}
	var fetched []manifest.Resource
	var err error
	if resource.ParentType != "" {
		fetched, err = s.specClient.FetchResourcesWithParent(ctx, resource)
	} else {
		fetched, err = s.specClient.FetchResources(ctx, resource.Type, map[string]string{"realm": resource.Realm})
	}
	if err != nil {
		return ""
	}
	for _, item := range fetched {
		if strings.EqualFold(s.resourceName(resource), s.resourceName(item)) {
			if id := stringID(item.Data, "id"); id != "" {
				return id
			}
			break
		}
	}
	return ""
}

func mapID(idMap map[string]string, originalID, serverID string) {
	if idMap != nil && originalID != "" && originalID != serverID {
		idMap[originalID] = serverID
	}
}

func stringID(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if id, ok := data[key].(string); ok {
		return id
	}
	return ""
}

// locateExistingResource checks whether a resource already exists on the server
// and, if so, copies its server-assigned id into resource.Data and the idMap.
// It returns false when the resource cannot be found.
func (s *service) locateExistingResource(ctx context.Context, resource *manifest.Resource, idMap map[string]string) bool {
	_, err := s.resolveExistingResource(ctx, resource, idMap, false)
	return err == nil
}

// resolveExistingResourceID is used when a create returns 409 but we do not yet
// know the server's id. It locates the existing resource by name and updates
// resource.Data with the server id.
func (s *service) resolveExistingResourceID(ctx context.Context, resource *manifest.Resource, idMap map[string]string) error {
	_, err := s.resolveExistingResource(ctx, resource, idMap, true)
	return err
}

func (s *service) resolveExistingResource(ctx context.Context, resource *manifest.Resource, idMap map[string]string, allowCollectionFallback bool) (manifest.Resource, error) {
	resolver := s.Spec().Resolver()
	originalID := stringID(resource.Data, "id")

	if operationExists(resolver, *resource, http.MethodGet, catalog.OperationSingle) {
		fetched, exists, err := s.specClient.FetchResource(ctx, *resource)
		if err != nil {
			log.Logger.Debug().Str("pkg", "admin").Msgf("fetch resource %s/%s failed: %v", resource.Type, s.resourceName(*resource), err)
		}
		if exists {
			if fetchedID := stringID(fetched.Data, "id"); fetchedID != "" {
				resource.Data["id"] = fetchedID
				mapID(idMap, originalID, fetchedID)
			}
			return fetched, nil
		}
		if !allowCollectionFallback {
			return manifest.Resource{}, fmt.Errorf("not found")
		}
	} else if !allowCollectionFallback {
		log.Logger.Warn().Str("pkg", "admin").Str("type", resource.Type).Msg("no single GET endpoint; falling back to collection search")
	}

	fetched, fetchErr := s.specClient.FetchResourcesWithParent(ctx, *resource, map[string]string{"max": conflictResolutionMaxResults})
	if fetchErr != nil {
		// Fall back to the realm-level collection endpoint for resources that are not nested.
		if resource.ParentType == "" {
			fetched, fetchErr = s.specClient.FetchResources(ctx, resource.Type, map[string]string{"realm": resource.Realm}, map[string]string{"max": conflictResolutionMaxResults})
		}
		if fetchErr != nil {
			return manifest.Resource{}, fetchErr
		}
	}
	for i := range fetched {
		if !strings.EqualFold(s.resourceName(*resource), s.resourceName(fetched[i])) {
			continue
		}
		if fetchedID := stringID(fetched[i].Data, "id"); fetchedID != "" {
			resource.Data["id"] = fetchedID
			mapID(idMap, originalID, fetchedID)
		}
		return fetched[i], nil
	}
	return manifest.Resource{}, fmt.Errorf("could not locate existing %s by name", resource.Type)
}

func (s *service) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if s.timeout <= 0 {
		return context.WithCancel(parent)
	}
	// Use WithoutCancel so the per-request timeout is independent of any
	// command-level deadline. Bulk uploads may issue hundreds of sequential
	// requests; sharing the command deadline causes later requests to fail
	// immediately once the first batch consumes the budget.
	return context.WithTimeout(context.WithoutCancel(parent), s.timeout)
}

func rewriteRelationshipIDs(relationships []manifest.RelationshipOperation, idMap map[string]string) []manifest.RelationshipOperation {
	if len(idMap) == 0 {
		return relationships
	}

	for i := range relationships {
		rel := &relationships[i]
		for key, value := range rel.PathParams {
			if mapped, ok := idMap[value]; ok {
				rel.PathParams[key] = mapped
			}
		}

		rel.RebuildPath()

		if len(rel.Data) == 0 {
			continue
		}

		var payload interface{}
		if err := json.Unmarshal(rel.Data, &payload); err != nil {
			continue
		}

		updated, err := json.Marshal(remapIDs(payload, idMap))
		if err != nil {
			continue
		}
		rel.Data = updated
	}

	return relationships
}

func remapIDs(node interface{}, idMap map[string]string) interface{} {
	switch typed := node.(type) {
	case string:
		if mapped, ok := idMap[typed]; ok {
			return mapped
		}
		return typed
	case map[string]interface{}:
		for key, value := range typed {
			typed[key] = remapIDs(value, idMap)
		}
		return typed
	case []interface{}:
		for i := range typed {
			typed[i] = remapIDs(typed[i], idMap)
		}
		return typed
	default:
		return typed
	}
}
func looksLikeUUID(s string) bool {
	// Loose check: 36 chars with hyphens at positions 8, 13, 18, 23.
	if len(s) != 36 {
		return false
	}
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

// priorityMapWithInlineReferences extends a spec-derived dependency graph with
// edges discovered from inline UUID references in the manifest. If a resource
// of type A contains a UUID that matches the id of a resource of type B in the
// same manifest, A is ordered after B so the reference can be remapped to B's
// target-server id during apply.
func priorityMapWithInlineReferences(resources []manifest.Resource, specGraph map[string][]string) (map[string]int, error) {
	idToType := make(map[string]string, len(resources))
	for _, r := range resources {
		if id := stringID(r.Data, "id"); id != "" {
			idToType[id] = r.Type
		}
	}

	graph := make(map[string]map[string]struct{})
	addEdge := func(from, to string) {
		if graph[from] == nil {
			graph[from] = make(map[string]struct{})
		}
		graph[from][to] = struct{}{}
	}

	for child, parents := range specGraph {
		for _, parent := range parents {
			addEdge(child, parent)
		}
	}
	for _, r := range resources {
		if graph[r.Type] == nil {
			graph[r.Type] = make(map[string]struct{})
		}
	}

	for _, r := range resources {
		collectInlineReferenceTypes(r.Data, idToType, func(refType string) {
			if refType == "" || refType == r.Type {
				return
			}
			addEdge(r.Type, refType)
		})
	}

	return topologicalSortPriorityMap(graph)
}

func collectInlineReferenceTypes(value interface{}, idToType map[string]string, visitor func(string)) {
	switch typed := value.(type) {
	case string:
		if looksLikeUUID(typed) {
			if t, ok := idToType[typed]; ok {
				visitor(t)
			}
		}
	case map[string]interface{}:
		for _, v := range typed {
			collectInlineReferenceTypes(v, idToType, visitor)
		}
	case []interface{}:
		for _, v := range typed {
			collectInlineReferenceTypes(v, idToType, visitor)
		}
	}
}

func topologicalSortPriorityMap(graph map[string]map[string]struct{}) (map[string]int, error) {
	inDegree := make(map[string]int, len(graph))
	children := make(map[string]map[string]struct{})
	for node := range graph {
		inDegree[node] = 0
		children[node] = make(map[string]struct{})
	}
	for node, parents := range graph {
		for parent := range parents {
			if _, ok := graph[parent]; !ok {
				graph[parent] = make(map[string]struct{})
				inDegree[parent] = 0
				children[parent] = make(map[string]struct{})
			}
			inDegree[node]++
			children[parent][node] = struct{}{}
		}
	}

	queue := make([]string, 0, len(graph))
	for node, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}

	priority := 1
	result := make(map[string]int, len(graph))
	for len(queue) > 0 {
		nextQueue := make([]string, 0)
		for _, node := range queue {
			result[node] = priority
			for child := range children[node] {
				inDegree[child]--
				if inDegree[child] == 0 {
					nextQueue = append(nextQueue, child)
				}
			}
		}
		queue = nextQueue
		priority++
	}

	if len(result) != len(graph) {
		return nil, fmt.Errorf("inline reference dependencies contain a cycle")
	}
	return result, nil
}

func relationshipRealms(relationships []manifest.RelationshipOperation) []string {
	seen := make(map[string]struct{})
	realms := make([]string, 0)
	for _, rel := range relationships {
		realm := rel.PathParams["realm"]
		if realm == "" {
			continue
		}
		if _, ok := seen[realm]; ok {
			continue
		}
		seen[realm] = struct{}{}
		realms = append(realms, realm)
	}
	return realms
}

func relationshipKey(rel manifest.RelationshipOperation, identityFromPath bool) string {
	data := ""
	if len(rel.Data) > 0 && !identityFromPath {
		var payload interface{}
		if err := json.Unmarshal(rel.Data, &payload); err == nil {
			if canonical, err := json.Marshal(payload); err == nil {
				data = string(canonical)
			}
		}
	}
	return strings.Join([]string{rel.Kind, rel.Path, data}, "|")
}

func identityFromPath(rel manifest.RelationshipOperation) bool {
	kind, ok := catalog.DefaultRegistry().ByName(rel.Kind)
	if !ok {
		return false
	}
	return !kind.BulkPayload && kind.ItemParamName != ""
}

func reconcileRelationshipSets(desired, actual []manifest.RelationshipOperation) (toAdd, toRemove []manifest.RelationshipOperation) {
	actualByKey := make(map[string]manifest.RelationshipOperation, len(actual))
	for _, rel := range actual {
		actualByKey[relationshipKey(rel, identityFromPath(rel))] = rel
	}

	desiredKeys := make(map[string]struct{}, len(desired))
	for _, rel := range desired {
		key := relationshipKey(rel, identityFromPath(rel))
		desiredKeys[key] = struct{}{}
		if _, ok := actualByKey[key]; !ok {
			toAdd = append(toAdd, rel)
		}
	}

	for _, rel := range actual {
		if _, ok := desiredKeys[relationshipKey(rel, identityFromPath(rel))]; ok {
			continue
		}
		deleteOp, ok := buildRelationshipDeleteOperation(rel)
		if !ok {
			continue
		}
		toRemove = append(toRemove, deleteOp)
	}
	return toAdd, toRemove
}

func buildRelationshipDeleteOperation(rel manifest.RelationshipOperation) (manifest.RelationshipOperation, bool) {
	kind, ok := catalog.DefaultRegistry().ByName(rel.Kind)
	if !ok {
		return manifest.RelationshipOperation{}, false
	}
	op, err := catalog.BuildDeleteOperation(rel, kind)
	if err != nil {
		return manifest.RelationshipOperation{}, false
	}
	return op, true
}
