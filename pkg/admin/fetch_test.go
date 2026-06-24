package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thedataflows/keycloak-cli/pkg/admin"
	"github.com/thedataflows/keycloak-cli/pkg/manifest"
)

func TestFetchDepthZeroPreservesExistingBehavior(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes":
			writeJSON(t, w, []map[string]interface{}{{"id": "scope-1", "name": "email"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "clientscope", Depth: 0})
	require.NoError(t, err)
	require.Len(t, report.Resources, 1)
	assert.Equal(t, "clientscope", report.Resources[0].Type)
	assert.Equal(t, "scope-1", report.Resources[0].Data["id"])
	assert.NotContains(t, requestPaths, "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models")
}

func TestFetchDepthOneFetchesNestedChildren(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes":
			writeJSON(t, w, []map[string]interface{}{{"id": "scope-1", "name": "email"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{{"id": "mapper-1", "name": "email-mapper"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "clientscope", Depth: 1})
	require.NoError(t, err)
	require.Len(t, report.Resources, 2)
	assert.Contains(t, requestPaths, "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models")

	types := resourceTypes(report.Resources)
	assert.Contains(t, types, "clientscope")
	assert.Contains(t, types, "protocolmapper")

	var mapper *manifest.Resource
	for i := range report.Resources {
		if report.Resources[i].Type == "protocolmapper" {
			mapper = &report.Resources[i]
			break
		}
	}
	require.NotNil(t, mapper)
	assert.Equal(t, "mapper-1", mapper.Data["id"])
	assert.Equal(t, "scope-1", mapper.Data["clientScopeId"])
}

func TestFetchDepthOneInjectsClientParentIDIntoAuthzChildren(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients":
			writeJSON(t, w, []map[string]interface{}{{"id": "client-1", "clientId": "app"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/authz/resource-server/resource":
			writeJSON(t, w, []map[string]interface{}{{"_id": "res-1", "name": "Default Resource"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/authz/resource-server/scope":
			writeJSON(t, w, []map[string]interface{}{{"id": "scope-1", "name": "scope1"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "client", Depth: 1})
	require.NoError(t, err)

	var resource, scope *manifest.Resource
	for i := range report.Resources {
		switch report.Resources[i].Type {
		case "resource":
			resource = &report.Resources[i]
		case "scope":
			scope = &report.Resources[i]
		}
	}
	require.NotNil(t, resource)
	require.NotNil(t, scope)
	assert.Equal(t, "client-1", resource.Data["clientUuid"])
	assert.Equal(t, "client-1", scope.Data["clientUuid"])
}

func TestFetchDepthRespectsRealmFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes":
			writeJSON(t, w, []map[string]interface{}{{"id": "scope-1", "name": "email"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{{"id": "mapper-1", "name": "email-mapper"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Realm: "demo", Resources: "clientscope", Depth: 1})
	require.NoError(t, err)
	require.Len(t, report.Resources, 2)
	assert.Equal(t, "demo", report.Resources[0].Realm)
	assert.Equal(t, "demo", report.Resources[1].Realm)
}

func TestFetchDepthOneDoesNotFetchRelationships(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes":
			writeJSON(t, w, []map[string]interface{}{{"id": "scope-1", "name": "email"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{{"id": "mapper-1", "name": "email-mapper"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "clientscope", Depth: 1})
	require.NoError(t, err)
	assert.Empty(t, report.Relationships)
	assert.NotContains(t, requestPaths, "/admin/realms/demo/client-scopes/scope-1/scope-mappings/realm")
}

func TestFetchFilterScopesDepthExpansion(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "scope-1", "name": "email"},
				{"id": "scope-2", "name": "profile"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{{"id": "mapper-1", "name": "email-mapper"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes/scope-2/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{{"id": "mapper-2", "name": "profile-mapper"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "clientscope", Depth: 1, Filter: "email"})
	require.NoError(t, err)
	require.Len(t, report.Resources, 2)
	assert.Contains(t, requestPaths, "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models")
	assert.NotContains(t, requestPaths, "/admin/realms/demo/client-scopes/scope-2/protocol-mappers/models")
}

func TestFetchDepthTwoFetchesChildRelationships(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		t.Logf("request: %s %s", r.Method, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients":
			writeJSON(t, w, []map[string]interface{}{{"id": "client-1", "clientId": "app"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/roles":
			writeJSON(t, w, []map[string]interface{}{{"id": "role-1", "name": "app-role"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/roles-by-id/role-1/composites":
			writeJSON(t, w, []map[string]interface{}{{"id": "role-2", "name": "composite-role"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "client", Depth: 2})
	require.NoError(t, err)
	t.Logf("resources: %v", resourceTypes(report.Resources))
	t.Logf("relationships: %v", relationshipKindsFromFetch(report.Relationships))
	t.Logf("failures: %v", report.Failures)
	require.NotEmpty(t, report.Relationships)
	kinds := relationshipKindsFromFetch(report.Relationships)
	assert.Contains(t, kinds, "role-composite-mapping")
}

func TestFetchDepthOneResolvesIDReferences(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "client-1", "clientId": "fcc", "authenticationFlowBindingOverrides": map[string]interface{}{"browser": "f4509057-d632-42d8-9ce8-4a2f832a8620"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/authentication/flows":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "f4509057-d632-42d8-9ce8-4a2f832a8620", "alias": "browser", "providerId": "basic-flow"},
				{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "alias": "other", "providerId": "basic-flow"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "client", Filter: "fcc", Depth: 1})
	require.NoError(t, err)
	require.Contains(t, requestPaths, "/admin/realms/demo/authentication/flows")

	types := resourceTypes(report.Resources)
	assert.Contains(t, types, "client")
	assert.Contains(t, types, "authenticationflow")

	var flow *manifest.Resource
	for i := range report.Resources {
		if report.Resources[i].Type == "authenticationflow" {
			flow = &report.Resources[i]
			break
		}
	}
	require.NotNil(t, flow)
	assert.Equal(t, "f4509057-d632-42d8-9ce8-4a2f832a8620", flow.Data["id"])
}

func relationshipKindsFromFetch(rels []manifest.RelationshipOperation) []string {
	kinds := make([]string, len(rels))
	for i, r := range rels {
		kinds[i] = r.Kind
	}
	return kinds
}

func TestFetchDepthTwoResolvesReferencesFromChildren(t *testing.T) {
	requestPaths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "client-1", "clientId": "fcc"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/roles":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "role-1", "name": "app-role", "attributes": map[string]interface{}{"flowRef": []interface{}{"f4509057-d632-42d8-9ce8-4a2f832a8620"}}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/authentication/flows":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "f4509057-d632-42d8-9ce8-4a2f832a8620", "alias": "browser", "providerId": "basic-flow"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)
	report, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "client", Filter: "fcc", Depth: 2})
	require.NoError(t, err)
	require.Contains(t, requestPaths, "/admin/realms/demo/authentication/flows")

	types := resourceTypes(report.Resources)
	assert.Contains(t, types, "client")
	assert.Contains(t, types, "role")
	assert.Contains(t, types, "authenticationflow")

	var flow *manifest.Resource
	for i := range report.Resources {
		if report.Resources[i].Type == "authenticationflow" {
			flow = &report.Resources[i]
			break
		}
	}
	require.NotNil(t, flow)
	assert.Equal(t, "f4509057-d632-42d8-9ce8-4a2f832a8620", flow.Data["id"])
}

func TestFetchAllDefaultResourcesIsIdempotentAcrossDepths(t *testing.T) {
	server := httptest.NewServer(newIdempotentMockHandler(t))
	defer server.Close()

	service := newServiceForTest(t, server.URL)

	for _, depth := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("depth-%d", depth), func(t *testing.T) {
			first, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "realm,user,client,group,role", Realm: "demo", Depth: depth})
			require.NoError(t, err)

			second, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "realm,user,client,group,role", Realm: "demo", Depth: depth})
			require.NoError(t, err)

			assertNoDuplicateResources(t, first.Resources)
			assertNoDuplicateResources(t, second.Resources)
			assertResourceSetsEqual(t, first.Resources, second.Resources)
		})
	}
}

func TestFetchDepthIsMonotonic(t *testing.T) {
	server := httptest.NewServer(newIdempotentMockHandler(t))
	defer server.Close()

	service := newServiceForTest(t, server.URL)

	depth0, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "realm,user,client,group,role", Realm: "demo", Depth: 0})
	require.NoError(t, err)

	depth1, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "realm,user,client,group,role", Realm: "demo", Depth: 1})
	require.NoError(t, err)

	depth2, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "realm,user,client,group,role", Realm: "demo", Depth: 2})
	require.NoError(t, err)

	assert.Less(t, len(depth0.Resources), len(depth1.Resources))
	assert.LessOrEqual(t, len(depth1.Resources), len(depth2.Resources))

	depth1Types := resourceTypes(depth1.Resources)
	depth2Types := resourceTypes(depth2.Resources)

	assert.Contains(t, depth1Types, "client")
	assert.Contains(t, depth1Types, "protocolmapper")
	assert.Contains(t, depth1Types, "authenticationflow")
	assert.Contains(t, depth2Types, "role")
}

func newIdempotentMockHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo":
			writeJSON(t, w, map[string]interface{}{"realm": "demo", "enabled": true})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/users":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "user-1", "username": "alice"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "client-1", "clientId": "fcc", "authenticationFlowBindingOverrides": map[string]interface{}{"browser": "f4509057-d632-42d8-9ce8-4a2f832a8620"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/groups":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "group-1", "name": "admins"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/roles":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "realm-role-1", "name": "reader"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "scope-1", "name": "email"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/authentication/flows":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "f4509057-d632-42d8-9ce8-4a2f832a8620", "alias": "browser", "providerId": "basic-flow"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "mapper-1", "name": "docker-v2-allow-all-mapper", "protocol": "docker-v2"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/roles":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "client-role-1", "name": "read", "attributes": map[string]interface{}{"scopeRef": []interface{}{"a1b2c3d4-e5f6-7890-abcd-ef1234567890"}}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes/scope-1/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "scope-mapper-1", "name": "email-mapper"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestFetchDepthFourWalksDeepReferenceChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
			writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "client-1", "clientId": "fcc", "authenticationFlowBindingOverrides": map[string]interface{}{"browser": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/authentication/flows":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1", "alias": "flow-a", "providerId": "basic-flow", "copyOf": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2"},
				{"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2", "alias": "flow-b", "providerId": "basic-flow", "copyOf": "cccccccc-cccc-cccc-cccc-ccccccccccc3"},
				{"id": "cccccccc-cccc-cccc-cccc-ccccccccccc3", "alias": "flow-c", "providerId": "basic-flow", "copyOf": "dddddddd-dddd-dddd-dddd-ddddddddddd4"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/client-scopes":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "dddddddd-dddd-dddd-dddd-ddddddddddd4", "name": "deep-scope", "linkedRole": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeee5"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/roles":
			writeJSON(t, w, []map[string]interface{}{
				{"id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeee5", "name": "deep-role"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/roles":
			writeJSON(t, w, []map[string]interface{}{})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/clients/client-1/protocol-mappers/models":
			writeJSON(t, w, []map[string]interface{}{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service := newServiceForTest(t, server.URL)

	depth1, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "client", Filter: "fcc", Depth: 1})
	require.NoError(t, err)

	depth5, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "client", Filter: "fcc", Depth: 5})
	require.NoError(t, err)

	assert.Less(t, len(depth1.Resources), len(depth5.Resources))

	types := resourceTypes(depth5.Resources)
	assert.Contains(t, types, "client")
	assert.Contains(t, types, "authenticationflow")
	assert.Contains(t, types, "clientscope")
	assert.Contains(t, types, "role")

	assertNoDuplicateResources(t, depth5.Resources)

	first, err := service.Fetch(context.Background(), admin.FetchQuery{Resources: "client", Filter: "fcc", Depth: 5})
	require.NoError(t, err)
	assertResourceSetsEqual(t, depth5.Resources, first.Resources)
}

func assertNoDuplicateResources(t *testing.T, resources []manifest.Resource) {
	t.Helper()
	seen := make(map[string]struct{})
	for _, r := range resources {
		key := strings.Join([]string{r.Type, r.Realm, r.Identifier()}, "|")
		if _, ok := seen[key]; ok {
			t.Errorf("duplicate resource: %s", key)
			continue
		}
		seen[key] = struct{}{}
	}
}

func assertResourceSetsEqual(t *testing.T, a, b []manifest.Resource) {
	t.Helper()
	require.Len(t, b, len(a))
	keysA := resourceKeys(a)
	keysB := resourceKeys(b)
	assert.ElementsMatch(t, keysA, keysB)
}

func resourceKeys(resources []manifest.Resource) []string {
	keys := make([]string, len(resources))
	for i, r := range resources {
		keys[i] = strings.Join([]string{r.Type, r.Realm, r.Identifier()}, "|")
	}
	return keys
}

func resourceTypes(resources []manifest.Resource) []string {
	types := make([]string, len(resources))
	for i, r := range resources {
		types[i] = r.Type
	}
	return types
}

func TestFetchExactMatchEmitsExactQueryParam(t *testing.T) {
	tests := []struct {
		name       string
		exactMatch bool
		wantExact  string
	}{
		{name: "exact match on", exactMatch: true, wantExact: "true"},
		{name: "exact match off", exactMatch: false, wantExact: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedQuery string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/admin/realms":
					writeJSON(t, w, []map[string]interface{}{{"realm": "demo"}})
				case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/demo/users":
					capturedQuery = r.URL.RawQuery
					writeJSON(t, w, []map[string]interface{}{{"id": "user-1", "username": "alice"}})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			service := newServiceForTest(t, server.URL)
			_, err := service.Fetch(context.Background(), admin.FetchQuery{
				Resources:  "user",
				Search:     "alice",
				ExactMatch: tc.exactMatch,
			})
			require.NoError(t, err)

			require.NotEmpty(t, capturedQuery, "expected a request to the user collection")
			assert.Contains(t, capturedQuery, "search=alice")
			if tc.wantExact != "" {
				assert.Contains(t, capturedQuery, "exact="+tc.wantExact)
			} else {
				assert.NotContains(t, capturedQuery, "exact=")
			}
		})
	}
}
