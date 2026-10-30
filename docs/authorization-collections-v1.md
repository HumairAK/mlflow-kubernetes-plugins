# release-v1 Collection Authorization Baseline

This delivery for [RHOAIENG-102178](https://redhat.atlassian.net/browse/RHOAIENG-102178)
enforces the v1 broad-list policy, preserves existing collection behavior, and adds regression
coverage. Broad-only rules must use `list`, an explicit resource, and no name parsers or
missing-reference fallbacks; invalid mappings fail at startup. A denied broad check returns
`PERMISSION_DENIED` before any named-grant or filtering fallback.
It also repairs startup route discovery for FastAPI releases that retain included routers,
so unmapped native endpoints cannot silently escape startup validation.
The v1 release line supports released MLflow `>=3.10.0,<3.18.0`. The dependency range
and both CI matrices include 3.17 alongside previously supported minors. No new response
filters or v2 request-side scoping are introduced. MLflow 3.18 and skills-registry support
are outside this delivery.

## MLflow 3.17 Compatibility

The explicit mappings in `rules_v3_17.py` cover:

- `GET /gateway/mlflow/v1/models`: broad `gatewayendpoints:list`, without a named-grant
  or response-filter fallback.
- `POST /gateway/typesafe/v1/systemone`: `create` on `gatewayendpoints/use`, with named
  authorization resolved from the request's `model` field.

The release-v1 base already includes the assistant tool-result rule, static-prefix handling
for gateway and OTLP trace routes, and the workspace provider's deletion `mode` parameter.
Namespace deletion remains unsupported. Unknown protected endpoints continue to fail startup
validation rather than acquiring a dynamic fallback.

## Endpoint Inventory

The [machine-readable inventory](authorization-collections-v1.json) records the preserved
baseline by endpoint, method, framework, protobuf request class where present, RBAC resource,
verb, subresource, name parser, and collection policy. Each entry lists the exact installed
MLflow versions in which it was observed. API and AJAX aliases remain separate entries.
Version lists describe observations across 3.10–3.16, not inferred introduction dates.

The inventory covers live registered Flask and FastAPI collection surfaces, GraphQL collection
fields, and explicit denial exceptions. It includes protobuf `Search`, `List`, `BatchGet`,
`Query`, and `Calculate` requests, any collection-policy or `list` rule, workspace filters,
and parent-scoped metric history, plus custom GET collections such as MCP versions/endpoints
and artifact files. The generator
validates all protected routes and GraphQL fields before selecting collection entries.
Non-collection mutations and direct object reads are outside this inventory, except explicit
denials. An unused legacy path-table entry is not presented as a registered endpoint.

Classifications retain the existing policy:

- `existing_filtered`: explicit request or response filtering; the resource, parser, and policy
  columns determine which ownership checks apply.
- `existing_hybrid_filtered`: named-parent authorization with filtering only when the reference
  is missing. In particular, `ListScorers` remains distinct from generic filtered collections.
- `existing_parent_or_name_scoped`: collection access resolves a named resource or parent.
- `existing_broad_only`: an unnamed `list` check, with no named or filtering fallback. Some
  existing rules enforce this without the explicit `broad_only` marker.
- `existing_workspace_scoped`: an existing workspace-level check, commonly `get`; this is not
  reclassified to `list` by the new-resource policy.
- `existing_workspace_filter`: the caller's accessible namespace list filters workspace results.
- `existing_query_driven`: GraphQL field policies; authorization still depends on the complete
  query, aliases, inputs, and nested fields, rather than `operationName`.
- `explicitly_denied`: the recorded denial and message remain in effect.

GraphQL request-filter fields require suitable experiment IDs in every relevant occurrence;
unscoped or mixed queries can still require broad permission. Nested `modelVersions` outside
the root model-version response-filter path adds a broad `registeredmodels:get` check. The
inventory records this condition separately rather than suggesting that all nested reads filter.

This JSON is the preserved 3.10–3.16 baseline, not a snapshot of the new 3.17 surface.
The new gateway discovery mapping is documented above and tested against released 3.17;
TypeSafe invocation is not a collection. Actual protected-route startup validation covers
the full installed target. The inventory generator remains an audit tool and never supplies
runtime authorization rules.

## Reproducing the Inventory

From the repository root, capture each baseline MLflow minor in an isolated environment and
merge the snapshots. Use the exact patch versions in the JSON metadata for an exact replay.

```bash
inventory_dir=$(mktemp -d)
for version in 3.10 3.11 3.12 3.13 3.14 3.15 3.16; do
  uv run --isolated --no-project --with-editable '.[dev]' --with "mlflow~=${version}.0" \
    python hack/inventory_collection_authorization.py \
    --output "${inventory_dir}/${version}.json"
done
uv run python hack/inventory_collection_authorization.py \
  --merge "${inventory_dir}/"*.json --output docs/authorization-collections-v1.json
```

The revision in the output identifies the rule-table baseline. Rule changes in a compatibility
backport require a fresh inventory and review of the resulting differences.

## Regression Evidence

The gateway contract test uses the installed MLflow endpoint registrations and real rules for
broad-list and named-get behavior. Its listing requests use supported gateway fields. It covers
broad list, named get, combined grants, broad get, named list, no grants, namespace isolation,
and missing names through native FastAPI and mounted Flask in both SSAR and SAR modes.

The separate `test_broad_only_search_contract_with_exact_name_filter` fixture deliberately
supports an exact name in GET query parameters and POST JSON. It checks the authorization
engine through both FastAPI and mounted Flask, in SSAR and SAR modes. Broad `list` reaches the
handler and returns its requested subset; named `get`, named `list`, and no grants are denied
before the handler. It also fails if the engine calls the request-filter fallback. Any new
resource backport must additionally exercise that resource's actual filter syntax and handlers.

`test_compile_rejects_broad_only_collection_fallbacks` checks both protobuf and path rule tables:
wrong or missing verbs, missing resources, name parsers, and missing-reference fallbacks fail
startup with `INTERNAL_ERROR`. Existing valid broad-only and filtered rules continue to compile.

`test_create_app_validates_current_mlflow_startup_rules` bypasses the test fixture's mocked
Flask iterator and validates the real Flask map, protobuf registrations, FastAPI routes, and
GraphQL schema. Its negative case adds an uncovered custom Flask collection to a copied live
map and verifies that startup fails. A second negative case injects an included native FastAPI
router into the actual MLflow app. Additional regressions cover nested router prefixes,
static-prefix normalization, and missing method rules. Validation and inventory generation
share route discovery, using effective route contexts on newer FastAPI and flattened routes
on older releases. Existing negative FastAPI and protobuf coverage tests remain in the suite.

Existing experiment, registered-model, model-version, trace, MCP, scorer, request-narrowing,
and query-driven GraphQL regressions remain covered by the full test suite. A follow-up repair
corrects the existing evaluation-dataset filter to read the actual plural `experiment_ids`
field while retaining legacy singular IDs, snake_case/camelCase fields, and numeric IDs.
Shared datasets require read permission on every associated experiment; missing, malformed,
unresolved, and unreadable associations fail closed. Real serialized
`SearchEvaluationDatasets.Response` tests and registered-handler HTTP regressions cover both
API aliases, GET/POST, authorization modes, pagination metadata, and the broad-list bypass.
The former expected-failure test now passes. This fixes an existing filter; it adds no new
collection policy or response filter.

The released 3.17 tests exercise gateway discovery with broad list, broad get, named get,
named list, and no grants, plus namespace isolation. TypeSafe tests cover broad and named
endpoint-use grants and reject unrelated permissions. Both authorization modes are covered.
The supported CI matrix covers Python 3.12–3.14 with its existing exclusion, and separate
static-prefix runs cover every supported MLflow minor.

Local validation of this scope on Python 3.12.10 passed the full suite with released MLflow
3.10.1 (493 passed), 3.16.1 (511 passed), and 3.17.2 (534 passed). Static-prefix runs also
passed on 3.16.1 and 3.17.2. Development dependency sync, lint, pre-commit, and source/wheel
builds passed. Type checking reports the same 22 diagnostics as the pre-change commit,
with no new diagnostics. Python 3.13/3.14 remain covered by the configured CI matrix;
those versions were not tested locally for this scope change.
