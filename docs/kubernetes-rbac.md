# Kubernetes RBAC

Both plugins talk to the Kubernetes API, but they need different permissions depending on whether they are acting as the MLflow server or as the authenticated caller.

## MLflow Server Permissions

The workspace provider needs to list and watch namespaces. If you use the optional `MLflowConfig` CRD for artifact overrides, the server also needs access to that CRD and to list/watch the shared `mlflow-artifact-connection` secret across namespaces.

The provider watches only that secret name by using a `metadata.name=mlflow-artifact-connection` field selector. On Kubernetes 1.27+ the apiserver passes that field selector through authorization, so the RBAC rule can stay scoped with `resourceNames: ["mlflow-artifact-connection"]`.

Reusable example:

- [`examples/mlflow-server-rbac.yaml`](../examples/mlflow-server-rbac.yaml)

## Caller Permissions

The authorization plugin checks access against resources in the `mlflow.kubeflow.org` API group.

| Resource | Common verbs |
| --- | --- |
| `assistants` | `get`, `create`, `update` |
| `datasets` | `get`, `list`, `create`, `update`, `delete` |
| `experiments` | `get`, `list`, `create`, `update`, `delete` |
| `mcpservers` | `get`, `list`, `create`, `update`, `delete` |
| `registeredmodels` | `get`, `list`, `create`, `update`, `delete` |
| `gatewaysecrets` | `get`, `list`, `create`, `update`, `delete` |
| `gatewaysecrets/use` | `create` |
| `gatewayendpoints` | `get`, `list`, `create`, `update`, `delete` |
| `gatewayendpoints/use` | `create` |
| `gatewayguardrails` | `get`, `list`, `create`, `update`, `delete` |
| `gatewaybudgets` | `get`, `list`, `create`, `update`, `delete` |
| `gatewaymodeldefinitions` | `get`, `list`, `create`, `update`, `delete` |
| `gatewaymodeldefinitions/use` | `create` |

Reusable example:

- [`examples/team-a-workspace.yaml`](../examples/team-a-workspace.yaml)

## Fine-Grained Resource Names

Caller RBAC can also use Kubernetes `resourceNames` for fine-grained MLflow access.

Important details:

- Kubernetes ignores `resourceNames` on `create` without subresource because the object does not yet exist. The plugin mirrors this: name-scoped RBAC applies to `get`, `update`, `delete`, `list`, and subresource verbs like `create` on `<resource>/use`, but not bare `create`.
- Use the MLflow resource name, not the MLflow ID
- For `datasets`, the `resourceName` is the dataset name
- For `experiments`, the `resourceName` is the experiment name
- For `mcpservers`, the `resourceName` is the MCP server name
- For `registeredmodels`, the `resourceName` is the registered model name
- For `gatewaysecrets`, the `resourceName` is the gateway secret name
- For `gatewayendpoints`, the `resourceName` is the gateway endpoint name
- For `gatewaymodeldefinitions`, the `resourceName` is the gateway model definition name
- `gatewayguardrails` intentionally does not support `resourceNames`. MLflow guardrail names are
  not unique within a workspace, so name-scoped RBAC would be ambiguous and could accidentally
  authorize multiple guardrails that share the same display name.
- `gatewaybudgets` intentionally does not support `resourceNames`. MLflow exposes only opaque
  budget-policy IDs rather than a declarative unique name that can be pre-provisioned through
  GitOps-friendly RBAC, so budget authorization stays at the workspace level.
- `gatewaybudgets` also rejects `GLOBAL` target scope in this plugin. Budget policies must remain
  workspace-scoped to preserve workspace isolation.

This is most useful for single-object operations such as:

- reading a specific dataset, experiment, MCP server, registered model, or gateway resource
- creating or updating runs, traces, tags, scorers, and other experiment-scoped writes
- creating or updating model versions, webhooks, and many gateway resources by name
- reading artifacts or trace details that resolve back to one experiment

### Collection Permissions in v1

Existing collection policies remain supported on `release-v1`:

- experiment search responses are filtered by named `get` on `experiments`
- registered-model and model-version search responses are filtered by named `get` on
  `registeredmodels`, using the registered model name for both; `GetLatestVersions` instead
  requires broad or matching named `list` on `registeredmodels` and does not filter its response
- trace collection responses are filtered by named `get` on their owning `experiments`
- MCP server and access-endpoint (binding) collection responses are filtered by named `get` on
  `mcpservers`, using the server name
- scorer collections retain their experiment-based policy: a supplied experiment reference
  requires `get` on that experiment; supported unscoped collections filter by readable experiments
- configured run, logged-model, dataset, trace, and metric collection requests retain their
  request-side narrowing by explicit experiment IDs, run IDs, or trace locations
- GraphQL collections retain their explicit query-driven authorization and filtering

The [versioned endpoint inventory](authorization-collections-v1.md) records the exact mappings,
including hybrid scorer behavior and workspace-scoped exceptions.

These policies are endpoint-specific. Dataset-input search uses `datasets:list` with
experiment-based request narrowing. Evaluation-dataset search responses retain a dataset only
when the caller can read every associated experiment. The existing filter accepts plural
`experiment_ids`/`experimentIds` and legacy singular `experiment_id`/`experimentId` fields.
Datasets with missing, malformed, unresolved, or unreadable experiment associations are omitted.
Broad `datasets:list` continues to bypass response filtering.
Existing broad-only collections, including gateway listings and webhook listings, continue
to require broad `list` permission.

For **new resource types** added in v1 compatibility backports, workspace-wide searches and
listings require broad `list` on the resource in the resolved workspace namespace. The
authorization review has no `resourceName`, so the Role rule must omit `resourceNames`.
Named `get` or named `list` alone does not authorize a search, even when the request includes an
exact name predicate. Without broad `list`, the plugin returns `PERMISSION_DENIED` before
invoking the MLflow handler.

Direct reads remain separate: broad `get` permits reads, and a matching named `get` permits
reading that object when the resource supports stable name resolution. Broad `list` does not
grant `get`, and broad `get` does not grant `list`. Grants apply only within their namespace;
normal workspace isolation still applies to allowed collections.

For example, these rules allow gateway endpoint listings in `team-a` and direct reads of
`endpoint-a`. Direct reads of other endpoints require additional `get` permission:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mlflow-gateway-reader
  namespace: team-a
rules:
  - apiGroups: ["mlflow.kubeflow.org"]
    resources: ["gatewayendpoints"]
    verbs: ["list"]
  - apiGroups: ["mlflow.kubeflow.org"]
    resources: ["gatewayendpoints"]
    resourceNames: ["endpoint-a"]
    verbs: ["get"]
```

New v1 response filters are out of scope. Named-grant collection searches for new resources
are deferred to v2 request-side scoping, tracked in
[RHOAIENG-74916](https://redhat.atlassian.net/browse/RHOAIENG-74916).

Use the example manifest below as a starting point for both broad workspace access and name-scoped experiment access:

- [`examples/team-a-workspace.yaml`](../examples/team-a-workspace.yaml)

Example: allow an agent to send traces only to the `exp-a` experiment in the `team-a` workspace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mlflow-trace-agent
  namespace: team-a
rules:
  - apiGroups: ["mlflow.kubeflow.org"]
    resources: ["experiments"]
    resourceNames: ["exp-a"]
    verbs: ["update"]
```

## Trusted Proxy Mode

When `MLFLOW_K8S_AUTH_AUTHORIZATION_MODE=subject_access_review`, the MLflow server must also be allowed to create `subjectaccessreviews.authorization.k8s.io`.

That permission is included in:

- [`examples/mlflow-server-rbac.yaml`](../examples/mlflow-server-rbac.yaml)

## Token Creation

To create a service-account token for testing:

```bash
kubectl -n team-a create token mlflow-writer
kubectl -n team-a create token mlflow-experiments-reader
```

Then send the token with the workspace header:

```bash
curl \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-MLFLOW-WORKSPACE: team-a" \
  https://mlflow.example/api/2.0/mlflow/runs/search
```

Use plain HTTP only for local-only testing such as `localhost` or a `kubectl port-forward`.
