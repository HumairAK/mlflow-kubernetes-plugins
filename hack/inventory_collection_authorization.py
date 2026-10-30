"""Snapshot live release-v1 collection authorization, or merge version snapshots.

Run under each supported MLflow version; see docs/authorization-collections-v1.md.
This is an audit tool, never a runtime authorization fallback.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def snapshot() -> dict:
    import mlflow
    from mlflow.server import app
    from mlflow.server.fastapi_app import create_fastapi_app
    from mlflow.server.graphql.graphql_schema_extensions import schema
    from mlflow.server.handlers import get_endpoints
    from mlflow_kubernetes_plugins.auth import compiler, graphql
    from mlflow_kubernetes_plugins.auth.core import (
        _canonicalize_path,
        _fastapi_path_to_template,
        _is_unprotected_path,
    )
    from mlflow_kubernetes_plugins.auth.rules import PATH_AUTHORIZATION_RULES, _normalize_rules

    compiler._reset_compiled_rules()
    compiler._compile_authorization_rules()
    fastapi_app = create_fastapi_app(app)
    compiler._validate_fastapi_route_authorization(fastapi_app)
    graphql.validate_graphql_field_authorization()

    routes = {}
    for path, request_class, methods in get_endpoints(lambda request_class: request_class):
        for method in methods:
            routes[(_canonicalize_path(path), method)] = ("flask", request_class.__name__)
    for route in app.url_map.iter_rules():
        for method in (route.methods or set()) - {"HEAD", "OPTIONS"}:
            routes.setdefault((_canonicalize_path(route.rule), method), ("flask", None))
    for path, method in compiler._iter_fastapi_route_methods(fastapi_app):
        routes[(_fastapi_path_to_template(_canonicalize_path(path)), method)] = (
            "fastapi",
            None,
        )

    entries = []
    for (path, method), (framework, request_class) in sorted(routes.items()):
        if _is_unprotected_path(path) or path.endswith("/graphql"):
            continue
        explicit = PATH_AUTHORIZATION_RULES.get((path, method))
        rules = (
            _normalize_rules(explicit)
            if explicit is not None
            else compiler._find_authorization_rules(path, method)
        )
        if not rules:
            raise RuntimeError(f"No explicit rules for {method} {path}")
        # Include protobuf collections, policies, broad list rules, explicit denials, and
        # custom GET collections whose handler has no protobuf request class.
        collection = (
            (request_class or "").startswith(("Search", "List", "BatchGet", "Query", "Calculate"))
            or request_class in {"GetMetricHistory", "GetMetricHistoryBulkInterval"}
            or any(
                r.collection_policy or r.verb == "list" or r.apply_workspace_filter or r.deny
                for r in rules
            )
            or (
                method == "GET"
                and path.rsplit("/", 1)[-1]
                in {
                    "files",
                    "models",
                    "providers",
                    "sessions",
                    "versions",
                    "endpoints",
                    "online-configs",
                }
            )
        )
        if not collection:
            continue
        entries.append(
            {
                "path": path,
                "method": method,
                "framework": framework,
                "request_class": request_class,
                "rules": [describe_rule(rule) for rule in rules],
            }
        )

    # GraphQL is query-driven: record actual collection fields, not operationName aliases.
    for field in sorted(schema.graphql_schema.query_type.fields):
        if not any(token in field for token in ("Search", "List", "HistoryBulk")):
            continue
        entries.append(
            {
                "path": "/graphql",
                "method": "GET/POST",
                "framework": "graphql",
                "field": field,
                "rules": [
                    {
                        "resource": graphql.GRAPHQL_FIELD_RESOURCE_MAP[field],
                        "verb": graphql.GRAPHQL_FIELD_VERB_MAP[field],
                        "name_parsers": list(
                            graphql.GRAPHQL_FIELD_RESOURCE_NAME_PARSERS.get(field, ())
                        ),
                        "policy": graphql.GRAPHQL_FIELD_AUTH_POLICY_MAP[field],
                        "classification": "existing_query_driven",
                    }
                ],
            }
        )
    if any(
        "modelVersions" in getattr(type_, "fields", {})
        for type_ in schema.graphql_schema.type_map.values()
    ):
        entries.append(
            {
                "path": "/graphql",
                "method": "GET/POST",
                "framework": "graphql",
                "field": "modelVersions",
                "condition": "Nested outside the mlflowSearchModelVersions response-filter path",
                "rules": [
                    {
                        "resource": "registeredmodels",
                        "verb": "get",
                        "name_parsers": [],
                        "policy": "broad_only",
                        "classification": "existing_query_driven",
                    }
                ],
            }
        )
    return {
        "baseline_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
        ).strip(),
        "mlflow_version": mlflow.__version__,
        "entries": entries,
    }


def describe_rule(rule) -> dict:
    if rule.deny:
        classification = "explicitly_denied"
    elif rule.fallback_to_collection_policy_on_missing_resource_reference:
        classification = "existing_hybrid_filtered"
    elif rule.collection_policy and rule.collection_policy != "broad_only":
        classification = "existing_filtered"
    elif rule.resource_name_parsers:
        classification = "existing_parent_or_name_scoped"
    elif rule.apply_workspace_filter:
        classification = "existing_workspace_filter"
    elif rule.verb == "list":
        classification = "existing_broad_only"
    else:
        classification = "existing_workspace_scoped"
    return {
        "resource": rule.resource,
        "verb": rule.verb,
        "subresource": rule.subresource,
        "name_parsers": list(rule.resource_name_parsers),
        "policy": rule.collection_policy,
        "classification": classification,
        "filter_on_missing_reference": rule.fallback_to_collection_policy_on_missing_resource_reference,
        "allow_if_reference_missing": rule.allow_if_resource_reference_missing,
        "requires_workspace": rule.requires_workspace,
        "deny_message": rule.deny_message,
    }


def merge(paths: list[Path]) -> dict:
    snapshots = [json.loads(path.read_text()) for path in paths]
    revisions = {item["baseline_revision"] for item in snapshots}
    if len(revisions) != 1:
        raise ValueError("Snapshots must describe the same baseline revision")
    entries = {}
    for item in snapshots:
        for entry in item["entries"]:
            key = json.dumps(entry, sort_keys=True)
            entries.setdefault(key, set()).add(item["mlflow_version"])
    return {
        "baseline_revision": revisions.pop(),
        "mlflow_versions": sorted(item["mlflow_version"] for item in snapshots),
        "entries": [
            dict(json.loads(key), mlflow_versions=sorted(versions))
            for key, versions in sorted(entries.items())
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--merge", type=Path, nargs="+")
    args = parser.parse_args()
    result = merge(args.merge) if args.merge else snapshot()
    # One complete endpoint per line keeps aliases and policy differences auditable in diffs.
    entries = result.pop("entries")
    header = json.dumps(result, indent=2)
    args.output.write_text(
        header[:-2]
        + ',\n  "entries": [\n'
        + ",\n".join("    " + json.dumps(entry, sort_keys=True) for entry in entries)
        + "\n  ]\n}\n"
    )


if __name__ == "__main__":
    main()
