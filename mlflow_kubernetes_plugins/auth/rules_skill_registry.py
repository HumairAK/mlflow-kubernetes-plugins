"""Explicit authorization rules for the MLflow skill registry."""

from __future__ import annotations

import importlib
import posixpath

from mlflow.protos import mlflow_artifacts_pb2 as artifacts_pb2

from mlflow_kubernetes_plugins.auth.constants import RESOURCE_SKILLS
from mlflow_kubernetes_plugins.auth.request_context import AuthorizationRequest
from mlflow_kubernetes_plugins.auth.resource_names import (
    RESOURCE_NAME_PARSER_SKILL_ARTIFACT_NAME,
    RESOURCE_NAME_PARSER_SKILL_NAME,
    ResourceNameResolutionError,
    _get_skill_artifact_path,
)
from mlflow_kubernetes_plugins.auth.rules import AuthorizationRule


def _skills_rule(verb: str, **kwargs) -> AuthorizationRule:
    return AuthorizationRule(verb, resource=RESOURCE_SKILLS, **kwargs)


SKILL_REGISTRY_PATH_AUTHORIZATION_RULES = {
    ("/api/3.0/mlflow/skills", "POST"): _skills_rule("create"),
    # Require broad list access; response filtering is being phased out.
    ("/api/3.0/mlflow/skills", "GET"): _skills_rule("list"),
    ("/api/3.0/mlflow/skills/bulk-register", "POST"): _skills_rule("update"),
    # Like MCP, version registration uses parent update even if MLflow creates the parent.
    ("/api/3.0/mlflow/skills/@<organization>/<name>/versions", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/versions", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>", "PATCH"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>/tags", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    (
        "/api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>/tags/<path:key>",
        "DELETE",
    ): _skills_rule("update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/aliases", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/aliases/<alias>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/aliases/<alias>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/tags", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>/tags/<path:key>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>", "PATCH"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/@<organization>/<name>", "DELETE"): _skills_rule(
        "delete", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/versions", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/versions", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/versions/<version>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/versions/<version>", "PATCH"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/versions/<version>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/versions/<version>/tags", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/versions/<version>/tags/<path:key>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/aliases", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/aliases/<alias>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/aliases/<alias>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/tags", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>/tags/<path:key>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>", "PATCH"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/api/3.0/mlflow/skills/<name>", "DELETE"): _skills_rule(
        "delete", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills", "POST"): _skills_rule("create"),
    # Require broad list access; response filtering is being phased out.
    ("/ajax-api/3.0/mlflow/skills", "GET"): _skills_rule("list"),
    ("/ajax-api/3.0/mlflow/skills/bulk-register", "POST"): _skills_rule("update"),
    (
        "/ajax-api/3.0/mlflow/skills/@<organization>/<name>/versions",
        "POST",
    ): _skills_rule("update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>/versions", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    (
        "/ajax-api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>",
        "PATCH",
    ): _skills_rule("update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)),
    (
        "/ajax-api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>",
        "DELETE",
    ): _skills_rule("update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)),
    (
        "/ajax-api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>/tags",
        "POST",
    ): _skills_rule("update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)),
    (
        "/ajax-api/3.0/mlflow/skills/@<organization>/<name>/versions/<version>/tags/<path:key>",
        "DELETE",
    ): _skills_rule("update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>/aliases", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>/aliases/<alias>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>/aliases/<alias>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>/tags", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>/tags/<path:key>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>", "PATCH"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/@<organization>/<name>", "DELETE"): _skills_rule(
        "delete", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/versions", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/versions", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/versions/<version>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/versions/<version>", "PATCH"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/versions/<version>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/versions/<version>/tags", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    (
        "/ajax-api/3.0/mlflow/skills/<name>/versions/<version>/tags/<path:key>",
        "DELETE",
    ): _skills_rule("update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)),
    ("/ajax-api/3.0/mlflow/skills/<name>/aliases", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/aliases/<alias>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/aliases/<alias>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/tags", "POST"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>/tags/<path:key>", "DELETE"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>", "GET"): _skills_rule(
        "get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>", "PATCH"): _skills_rule(
        "update", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
    ("/ajax-api/3.0/mlflow/skills/<name>", "DELETE"): _skills_rule(
        "delete", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_NAME,)
    ),
}


def apply_skill_registry_deltas(request_rules: dict, path_rules: dict) -> None:
    path_rules.update(SKILL_REGISTRY_PATH_AUTHORIZATION_RULES)
    for request_class in (
        artifacts_pb2.DownloadArtifact,
        artifacts_pb2.ListArtifacts,
        artifacts_pb2.GetPresignedDownloadUrl,
        artifacts_pb2.UploadArtifact,
        artifacts_pb2.DeleteArtifact,
        artifacts_pb2.CreateMultipartUpload,
        artifacts_pb2.CompleteMultipartUpload,
        artifacts_pb2.AbortMultipartUpload,
    ):
        request_rules[request_class] = request_rules[request_class]._replace(
            check_skill_artifact_permissions=True
        )
    for key in (
        ("/api/2.0/mlflow-artifacts/artifacts/<path:artifact_path>", "GET"),
        ("/ajax-api/2.0/mlflow-artifacts/artifacts/<path:artifact_path>", "GET"),
        ("/api/2.0/mlflow-artifacts/artifacts/<path:artifact_path>", "PUT"),
        ("/ajax-api/2.0/mlflow-artifacts/artifacts/<path:artifact_path>", "PUT"),
    ):
        path_rules[key] = path_rules[key]._replace(check_skill_artifact_permissions=True)


def skill_artifact_rules(
    context: AuthorizationRequest, original_rules: list[AuthorizationRule]
) -> list[AuthorizationRule]:
    try:
        decoded = _get_skill_artifact_path(context)
    except ResourceNameResolutionError as exc:
        return [AuthorizationRule(None, deny=True, deny_message=f"Skill artifacts: {exc}")]
    if decoded is None:
        if context.method != "DELETE":
            return original_rules
        decoded = ""
    # MLflow normalizes proxy paths. Recognize both the supplied and resolved skill
    # namespace so traversal cannot acquire broader experiment permissions.
    candidates = (decoded, posixpath.normpath(decoded))
    paths = []
    for candidate in candidates:
        segments = candidate.strip("/").split("/")
        if segments[0].lower() == "workspaces" and len(segments) >= 2:
            if segments[1] != context.workspace:
                return [
                    AuthorizationRule(
                        None, deny=True, deny_message="Skill artifacts: invalid workspace."
                    )
                ]
            segments = segments[2:]
        paths.append("/".join(segments))
    # Recursive root deletes can remove skill uploads alongside experiment artifacts.
    if context.method == "DELETE" and any(path in {"", ".", "..", "workspaces"} for path in paths):
        return [
            AuthorizationRule(None, deny=True, deny_message="Artifact root deletion is denied.")
        ]
    if not any(path.split("/")[0].lower() == "skills" for path in paths):
        return original_rules
    artifact_paths = importlib.import_module("mlflow.store.tracking.skill_registry.artifact_paths")
    identity = artifact_paths.parse_skill_upload_path(decoded)
    if identity is None or decoded.startswith("/") or context.method != "GET":
        return [
            AuthorizationRule(
                None,
                deny=True,
                deny_message=(
                    "Skill artifacts require a valid skill path and are read-only; "
                    "register a new version to upload content."
                ),
            )
        ]
    # Resolve the validated artifact identity for name-scoped RBAC.
    return [_skills_rule("get", resource_name_parsers=(RESOURCE_NAME_PARSER_SKILL_ARTIFACT_NAME,))]
