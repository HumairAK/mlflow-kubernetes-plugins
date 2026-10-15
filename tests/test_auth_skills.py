"""Skill identity and authorization boundaries."""

from dataclasses import replace
from unittest.mock import Mock

import pytest
from mlflow.exceptions import MlflowException
from mlflow_kubernetes_plugins.auth._compat import HAS_SKILL_REGISTRY
from mlflow_kubernetes_plugins.auth.authorizer import AuthorizationMode, KubernetesAuthConfig
from mlflow_kubernetes_plugins.auth.compiler import _find_authorization_rules
from mlflow_kubernetes_plugins.auth.request_context import AuthorizationRequest
from mlflow_kubernetes_plugins.auth.resource_names import (
    RESOURCE_NAME_PARSER_SKILL_NAME,
    resolve_resource_names,
)
from mlflow_kubernetes_plugins.auth.rules import PATH_AUTHORIZATION_RULES

from conftest import _authorize_request


def _request(**kwargs):
    return replace(
        AuthorizationRequest(
            authorization_header=None,
            forwarded_access_token=None,
            remote_user_header_value="alice",
            remote_groups_header_value=None,
            path="/api/3.0/mlflow/skills/@team/hidden",
            method="GET",
            workspace="team-a",
            path_params={"name": "hidden", "organization": "team"},
        ),
        **kwargs,
    )


@pytest.mark.parametrize("organization, expected", [("", "hidden"), ("team", "@team/hidden")])
def test_skill_identity_ignores_body_and_query(organization, expected):
    context = _request(
        path_params={"name": "hidden", "organization": organization},
        query_params={"name": "visible", "organization": "other", "path": "skills/visible"},
        json_body={"name": "visible", "organization": "other"},
    )
    assert resolve_resource_names(context, [RESOURCE_NAME_PARSER_SKILL_NAME]) == (expected,)


def test_skill_routes_are_absent_without_upstream_capability():
    if HAS_SKILL_REGISTRY:
        pytest.skip("Installed MLflow exposes the skill registry.")
    assert not any("/mlflow/skills" in path for path, _ in PATH_AUTHORIZATION_RULES)


@pytest.fixture
def skill_auth(compile_auth_rules):
    if not HAS_SKILL_REGISTRY:
        pytest.skip("Installed MLflow does not expose the skill registry.")
    from mlflow.protos.mlflow_artifacts_pb2 import ListArtifacts

    compile_auth_rules(
        [
            ("/api/2.0/mlflow-artifacts/artifacts", ListArtifacts, ["GET"]),
        ]
    )
    config = Mock(spec=KubernetesAuthConfig)
    config.authorization_mode = AuthorizationMode.SUBJECT_ACCESS_REVIEW
    config.groups_separator = "|"
    config.workspaces_enabled = True
    authorizer = Mock()
    return authorizer, config


def _authorize(context, skill_auth):
    authorizer, config = skill_auth
    return _authorize_request(context, authorizer=authorizer, config_values=config)


@pytest.mark.parametrize("prefix", ["/api/3.0", "/ajax-api/3.0"])
def test_skill_search_requires_broad_list_permission(skill_auth, prefix):
    authorizer, _ = skill_auth
    context = _request(path=f"{prefix}/mlflow/skills", path_params={})
    # Broad get and named get/list grants must not authorize collection search.
    authorizer.is_allowed.side_effect = lambda *args, **kwargs: (
        args[1] == "skills" and (args[2] == "get" or kwargs.get("resource_name") is not None)
    )
    with pytest.raises(MlflowException) as exc:
        _authorize(context, skill_auth)
    assert exc.value.get_http_status_code() == 403
    authorizer.is_allowed.assert_called_once()
    assert authorizer.is_allowed.call_args.args[1:] == ("skills", "list", "team-a", None)

    authorizer.is_allowed.side_effect = lambda *args, **kwargs: (
        args[1:3] == ("skills", "list") and kwargs.get("resource_name") is None
    )
    result = _authorize(context, skill_auth)
    assert not result.response_filter_required
    assert all(rule.collection_policy is None for rule in result.rules)


@pytest.mark.parametrize("prefix", ["/api/3.0", "/ajax-api/3.0"])
def test_skill_nested_routes_and_named_permissions(skill_auth, prefix):
    authorizer, _ = skill_auth
    authorizer.is_allowed.side_effect = lambda *args, **kwargs: (
        args[1:3] == ("skills", "get") and kwargs.get("resource_name") == "@team/visible"
    )
    for suffix in ("", "/versions", "/versions/1", "/aliases/latest"):
        context = _request(
            path=f"{prefix}/mlflow/skills/@team/visible{suffix}",
            path_params={
                "organization": "team",
                "name": "visible",
                "version": "1",
                "alias": "latest",
            },
        )
        result = _authorize(context, skill_auth)
        assert result.rules[0].resource == "skills"
        with pytest.raises(MlflowException, match="Permission denied"):
            _authorize(
                replace(context, path_params={"organization": "other", "name": "visible"}),
                skill_auth,
            )


@pytest.mark.parametrize("suffix", ["/visible/versions", "/bulk-register"])
def test_skill_registration_requires_create_and_update(skill_auth, suffix):
    authorizer, _ = skill_auth
    context = _request(
        path=f"/api/3.0/mlflow/skills{suffix}",
        method="POST",
        path_params={"name": "visible"},
    )
    for granted in ({"create"}, {"update"}, set()):
        authorizer.is_allowed.side_effect = lambda *args, **kwargs: args[2] in granted
        with pytest.raises(MlflowException, match="Permission denied"):
            _authorize(context, skill_auth)
    authorizer.is_allowed.return_value = True
    authorizer.is_allowed.side_effect = None
    assert {rule.verb for rule in _authorize(context, skill_auth).rules} == {"create", "update"}


@pytest.mark.parametrize("listing", [False, True])
@pytest.mark.parametrize(
    "artifact_path",
    [
        "skills/visible/token/SKILL.md",
        "skills/@team/visible/token/SKILL.md",
        "skills/%40team/visible/token/SKILL.md",
    ],
)
def test_skill_artifacts_require_skill_access_even_with_broad_experiment_access(
    skill_auth, listing, artifact_path
):
    authorizer, _ = skill_auth
    authorizer.is_allowed.side_effect = lambda *args, **kwargs: args[1] == "experiments"
    context = _request(
        path="/api/2.0/mlflow-artifacts/artifacts" + ("" if listing else f"/{artifact_path}"),
        path_params={} if listing else {"artifact_path": artifact_path},
        query_params={"path": artifact_path} if listing else {},
    )
    with pytest.raises(MlflowException, match="Permission denied"):
        _authorize(context, skill_auth)
    expected = "@team/visible" if "team" in artifact_path else "visible"
    authorizer.is_allowed.side_effect = lambda *args, **kwargs: (
        args[1] == "skills" and kwargs.get("resource_name") == expected
    )
    assert _authorize(context, skill_auth).rules[0].resource == "skills"


@pytest.mark.parametrize(
    "artifact_path",
    [
        "skills",
        "skills/@team",
        "skills/@team/../hidden/token/file",
        "skills//visible/token/file",
        "other/../skills/hidden/token/file",
        "skills/%252e%252e/1/file",
        "workspaces/other/skills/hidden/file",
    ],
)
def test_malformed_skill_artifacts_are_denied_with_broad_permissions(skill_auth, artifact_path):
    authorizer, _ = skill_auth
    authorizer.is_allowed.return_value = True
    context = _request(
        path="/api/2.0/mlflow-artifacts/artifacts",
        path_params={},
        query_params={"path": artifact_path},
    )
    with pytest.raises(MlflowException, match="Skill artifacts"):
        _authorize(context, skill_auth)
    authorizer.is_allowed.assert_not_called()


def test_skill_artifact_direct_writes_are_denied(skill_auth):
    authorizer, _ = skill_auth
    authorizer.is_allowed.return_value = True
    context = _request(
        path="/api/2.0/mlflow-artifacts/artifacts/skills/visible/token/file",
        method="PUT",
        path_params={"artifact_path": "skills/visible/token/file"},
    )
    with pytest.raises(MlflowException, match="read-only"):
        _authorize(context, skill_auth)


def test_experiment_artifacts_keep_existing_authorization(skill_auth):
    authorizer, _ = skill_auth
    authorizer.is_allowed.side_effect = lambda *args, **kwargs: args[1] == "experiments"
    context = _request(
        path="/api/2.0/mlflow-artifacts/artifacts/1/run/artifacts/file",
        path_params={"artifact_path": "1/run/artifacts/file"},
    )
    assert _authorize(context, skill_auth).rules[0].resource == "experiments"
    assert (
        _find_authorization_rules("/api/3.0/mlflow/skills/bulk-register", "POST")[0].verb
        == "create"
    )


def test_repeated_artifact_query_paths_cannot_bypass_skill_permissions(skill_auth):
    authorizer, _ = skill_auth
    authorizer.is_allowed.return_value = True
    context = _request(
        path="/api/2.0/mlflow-artifacts/artifacts",
        path_params={},
        query_params={"path": ["skills/hidden/token/file", "1/run/artifacts/file"]},
    )
    with pytest.raises(MlflowException, match="Invalid artifact path"):
        _authorize(context, skill_auth)
    authorizer.is_allowed.assert_not_called()
