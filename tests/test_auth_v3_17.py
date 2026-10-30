"""Authorization coverage for released MLflow 3.17 gateway endpoints."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from mlflow.exceptions import MlflowException
from mlflow.utils.workspace_utils import WORKSPACE_HEADER_NAME
from mlflow_kubernetes_plugins.auth._compat import HAS_MLFLOW_3_17_AUTH_SURFACE
from mlflow_kubernetes_plugins.auth.authorizer import (
    AuthorizationMode,
    KubernetesAuthConfig,
    KubernetesAuthorizer,
)
from mlflow_kubernetes_plugins.auth.compiler import (
    _compile_authorization_rules,
    _reset_compiled_rules,
    _validate_fastapi_route_authorization,
)
from mlflow_kubernetes_plugins.auth.constants import RESOURCE_GATEWAY_ENDPOINTS
from mlflow_kubernetes_plugins.auth.middleware import KubernetesAuthMiddleware
from mlflow_kubernetes_plugins.auth.request_context import AuthorizationRequest

from conftest import _authorize_request

pytestmark = pytest.mark.skipif(
    not HAS_MLFLOW_3_17_AUTH_SURFACE, reason="MLflow 3.17 gateway routes are not installed."
)


@pytest.fixture
def compile_live_rules():
    _reset_compiled_rules()
    _compile_authorization_rules()
    yield
    _reset_compiled_rules()


@pytest.mark.parametrize("mode", list(AuthorizationMode))
@pytest.mark.parametrize(
    ("grant", "allowed"),
    [
        (("list", None), True),
        (("get", None), False),
        (("get", "endpoint-a"), False),
        (("list", "endpoint-a"), False),
        (None, False),
    ],
)
def test_gateway_model_discovery_requires_broad_list(
    monkeypatch, compile_live_rules, mode, grant, allowed
):
    from mlflow.server import gateway_api

    store = Mock()
    store.list_gateway_endpoints.return_value = [
        SimpleNamespace(name="endpoint-a", created_at=1000),
        SimpleNamespace(name="endpoint-b", created_at=2000),
    ]
    monkeypatch.setattr(gateway_api, "_get_store", lambda: store)
    monkeypatch.setattr(gateway_api, "_validate_store", lambda store: None)
    app = FastAPI()
    app.include_router(gateway_api.gateway_router)
    _validate_fastapi_route_authorization(app)
    authorizer = Mock(spec=KubernetesAuthorizer)

    def is_allowed(identity, resource, verb, namespace, subresource=None, resource_name=None):
        return (
            namespace == "team-a"
            and resource == RESOURCE_GATEWAY_ENDPOINTS
            and (verb, resource_name) == grant
        )

    authorizer.is_allowed.side_effect = is_allowed
    app.add_middleware(
        KubernetesAuthMiddleware,
        authorizer=authorizer,
        config_values=KubernetesAuthConfig(authorization_mode=mode),
    )
    monkeypatch.setattr(
        "mlflow_kubernetes_plugins.auth.middleware.resolve_workspace_from_header",
        lambda name: SimpleNamespace(name=name),
    )
    headers = {
        "Authorization": "Bearer discovery-token",
        "x-remote-user": "alice",
        WORKSPACE_HEADER_NAME: "team-a",
    }
    with TestClient(app) as client:
        response = client.get("/gateway/mlflow/v1/models", headers=headers)
        assert response.status_code == (200 if allowed else 403)
        if allowed:
            assert [model["id"] for model in response.json()["data"]] == [
                "endpoint-a",
                "endpoint-b",
            ]
            store.list_gateway_endpoints.assert_called_once_with()
        else:
            assert response.json()["error"]["code"] == "PERMISSION_DENIED"
            store.list_gateway_endpoints.assert_not_called()
        authorizer.is_allowed.assert_called_once()
        assert authorizer.is_allowed.call_args.args[1:] == (
            RESOURCE_GATEWAY_ENDPOINTS,
            "list",
            "team-a",
            None,
        )
        assert not authorizer.is_allowed.call_args.kwargs
        store.reset_mock()
        response = client.get(
            "/gateway/mlflow/v1/models",
            headers={**headers, WORKSPACE_HEADER_NAME: "team-b"},
        )
        assert response.status_code == 403
        store.list_gateway_endpoints.assert_not_called()


@pytest.mark.parametrize("mode", list(AuthorizationMode))
@pytest.mark.parametrize(
    ("verb", "subresource", "name", "allowed"),
    [
        ("create", "use", None, True),
        ("create", "use", "endpoint-a", True),
        ("create", "use", "endpoint-b", False),
        ("get", None, "endpoint-a", False),
        ("list", None, None, False),
        ("create", None, None, False),
    ],
)
def test_typesafe_invocation_requires_endpoint_use(
    compile_live_rules, mode, verb, subresource, name, allowed
):
    authorizer = Mock(spec=KubernetesAuthorizer)
    authorizer.is_allowed.side_effect = (
        lambda identity, resource, checked_verb, namespace, checked_subresource=None, resource_name=None: (
            resource == RESOURCE_GATEWAY_ENDPOINTS
            and namespace == "team-a"
            and (checked_verb, checked_subresource, resource_name) == (verb, subresource, name)
        )
    )
    request = AuthorizationRequest(
        authorization_header="Bearer invocation-token",
        forwarded_access_token=None,
        remote_user_header_value="alice",
        remote_groups_header_value=None,
        path="/gateway/typesafe/v1/systemone",
        method="POST",
        workspace="team-a",
        json_body={"model": "endpoint-a", "state": "Review", "questions": {}},
    )
    if allowed:
        result = _authorize_request(
            request,
            authorizer=authorizer,
            config_values=KubernetesAuthConfig(authorization_mode=mode),
        )
        assert result.response_filter_required is False
    else:
        with pytest.raises(MlflowException) as error:
            _authorize_request(
                request,
                authorizer=authorizer,
                config_values=KubernetesAuthConfig(authorization_mode=mode),
            )
        assert error.value.error_code == "PERMISSION_DENIED"
