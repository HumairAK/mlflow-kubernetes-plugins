"""MLflow 3.17 authorization deltas layered on top of the earlier tables."""

from __future__ import annotations

from mlflow_kubernetes_plugins.auth.collection_filters import COLLECTION_POLICY_BROAD_ONLY
from mlflow_kubernetes_plugins.auth.resource_names import (
    RESOURCE_NAME_PARSER_GATEWAY_PROXY_ENDPOINT_NAME,
)
from mlflow_kubernetes_plugins.auth.rules import (
    AuthorizationRule,
    _gateway_endpoints_rule,
    _gateway_endpoints_use_rule,
)


def apply_v3_17_deltas(
    *,
    path_authorization_rules: dict[
        tuple[str, str], AuthorizationRule | tuple[AuthorizationRule, ...]
    ],
) -> None:
    path_authorization_rules.update(
        {
            # This lists gateway endpoint names, matching ListGatewayEndpoints permissions.
            ("/gateway/mlflow/v1/models", "GET"): _gateway_endpoints_rule(
                "list", collection_policy=COLLECTION_POLICY_BROAD_ONLY
            ),
            ("/gateway/typesafe/v1/systemone", "POST"): _gateway_endpoints_use_rule(
                resource_name_parsers=(RESOURCE_NAME_PARSER_GATEWAY_PROXY_ENDPOINT_NAME,),
            ),
        }
    )
