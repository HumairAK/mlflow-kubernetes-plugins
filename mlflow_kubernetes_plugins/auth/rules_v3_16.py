"""MLflow 3.16 authorization deltas layered on top of the earlier tables."""

from __future__ import annotations

from mlflow_kubernetes_plugins.auth.rules import AuthorizationRule, _assistants_rule


def apply_v3_16_deltas(
    *,
    path_authorization_rules: dict[
        tuple[str, str], AuthorizationRule | tuple[AuthorizationRule, ...]
    ],
) -> None:
    path_authorization_rules.update(
        {
            (
                "/ajax-api/3.0/mlflow/assistant/sessions/<session_id>/tool-result",
                "POST",
            ): _assistants_rule("update"),
        }
    )
