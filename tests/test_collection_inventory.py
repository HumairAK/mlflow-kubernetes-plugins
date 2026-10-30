"""Verify the audit inventory against installed MLflow route registrations."""

import runpy
from pathlib import Path

from mlflow_kubernetes_plugins.auth._compat import HAS_MCP_REGISTRY
from mlflow_kubernetes_plugins.auth.compiler import _reset_compiled_rules


def test_inventory_includes_native_and_parent_scoped_collections(monkeypatch):
    script = Path(__file__).resolve().parents[1] / "hack/inventory_collection_authorization.py"
    snapshot = runpy.run_path(str(script))["snapshot"]
    # Source archives have no Git checkout; revision metadata is unrelated to route coverage.
    monkeypatch.setattr("subprocess.check_output", lambda *args, **kwargs: "test-baseline\n")
    try:
        inventory = snapshot()
    finally:
        _reset_compiled_rules()
    entries = inventory["entries"]
    for alias in ("/api/", "/ajax-api/"):
        metric = next(
            entry
            for entry in entries
            if entry["path"] == alias + "2.0/mlflow/metrics/get-history"
            and entry["method"] == "GET"
        )
        assert metric["rules"][0]["classification"] == "existing_parent_or_name_scoped"
        assert metric["rules"][0]["verb"] == "get"
        latest = next(
            entry
            for entry in entries
            if entry["path"] == alias + "2.0/mlflow/registered-models/get-latest-versions"
            and entry["method"] == "GET"
        )
        assert latest["rules"][0]["verb"] == "list"
        assert latest["rules"][0]["policy"] is None
        if HAS_MCP_REGISTRY:
            mcp = next(
                entry
                for entry in entries
                if entry["path"] == alias + "3.0/mlflow/mcp-servers" and entry["method"] == "GET"
            )
            assert mcp["framework"] == "fastapi"
            assert mcp["rules"][0]["policy"] == "response_filter_mcp_servers"
