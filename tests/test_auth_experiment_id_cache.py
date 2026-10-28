"""Reverse experiment lookups must preserve workspace and mutation boundaries."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from mlflow.exceptions import MlflowException
from mlflow.utils.workspace_context import ServerWorkspaceContext, get_request_workspace
from mlflow_kubernetes_plugins.auth import resource_names
from mlflow_kubernetes_plugins.auth.request_context import AuthorizationRequest
from mlflow_kubernetes_plugins.auth.rules import AuthorizationRule


@pytest.fixture
def experiments(monkeypatch):
    rows = {("team-a", "shared"): "1", ("team-b", "shared"): "2"}

    def lookup(name):
        experiment_id = rows.get((get_request_workspace(), name))
        return (
            SimpleNamespace(name=name, experiment_id=experiment_id)
            if experiment_id is not None
            else None
        )

    store = SimpleNamespace(get_experiment_by_name=Mock(side_effect=lookup))
    monkeypatch.setattr(resource_names, "_get_tracking_store", lambda: store)
    with ServerWorkspaceContext("team-a"):
        yield rows, store.get_experiment_by_name


def _apply_mutation(operation, *, prefix="/api", status_code=200, body_available=True):
    rename = operation == "rename"
    request = AuthorizationRequest(
        authorization_header=None,
        forwarded_access_token=None,
        remote_user_header_value=None,
        remote_groups_header_value=None,
        path=f"{prefix}/2.0/mlflow/experiments/{'update' if rename else 'delete'}",
        method="PATCH" if rename else "POST",
        workspace="team-a",
        json_body=(
            {"experiment_id": "1", **({"new_name": "renamed"} if rename else {})}
            if body_available
            else None
        ),
    )
    rules = [
        AuthorizationRule(
            "update" if rename else "delete",
            resource="experiments",
            resource_name_parsers=(
                resource_names.RESOURCE_NAME_PARSER_EXPERIMENT_ID_TO_NAME,
                resource_names.RESOURCE_NAME_PARSER_NEW_EXPERIMENT_NAME,
            )
            if rename
            else (resource_names.RESOURCE_NAME_PARSER_EXPERIMENT_ID_TO_NAME,),
        )
    ]
    resource_names.apply_response_cache_updates(request, rules, status_code=status_code)


def test_repeated_lookups_reuse_ids_without_crossing_workspaces(experiments):
    _, lookup = experiments
    assert resource_names.resolve_experiment_ids_from_names(("shared", "shared")) == ("1",)
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    with ServerWorkspaceContext("team-b"):
        assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("2",)
        assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("2",)
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    assert lookup.call_count == 2


def test_missing_experiment_is_not_cached(experiments):
    rows, lookup = experiments
    assert resource_names.resolve_experiment_ids_from_names(("created-later",)) == ()
    rows[("team-a", "created-later")] = "3"
    assert resource_names.resolve_experiment_ids_from_names(("created-later",)) == ("3",)
    assert lookup.call_count == 2


@pytest.mark.parametrize(
    "bad_result",
    [None, SimpleNamespace(name="other", experiment_id="1"), SimpleNamespace(name="shared")],
    ids=["store-error", "mismatched-name", "missing-id"],
)
def test_invalid_lookups_fail_closed_and_are_not_cached(monkeypatch, bad_result):
    lookup = Mock(
        side_effect=[
            MlflowException("Storage unavailable") if bad_result is None else bad_result,
            SimpleNamespace(name="shared", experiment_id="1"),
        ]
    )
    monkeypatch.setattr(
        resource_names,
        "_get_tracking_store",
        lambda: SimpleNamespace(get_experiment_by_name=lookup),
    )
    with pytest.raises(resource_names.ResourceNameResolutionError):
        resource_names.resolve_experiment_ids_from_names(("shared",))
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    assert lookup.call_count == 2


def test_external_rename_expires_without_extending_ttl_on_hits(monkeypatch, experiments):
    rows, lookup = experiments
    now = 1_000.0
    monkeypatch.setattr(resource_names.time, "time", lambda: now)
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    del rows[("team-a", "shared")]
    rows[("team-a", "renamed")] = "1"

    now += 59
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    now += 1
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ()
    assert resource_names.resolve_experiment_ids_from_names(("renamed",)) == ("1",)
    assert lookup.call_count == 3


def test_reverse_cache_bounds_entries_and_retains_recently_used_names(monkeypatch, experiments):
    rows, lookup = experiments
    rows.update({("team-a", "second"): "2", ("team-a", "third"): "3"})
    monkeypatch.setattr(
        resource_names,
        "_experiment_id_cache",
        resource_names._ExperimentIdLookupCache(ttl_seconds=60, max_entries=2),
    )
    assert resource_names.resolve_experiment_ids_from_names(("shared", "second")) == ("1", "2")
    assert resource_names.resolve_experiment_ids_from_names(("shared", "third")) == ("1", "3")
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    assert lookup.call_count == 3
    assert resource_names.resolve_experiment_ids_from_names(("second",)) == ("2",)
    assert lookup.call_count == 4


@pytest.mark.parametrize("operation", ["rename", "delete"])
@pytest.mark.parametrize("prefix", ["/api", "/ajax-api"])
def test_successful_mutations_invalidate_old_name_before_reuse(experiments, operation, prefix):
    rows, _ = experiments
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    del rows[("team-a", "shared")]
    if operation == "rename":
        rows[("team-a", "renamed")] = "1"

    # Response hooks may run after middleware has cleared the workspace context.
    with ServerWorkspaceContext(None):
        _apply_mutation(operation, prefix=prefix)
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ()
    if operation == "rename":
        assert resource_names.resolve_experiment_ids_from_names(("renamed",)) == ("1",)
    rows[("team-a", "shared")] = "3"
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("3",)


@pytest.mark.parametrize("operation", ["rename", "delete"])
def test_failed_mutations_keep_cached_mapping(experiments, operation):
    _, lookup = experiments
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    _apply_mutation(operation, status_code=403)
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    lookup.assert_called_once_with("shared")


@pytest.mark.parametrize("operation", ["rename", "delete"])
def test_mutations_without_body_still_invalidate_reverse_cache(experiments, operation):
    rows, _ = experiments
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ("1",)
    del rows[("team-a", "shared")]
    _apply_mutation(operation, body_available=False)
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ()


def test_lookup_started_before_delete_cannot_repopulate_cache(experiments):
    rows, lookup = experiments
    original_lookup = lookup.side_effect

    def delete_during_lookup(name):
        experiment = original_lookup(name)
        del rows[("team-a", "shared")]
        _apply_mutation("delete")
        return experiment

    lookup.side_effect = delete_during_lookup
    resource_names.resolve_experiment_ids_from_names(("shared",))
    lookup.side_effect = original_lookup
    assert resource_names.resolve_experiment_ids_from_names(("shared",)) == ()
    assert lookup.call_count == 2
