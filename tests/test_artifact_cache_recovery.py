from __future__ import annotations

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kubernetes.client.exceptions import ApiException
from mlflow_kubernetes_plugins.workspace_plugin import caches
from urllib3.exceptions import ReadTimeoutError


def config(namespace, *, version="1", path="data"):
    return {
        "metadata": {"namespace": namespace, "resourceVersion": version},
        "spec": {
            "artifactRootSecret": caches.ARTIFACT_CONNECTION_SECRET_NAME,
            "artifactRootPath": path,
        },
    }


def secret(namespace, *, version="1", bucket="bucket"):
    return SimpleNamespace(
        metadata=SimpleNamespace(namespace=namespace, resource_version=version),
        data={"AWS_S3_BUCKET": base64.b64encode(bucket.encode()).decode()},
    )


@pytest.fixture(params=["config", "secret"])
def artifact_cache(request, monkeypatch):
    # Run the real watch loops synchronously, with no threads or timed sleeps.
    monkeypatch.setattr(caches.threading.Thread, "start", lambda self: None)
    api = MagicMock()
    ensure_secret_cache = MagicMock()
    if request.param == "config":
        item = config

        def listing(*items, version="1"):
            return {"items": list(items), "metadata": {"resourceVersion": version}}

        list_api = api.list_cluster_custom_object
        kwargs = {
            "group": caches.MLFLOW_CONFIG_GROUP,
            "version": caches.MLFLOW_CONFIG_VERSION,
            "plural": caches.MLFLOW_CONFIG_PLURAL,
        }
        list_api.return_value = listing(item("old"), item("changed"))
        cache = caches.MlflowConfigCache(api, ensure_secret_cache)
        get = cache.get_config
    else:
        item = secret

        def listing(*items, version="1"):
            return SimpleNamespace(
                items=list(items), metadata=SimpleNamespace(resource_version=version)
            )

        list_api = api.list_secret_for_all_namespaces
        kwargs = {"field_selector": f"metadata.name={caches.ARTIFACT_CONNECTION_SECRET_NAME}"}
        list_api.return_value = listing(item("old"), item("changed"))
        cache = caches.SecretCache(api)
        get = cache.get_secret
    list_api.reset_mock()
    monkeypatch.setattr(cache._stop_event, "wait", lambda timeout: False)
    return SimpleNamespace(
        kind=request.param,
        cache=cache,
        get=get,
        item=item,
        listing=listing,
        list_api=list_api,
        kwargs=kwargs,
        ensure_secret_cache=ensure_secret_cache,
    )


@pytest.mark.parametrize("ending", ["eof", "timeout", "expired", "api", "error_event"])
def test_reconnect_repairs_additions_modifications_and_deletions(
    artifact_cache, monkeypatch, ending
):
    ctx = artifact_cache
    cache = ctx.cache
    changed = (
        config("changed", version="12", path="updated")
        if ctx.kind == "config"
        else secret("changed", version="12", bucket="updated")
    )
    ctx.list_api.return_value = ctx.listing(ctx.item("new"), changed, version="12")
    first = MagicMock()
    if ending == "timeout":
        first.stream.side_effect = ReadTimeoutError(None, None, "stalled")
    elif ending == "expired":
        first.stream.side_effect = ApiException(status=410)
    elif ending == "api":
        first.stream.side_effect = ApiException(status=503)
    elif ending == "error_event":
        first.stream.return_value = iter(
            [
                {"type": "ERROR", "object": {"code": 410}},
                {"type": "ADDED", "object": ctx.item("obsolete")},
            ]
        )
    else:
        first.stream.return_value = iter(())
    second = MagicMock()

    def recovered(*args, **kwargs):
        assert ctx.get("old") is None
        assert ctx.get("obsolete") is None
        assert ctx.get("new").namespace == "new"
        info = ctx.get("changed")
        if ctx.kind == "config":
            assert info.artifact_root_path == "updated"
            assert info.artifact_root_secret == caches.ARTIFACT_CONNECTION_SECRET_NAME
        else:
            assert info.bucket_uri == "s3://updated"
        assert cache._resource_version == "12"
        cache.stop()
        return iter(())

    second.stream.side_effect = recovered
    watches = MagicMock(side_effect=[first, second])
    monkeypatch.setattr(caches.watch, "Watch", watches)

    cache._run()

    assert watches.call_count == 2
    first.stream.assert_called_once_with(
        ctx.list_api,
        **ctx.kwargs,
        resource_version="1",
        timeout_seconds=300,
        _request_timeout=(5, 330),
    )
    assert second.stream.call_args.kwargs["resource_version"] == "12"
    list_kwargs = dict(ctx.kwargs, _request_timeout=(5, 30))
    if ctx.kind == "secret":
        list_kwargs["watch"] = False
    ctx.list_api.assert_called_once_with(**list_kwargs)
    first.stop.assert_called_once()
    second.stop.assert_called_once()


def test_failed_refresh_retries_before_starting_watch(artifact_cache, monkeypatch):
    ctx = artifact_cache
    ctx.cache._resource_version = None
    ctx.list_api.side_effect = [
        ReadTimeoutError(None, None, "stalled"),
        ApiException(status=503),
        ctx.listing(ctx.item("new"), version="12"),
    ]
    watcher = MagicMock()

    def recovered(*args, **kwargs):
        assert ctx.list_api.call_count == 3
        assert ctx.get("new").namespace == "new"
        ctx.cache.stop()
        return iter(())

    watcher.stream.side_effect = recovered
    monkeypatch.setattr(caches.watch, "Watch", lambda: watcher)

    ctx.cache._run()

    assert watcher.stream.call_args.kwargs["resource_version"] == "12"


@pytest.mark.parametrize("status", [403, 404])
@pytest.mark.parametrize("source", ["refresh", "watch"])
def test_unavailable_resources_wait_then_recover(artifact_cache, monkeypatch, status, source):
    ctx = artifact_cache
    if ctx.kind == "secret" and status == 404:
        pytest.skip("Only MLflowConfig treats an absent CRD as optional")
    denied_watch = MagicMock()
    denied_watch.stream.side_effect = ApiException(status=status)
    if source == "refresh":
        ctx.cache._resource_version = None
        ctx.list_api.side_effect = [
            ApiException(status=status),
            ctx.listing(ctx.item("new"), version="12"),
        ]
    else:
        ctx.list_api.return_value = ctx.listing(ctx.item("new"), version="12")
    retry_waits = []

    def retry_wait(timeout):
        retry_waits.append(timeout)
        if ctx.kind == "secret":
            assert ctx.get("old") is None
        else:
            assert not ctx.cache._configs
        # Requests must not force a reload of an unavailable Secret cache.
        assert ctx.list_api.call_count == (1 if source == "refresh" else 0)
        return False

    monkeypatch.setattr(ctx.cache._retry_event, "wait", retry_wait)
    watcher = MagicMock()

    def recovered(*args, **kwargs):
        assert ctx.get("new").namespace == "new"
        ctx.cache.stop()
        return iter(())

    watcher.stream.side_effect = recovered
    watches = [watcher] if source == "refresh" else [denied_watch, watcher]
    monkeypatch.setattr(caches.watch, "Watch", MagicMock(side_effect=watches))
    ctx.cache._run()

    assert retry_waits == [300]
    assert ctx.list_api.call_count == (2 if source == "refresh" else 1)
    if source == "watch":
        denied_watch.stop.assert_called_once()


@pytest.mark.parametrize("event_type", ["ADDED", "MODIFIED", "DELETED"])
def test_resource_events_keep_updating_cache(artifact_cache, event_type):
    ctx = artifact_cache
    ctx.cache._handle_event({"type": event_type, "object": ctx.item("old", version="9")})
    assert ctx.cache._resource_version == "9"
    assert (ctx.get("old") is None) == (event_type == "DELETED")
    ctx.list_api.assert_not_called()


def test_nameless_bookmark_advances_cursor(artifact_cache):
    ctx = artifact_cache
    ctx.cache._handle_event({"type": "BOOKMARK", "object": {"metadata": {"resourceVersion": "12"}}})
    assert ctx.cache._resource_version == "12"
    if ctx.kind == "secret":
        ctx.cache._handle_event(
            {
                "type": "BOOKMARK",
                "object": SimpleNamespace(metadata=SimpleNamespace(resource_version="13")),
            }
        )
        assert ctx.cache._resource_version == "13"


def test_shutdown_interrupts_failed_refresh_retry(artifact_cache, monkeypatch):
    ctx = artifact_cache
    ctx.cache._resource_version = None
    ctx.list_api.side_effect = ReadTimeoutError(None, None, "stalled")
    waits = []

    def stop_on_wait(timeout):
        waits.append(timeout)
        ctx.cache.stop()
        return True

    monkeypatch.setattr(ctx.cache._stop_event, "wait", stop_on_wait)
    watcher_factory = MagicMock()
    monkeypatch.setattr(caches.watch, "Watch", watcher_factory)
    ctx.cache._run()

    assert waits == [2]
    ctx.list_api.assert_called_once()
    watcher_factory.assert_not_called()


def test_cached_reads_and_misses_keep_existing_semantics(artifact_cache):
    ctx = artifact_cache
    assert ctx.get("old").namespace == "old"
    assert ctx.get("missing") is None
    ctx.list_api.assert_not_called()


def test_empty_bookmark_preserves_cursor(artifact_cache):
    ctx = artifact_cache
    ctx.cache._handle_event({"type": "BOOKMARK", "object": {"metadata": {}}})
    assert ctx.cache._resource_version == "1"


def test_refresh_ensures_secret_cache_for_new_config(artifact_cache):
    ctx = artifact_cache
    if ctx.kind != "config":
        pytest.skip("Secret cache activation belongs to MLflowConfig")
    ctx.ensure_secret_cache.reset_mock()
    ctx.list_api.return_value = ctx.listing(ctx.item("new"), version="12")
    ctx.cache._refresh_full()
    ctx.ensure_secret_cache.assert_called_once_with()
