from collections.abc import Callable
from typing import Any

import pytest
import respx

from pyfederation import AuditLogType

from . import payloads
from .utils import run

pytestmark = pytest.mark.anyio


async def test_list_audit_logs(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/").respond(json=[payloads.audit_log()])

    logs = await run(client.list_audit_logs(2, 50, "ENTITY_EVENTS", "timestamp", "DESC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "2",
        "limit": "50",
        "category": "ENTITY_EVENTS",
        "by": "TIMESTAMP",
        "order": "DESC",
    }
    assert logs[0].type is AuditLogType.ENTITY_PUSHED


async def test_list_audit_logs_defaults(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/").respond(json=[])

    await run(client.list_audit_logs())

    assert dict(route.calls.last.request.url.params) == {"page": "1", "limit": "100"}


async def test_get_audit_log_record(client: Any, api: respx.MockRouter) -> None:
    api.get(f"/audit/{payloads.AUDIT_LOG_UUID}").respond(json=payloads.audit_log())

    log = await run(client.get_audit_log_record(payloads.AUDIT_LOG_UUID))

    assert log.entity == payloads.ENTITY_UUID


async def test_search_audit_logs(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/audit/search").respond(json=[payloads.audit_log()])

    logs = await run(client.search_audit_logs("pushed", category="ENTITY_EVENTS"))

    assert dict(route.calls.last.request.url.params) == {
        "q": "pushed",
        "page": "1",
        "limit": "100",
        "category": "ENTITY_EVENTS",
    }
    assert len(logs) == 1


async def test_sort_parameters_are_normalized(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/").respond(json=[])

    await run(client.list_audit_logs(by="timestamp", order="desc"))

    params = route.calls.last.request.url.params
    assert (params["by"], params["order"]) == ("TIMESTAMP", "DESC")


async def test_identifiers_are_one_path_segment(client: Any, api: respx.MockRouter) -> None:
    route = api.get(path__startswith="/audit/").respond(json=payloads.audit_log())

    await run(client.get_audit_log_record("../operators?x#y"))

    assert route.calls.last.request.url.raw_path == b"/audit/..%2Foperators%3Fx%23y"


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda client: client.list_audit_logs(page=0), "Page must be greater than 0"),
        (lambda client: client.list_audit_logs(limit=0), "Limit must be greater than 0"),
        (lambda client: client.get_audit_log_record(""), "Audit log UUID cannot be empty"),
        (lambda client: client.get_audit_log_record(".."), "Identifier cannot be"),
        (
            lambda client: client.search_audit_logs("a"),
            "Search query must contain at least 2 non-whitespace characters",
        ),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
