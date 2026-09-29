import json
from collections.abc import Callable
from typing import Any

import pytest
import respx

from pyfederation import IncidentType

from . import payloads
from .utils import ACCESS_TOKEN, run

pytestmark = pytest.mark.anyio

OPERATOR = f"/operators/{payloads.OPERATOR_UUID}"


async def test_create_operator(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/operators").respond(
        201, json={"uuid": payloads.OPERATOR_UUID, "access_token": ACCESS_TOKEN}
    )

    created = await run(client.create_operator("moderator"))

    assert json.loads(route.calls.last.request.content) == {"name": "moderator"}
    assert created.access_token == ACCESS_TOKEN


@pytest.mark.parametrize(
    ("method", "http_method", "path"),
    [
        ("delete_operator", "DELETE", OPERATOR),
        ("disable_operator", "PATCH", f"{OPERATOR}/disable"),
        ("enable_operator", "PATCH", f"{OPERATOR}/enable"),
    ],
)
async def test_operator_actions(
    client: Any, api: respx.MockRouter, method: str, http_method: str, path: str
) -> None:
    route = api.request(http_method, path).respond(json={"success": True})

    assert await run(getattr(client, method)(payloads.OPERATOR_UUID)) is None
    assert route.called


async def test_get_operator(client: Any, api: respx.MockRouter) -> None:
    api.get(OPERATOR).respond(json=payloads.operator())

    operator = await run(client.get_operator(payloads.OPERATOR_UUID))

    assert operator.name == "root"


async def test_get_self(client: Any, api: respx.MockRouter) -> None:
    api.get("/operators/self").respond(json=payloads.operator())

    operator = await run(client.get_self())

    assert operator.uuid == payloads.OPERATOR_UUID


async def test_list_operators(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/operators").respond(json=[payloads.operator()])

    operators = await run(client.list_operators(category="ENABLED", by="name", order="ASC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "limit": "100",
        "category": "ENABLED",
        "by": "name",
        "order": "ASC",
    }
    assert operators[0].uuid == payloads.OPERATOR_UUID


async def test_search_operators(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/operators/search").respond(json=[payloads.operator()])

    await run(client.search_operators("root", 1, 10))

    assert dict(route.calls.last.request.url.params) == {"q": "root", "page": "1", "limit": "10"}


async def test_list_operator_audit_logs(client: Any, api: respx.MockRouter) -> None:
    api.get(f"{OPERATOR}/audit").respond(json=[payloads.audit_log()])

    logs = await run(client.list_operator_audit_logs(payloads.OPERATOR_UUID))

    assert logs[0].operator == payloads.OPERATOR_UUID


async def test_list_operator_evidence(client: Any, api: respx.MockRouter) -> None:
    route = api.get(f"{OPERATOR}/evidence").respond(json=[payloads.evidence()])

    await run(client.list_operator_evidence(payloads.OPERATOR_UUID, include_confidential=True))

    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "limit": "100",
        "include_confidential": "true",
    }


async def test_list_operator_blacklist(client: Any, api: respx.MockRouter) -> None:
    route = api.get(f"{OPERATOR}/blacklist").respond(json=[payloads.blacklist()])

    records = await run(client.list_operator_blacklist(payloads.OPERATOR_UUID))

    assert route.calls.last.request.url.params["include_lifted"] == "false"
    assert records[0].type is IncidentType.SPAM


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("set_operator_permissions", "operator-permissions"),
        ("set_client_permissions", "client-permissions"),
        ("set_management_permissions", "management-permissions"),
        ("set_auto_assign", "auto-assign"),
    ],
)
async def test_operator_toggles(client: Any, api: respx.MockRouter, method: str, path: str) -> None:
    route = api.patch(f"{OPERATOR}/{path}").respond(json={"success": True})

    await run(getattr(client, method)(payloads.OPERATOR_UUID, False))

    assert json.loads(route.calls.last.request.content) == {"enabled": False}


async def test_generate_access_token_updates_the_client(client: Any, api: respx.MockRouter) -> None:
    new_token = "z" * 32
    api.post("/operators/refresh").respond(json=new_token)

    assert await run(client.generate_access_token()) == new_token
    assert client.access_token == new_token


async def test_generate_access_token_without_update(client: Any, api: respx.MockRouter) -> None:
    api.post("/operators/refresh").respond(json="z" * 32)

    await run(client.generate_access_token(update=False))

    assert client.access_token == ACCESS_TOKEN


async def test_generate_operator_access_token(client: Any, api: respx.MockRouter) -> None:
    api.post(f"{OPERATOR}/refresh").respond(json="z" * 32)

    assert await run(client.generate_operator_access_token(payloads.OPERATOR_UUID)) == "z" * 32
    assert client.access_token == ACCESS_TOKEN


async def test_update_operator_name(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{OPERATOR}/update-name").respond(json={"success": True})

    await run(client.update_operator_name(payloads.OPERATOR_UUID, "moderator"))

    assert json.loads(route.calls.last.request.content) == {"name": "moderator"}


@pytest.mark.parametrize(
    ("method", "path"),
    [("list_operator_reports", "reports"), ("list_assigned_operator_reports", "reports/assigned")],
)
async def test_list_operator_reports(
    client: Any, api: respx.MockRouter, method: str, path: str
) -> None:
    route = api.get(f"{OPERATOR}/{path}").respond(json=[payloads.report()])

    reports = await run(getattr(client, method)(payloads.OPERATOR_UUID, category="OPENED"))

    assert route.calls.last.request.url.params["category"] == "OPENED"
    assert reports[0].opened


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda client: client.create_operator(""), "Operator name cannot be empty"),
        (lambda client: client.get_operator(""), "Operator UUID cannot be empty"),
        (lambda client: client.set_auto_assign("", True), "Operator UUID cannot be empty"),
        (
            lambda client: client.update_operator_name(payloads.OPERATOR_UUID, ""),
            "Operator name cannot be empty",
        ),
        (
            lambda client: client.list_operator_reports(payloads.OPERATOR_UUID, page=0),
            "Page must be greater than 0",
        ),
        (lambda client: client.search_operators("a"), "Search query must be at least 2 characters"),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
