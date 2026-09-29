import json
from collections.abc import Callable
from typing import Any

import pytest
import respx

from pyfederation import IncidentType

from . import payloads
from .utils import run

pytestmark = pytest.mark.anyio

BLACKLIST = f"/blacklist/{payloads.BLACKLIST_UUID}"


async def test_blacklist_entity(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/blacklist").respond(201, json=payloads.BLACKLIST_UUID)

    blacklist_uuid = await run(
        client.blacklist_entity(
            "john@example.com", IncidentType.PHISHING, payloads.REPORT_UUID, payloads.TIMESTAMP
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        "entity_identifier": "john@example.com",
        "type": "PHISHING",
        "report_uuid": payloads.REPORT_UUID,
        "expires": payloads.TIMESTAMP,
    }
    assert blacklist_uuid == payloads.BLACKLIST_UUID


async def test_blacklist_entity_permanently(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/blacklist").respond(201, json=payloads.BLACKLIST_UUID)

    await run(client.blacklist_entity("john@example.com", IncidentType.MALWARE))

    assert json.loads(route.calls.last.request.content) == {
        "entity_identifier": "john@example.com",
        "type": "MALWARE",
    }


async def test_get_blacklist_record(client: Any, api: respx.MockRouter) -> None:
    api.get(BLACKLIST).respond(json=payloads.blacklist(expires=None))

    record = await run(client.get_blacklist_record(payloads.BLACKLIST_UUID))

    assert record.expires is None


@pytest.mark.parametrize(
    ("method", "http_method", "path"),
    [
        ("delete_blacklist_record", "DELETE", BLACKLIST),
        ("lift_blacklist_record", "PATCH", f"{BLACKLIST}/lift"),
    ],
)
async def test_blacklist_record_actions(
    client: Any, api: respx.MockRouter, method: str, http_method: str, path: str
) -> None:
    route = api.request(http_method, path).respond(json={"success": True})

    await run(getattr(client, method)(payloads.BLACKLIST_UUID))

    assert route.called


async def test_extend_blacklist_record(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{BLACKLIST}/extend").respond(json={"success": True})

    await run(client.extend_blacklist_record(payloads.BLACKLIST_UUID, 3600))

    assert json.loads(route.calls.last.request.content) == {"seconds": 3600}


async def test_list_blacklist_records(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/blacklist").respond(json=[payloads.blacklist()])

    records = await run(client.list_blacklist_records(1, 50, True, "ACTIVE", "expires", "ASC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "limit": "50",
        "include_lifted": "true",
        "category": "ACTIVE",
        "by": "expires",
        "order": "ASC",
    }
    assert records[0].report == payloads.REPORT_UUID


async def test_search_blacklist(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/blacklist/search").respond(json=[payloads.blacklist()])

    await run(client.search_blacklist("example.com", category="PERMANENT"))

    assert dict(route.calls.last.request.url.params) == {
        "q": "example.com",
        "page": "1",
        "limit": "100",
        "category": "PERMANENT",
    }


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (
            lambda client: client.blacklist_entity("", IncidentType.SPAM),
            "Entity identifier cannot be empty",
        ),
        (
            lambda client: client.blacklist_entity(
                payloads.ENTITY_UUID, IncidentType.SPAM, expires=-1
            ),
            "expires parameter must be a positive integer",
        ),
        (
            lambda client: client.extend_blacklist_record(payloads.BLACKLIST_UUID, 0),
            "Extension seconds must be positive",
        ),
        (lambda client: client.lift_blacklist_record(""), "Blacklist record UUID cannot be empty"),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
