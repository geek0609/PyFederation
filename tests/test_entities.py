import json
from collections.abc import Callable
from typing import Any

import pytest
import respx

from pyfederation import EntityRelationshipType, IncidentType, SuggestedAction

from . import payloads
from .utils import run

pytestmark = pytest.mark.anyio

ADDRESS = "john@example.com"
ENTITY = f"/entities/{ADDRESS}"


async def test_get_entity_record(client: Any, api: respx.MockRouter) -> None:
    api.get(ENTITY).respond(json=payloads.entity(metadata='{"platform": "telegram"}'))

    entity = await run(client.get_entity_record(ADDRESS))

    assert entity.metadata == {"platform": "telegram"}


async def test_delete_entity(client: Any, api: respx.MockRouter) -> None:
    route = api.delete(ENTITY).respond(json={"success": True})

    await run(client.delete_entity(ADDRESS))

    assert route.called


async def test_query_entity(client: Any, api: respx.MockRouter) -> None:
    api.get(f"{ENTITY}/query").respond(
        json={
            "entity_record": payloads.entity(),
            "related_entities": [],
            "active_blacklists": [payloads.blacklist()],
            "suggested_action": "TEMPORARILY_BLOCK_ENTITY",
            "suggested_lift_timestamp": payloads.TIMESTAMP + 86400,
        }
    )

    result = await run(client.query_entity(ADDRESS))

    assert result.suggested_action is SuggestedAction.TEMPORARILY_BLOCK_ENTITY
    assert result.active_blacklists[0].uuid == payloads.BLACKLIST_UUID


async def test_query_entity_with_concerns(client: Any, api: respx.MockRouter) -> None:
    route = api.get(f"{ENTITY}/query").respond(
        json={"entity_record": payloads.entity(), "related_entities": [], "active_blacklists": []}
    )

    await run(client.query_entity(ADDRESS, [IncidentType.MALWARE, IncidentType.PHISHING]))

    assert route.calls.last.request.url.params["concerns"] == "MALWARE,PHISHING"


async def test_list_entities(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/entities").respond(json=[payloads.entity()])

    entities = await run(client.list_entities(3, 20, "WHITELISTED", "reputation", "ASC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "3",
        "limit": "20",
        "category": "WHITELISTED",
        "by": "reputation",
        "order": "ASC",
    }
    assert entities[0].host == "example.com"


async def test_get_top_threats(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/entities/top-threats").respond(json=[payloads.entity(reputation=-900)])

    threats = await run(client.get_top_threats())

    assert route.calls.last.request.url.params["limit"] == "10"
    assert threats[0].reputation == -900


async def test_search_entities(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/entities/search").respond(json=[payloads.entity()])

    await run(client.search_entities("example", category="NOT_WHITELISTED"))

    assert dict(route.calls.last.request.url.params) == {
        "q": "example",
        "page": "1",
        "limit": "100",
        "category": "NOT_WHITELISTED",
    }


async def test_list_entity_audit_logs(client: Any, api: respx.MockRouter) -> None:
    api.get(f"{ENTITY}/audit").respond(json=[payloads.audit_log()])

    logs = await run(client.list_entity_audit_logs(ADDRESS))

    assert logs[0].entity == payloads.ENTITY_UUID


async def test_list_entity_blacklist_records(client: Any, api: respx.MockRouter) -> None:
    route = api.get(f"{ENTITY}/blacklist").respond(json=[payloads.blacklist(lifted=True)])

    records = await run(client.list_entity_blacklist_records(ADDRESS, include_lifted=True))

    assert route.calls.last.request.url.params["include_lifted"] == "true"
    assert records[0].lifted


async def test_list_entity_evidence_records(client: Any, api: respx.MockRouter) -> None:
    route = api.get(f"{ENTITY}/evidence").respond(json=[payloads.evidence()])

    await run(client.list_entity_evidence_records(ADDRESS, by="created", order="DESC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "limit": "100",
        "include_confidential": "false",
        "by": "created",
        "order": "DESC",
    }


async def test_list_entity_reports(client: Any, api: respx.MockRouter) -> None:
    api.get(f"{ENTITY}/reports").respond(json=[payloads.report()])

    reports = await run(client.list_entity_reports(ADDRESS))

    assert reports[0].reporting_entity == payloads.ENTITY_UUID


async def test_push_entity(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/entities").respond(json=payloads.ENTITY_UUID)

    entity_uuid = await run(client.push_entity("example.com", "john", {"platform": "telegram"}))

    assert json.loads(route.calls.last.request.content) == {
        "host": "example.com",
        "id": "john",
        "metadata": {"platform": "telegram"},
    }
    assert entity_uuid == payloads.ENTITY_UUID


async def test_push_entity_host_only(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/entities").respond(json=payloads.ENTITY_UUID)

    await run(client.push_entity("example.com"))

    assert json.loads(route.calls.last.request.content) == {"host": "example.com"}


async def test_update_entity(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(ENTITY).respond(json={"success": True})

    await run(client.update_entity(ADDRESS, {"platform": "discord"}))

    assert json.loads(route.calls.last.request.content) == {"metadata": {"platform": "discord"}}


async def test_set_entity_whitelist(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{ENTITY}/whitelist").respond(json={"success": True})

    await run(client.set_entity_whitelist(ADDRESS, True))

    assert json.loads(route.calls.last.request.content) == {"whitelisted": True}


async def test_clear_entity_reputation(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{ENTITY}/clear-reputation").respond(json={"success": True})

    await run(client.clear_entity_reputation(ADDRESS))

    assert route.called


async def test_set_entity_relationship(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{ENTITY}/relationship").respond(json={"success": True})

    await run(
        client.set_entity_relationship(
            ADDRESS, payloads.ENTITY_UUID, EntityRelationshipType.ALTERNATIVE
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        "target_identifier": payloads.ENTITY_UUID,
        "relationship_type": "ALTERNATIVE",
    }


async def test_clear_entity_relationship(client: Any, api: respx.MockRouter) -> None:
    route = api.delete(f"{ENTITY}/relationship").respond(json={"success": True})

    await run(client.clear_entity_relationship(ADDRESS))

    assert route.called


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda client: client.get_entity_record(""), "Entity identifier cannot be empty"),
        (
            lambda client: client.get_entity_record("a/b@example.com"),
            "Entity identifier cannot be used in a path",
        ),
        (lambda client: client.push_entity(""), "Host cannot be empty"),
        (lambda client: client.push_entity("example.com", ""), "Entity ID cannot be empty"),
        (
            lambda client: client.set_entity_relationship(
                ADDRESS, "", EntityRelationshipType.ALTERNATIVE
            ),
            "Related entity identifier cannot be empty",
        ),
        (lambda client: client.query_entity(ADDRESS, []), "Concerns cannot be empty"),
        (lambda client: client.get_top_threats(0), "Limit must be greater than 0"),
        (lambda client: client.list_entities(limit=0), "Limit must be greater than 0"),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
