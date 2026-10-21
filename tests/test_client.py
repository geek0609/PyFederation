import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from pyfederation import (
    AsyncFederationClient,
    ContentInput,
    FederationClient,
    FederationClientException,
    RecordType,
    SuggestedAction,
)
from pyfederation.records import EntityRecord, EvidenceRecord

from . import payloads
from .utils import ACCESS_TOKEN, run

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("client_type", [FederationClient, AsyncFederationClient])
def test_endpoint_trailing_slashes_are_removed(client_type: type) -> None:
    federation_client = client_type("https://federation.example/api//")
    assert federation_client.endpoint == "https://federation.example/api"


@pytest.mark.parametrize("client_type", [FederationClient, AsyncFederationClient])
def test_endpoint_must_be_a_url(client_type: type) -> None:
    with pytest.raises(ValueError, match="valid URL"):
        client_type("federation.example")


@pytest.mark.parametrize("access_token", ["", "abc def"])
def test_invalid_access_tokens_are_rejected(access_token: str) -> None:
    with pytest.raises(ValueError, match="Access token"):
        FederationClient("https://federation.example", access_token)


async def test_requests_are_authenticated(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/info").respond(json=payloads.server_information())

    await run(client.get_server_information())

    assert route.calls.last.request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"


async def test_requests_are_anonymous_without_an_access_token(
    client: Any, api: respx.MockRouter
) -> None:
    route = api.get("/info").respond(json=payloads.server_information())

    client.access_token = None
    await run(client.get_server_information())

    assert "Authorization" not in route.calls.last.request.headers


async def test_get_server_information(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").respond(json=payloads.server_information())

    information = await run(client.get_server_information())

    assert information.name == "Federation Server"
    assert information.public_search_types == [RecordType.ENTITY]


async def test_get_specification(client: Any, api: respx.MockRouter) -> None:
    api.get("/specification").respond(json={"openapi": "3.2.0"})

    assert await run(client.get_specification()) == {"openapi": "3.2.0"}


async def test_error_responses_raise(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").respond(
        503,
        json={
            "success": False,
            "code": 503,
            "message": "Service Unavailable: Database unavailable",
        },
    )

    with pytest.raises(FederationClientException) as raised:
        await run(client.get_server_information())

    assert raised.value.status_code == 503
    assert str(raised.value) == (
        "Failed to get server information, Service Unavailable: Database unavailable"
    )


async def test_transport_errors_raise(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").mock(side_effect=httpx.ConnectError("Connection refused"))

    with pytest.raises(FederationClientException) as raised:
        await run(client.get_server_information())

    assert raised.value.status_code == 0
    assert str(raised.value) == "Failed to get server information: Connection refused"


async def test_search(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/search").respond(
        json=[
            {"type": "ENTITY", "record": payloads.entity()},
            {"type": "EVIDENCE", "record": payloads.evidence()},
        ]
    )

    results = await run(client.search("example", [RecordType.ENTITY, RecordType.EVIDENCE], 2, 5))

    assert dict(route.calls.last.request.url.params) == {
        "q": "example",
        "type": "ENTITY,EVIDENCE",
        "page": "2",
        "limit": "5",
    }
    assert isinstance(results[0].record, EntityRecord)
    assert isinstance(results[1].record, EvidenceRecord)


async def test_search_leaves_out_unrecognized_record_types(
    client: Any, api: respx.MockRouter
) -> None:
    api.get("/search").respond(
        json=[{"type": "NEW", "record": {}}, {"type": "ENTITY", "record": payloads.entity()}]
    )

    results = await run(client.search("example"))

    assert [result.type for result in results] == [RecordType.ENTITY]


async def test_search_all_types(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/search").respond(json=[])

    await run(client.search("example"))

    assert dict(route.calls.last.request.url.params) == {"q": "example", "page": "1", "limit": "10"}


def scan_response() -> dict[str, Any]:
    return {
        "author_entity": None,
        "resolved_entities": [],
        "classification": {
            "classification_flag": "MALICIOUS",
            "confidence": 0.93,
            "detected_language": "en",
        },
        "suggested_action": "BLOCK_CONTENT",
        "suggested_lift_timestamp": None,
        "scan_results": {"classification": 42.5},
        "risk_score": 42.5,
    }


async def test_scan_content_text(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/scan").respond(json=scan_response())

    scanned = await run(client.scan_content("Buy cheap watches"))

    assert json.loads(route.calls.last.request.content) == {
        "evidence": {"text_content": "Buy cheap watches", "confidential": False}
    }
    assert scanned.classification.confidence == 0.93
    assert scanned.suggested_action is SuggestedAction.BLOCK_CONTENT
    assert scanned.risk_score == 42.5


async def test_scan_content_inputs(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/scan").respond(json=scan_response())

    await run(
        client.scan_content(
            [ContentInput("First message"), ContentInput("Second message", tag="spam")],
            author="john@example.com",
            top_k=3,
            threshold=0.5,
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        "evidence": [
            {"text_content": "First message", "confidential": False},
            {"text_content": "Second message", "tag": "spam", "confidential": False},
        ],
        "author": "john@example.com",
        "top_k": 3,
        "threshold": 0.5,
    }


async def test_non_json_responses_raise(client: Any, api: respx.MockRouter) -> None:
    api.get("/info").respond(content=b"<html></html>", headers={"Content-Type": "text/html"})

    with pytest.raises(FederationClientException, match="Expected JSON response") as error:
        await run(client.get_server_information())

    assert error.value.status_code == 200


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda client: client.search("a"), "Search query must be at least 2 characters"),
        (lambda client: client.search("spam", page=0), "Page must be greater than 0"),
        (lambda client: client.scan_content([]), "Evidence cannot be empty"),
        (
            lambda client: client.scan_content(""),
            "At least one evidence record must contain text content",
        ),
        (
            lambda client: client.scan_content([ContentInput(note="Seen in a group")]),
            "At least one evidence record must contain text content",
        ),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
