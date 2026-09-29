import json
from collections.abc import Callable
from typing import Any

import pytest
import respx

from pyfederation import ClassificationFlag

from . import payloads
from .utils import run

pytestmark = pytest.mark.anyio

EVIDENCE = f"/evidence/{payloads.EVIDENCE_UUID}"


async def test_get_evidence_record(client: Any, api: respx.MockRouter) -> None:
    api.get(EVIDENCE).respond(json=payloads.evidence())

    evidence = await run(client.get_evidence_record(payloads.EVIDENCE_UUID))

    assert evidence.classification_flag is ClassificationFlag.SUSPICIOUS
    assert evidence.metadata == {"source": "telegram"}


async def test_delete_evidence(client: Any, api: respx.MockRouter) -> None:
    route = api.delete(EVIDENCE).respond(json={"success": True})

    await run(client.delete_evidence(payloads.EVIDENCE_UUID))

    assert route.called


async def test_get_evidence_attachments(client: Any, api: respx.MockRouter) -> None:
    api.get(f"{EVIDENCE}/attachments").respond(json=[payloads.attachment()])

    attachments = await run(client.get_evidence_attachments(payloads.EVIDENCE_UUID))

    assert attachments[0].file_mime == "image/png"


async def test_list_evidence(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/evidence").respond(json=[payloads.evidence()])

    await run(client.list_evidence(2, 25, True, "CLASSIFIED", "tag", "ASC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "2",
        "limit": "25",
        "include_confidential": "true",
        "category": "CLASSIFIED",
        "by": "tag",
        "order": "ASC",
    }


async def test_search_evidence(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/evidence/search").respond(json=[payloads.evidence()])

    evidence = await run(client.search_evidence("watches"))

    assert dict(route.calls.last.request.url.params) == {
        "q": "watches",
        "page": "1",
        "limit": "100",
    }
    assert evidence[0].text_content == "Buy cheap watches"


async def test_submit_evidence(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/evidence").respond(201, json=payloads.EVIDENCE_UUID)

    evidence_uuid = await run(
        client.submit_evidence(
            "john@example.com",
            "Buy cheap watches",
            note="Reported by a member",
            tag="spam",
            confidential=True,
            metadata={"chat_id": 42},
            classification=ClassificationFlag.MALICIOUS,
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        "entity_identifier": "john@example.com",
        "text_content": "Buy cheap watches",
        "note": "Reported by a member",
        "tag": "spam",
        "confidential": True,
        "metadata": {"chat_id": 42},
        "classification": "MALICIOUS",
    }
    assert evidence_uuid == payloads.EVIDENCE_UUID


async def test_submit_evidence_without_content(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/evidence").respond(201, json=payloads.EVIDENCE_UUID)

    await run(client.submit_evidence("john@example.com"))

    assert json.loads(route.calls.last.request.content) == {
        "entity_identifier": "john@example.com",
        "confidential": False,
    }


@pytest.mark.parametrize(
    ("method", "path", "argument", "body"),
    [
        (
            "update_evidence_confidentiality",
            "update-confidentiality",
            True,
            {"confidential": True},
        ),
        ("update_evidence_tag", "update-tag", "phishing", {"tag": "phishing"}),
        (
            "classify_evidence",
            "classify",
            ClassificationFlag.NORMAL,
            {"classification_flag": "NORMAL"},
        ),
        (
            "add_evidence_to_report",
            "link-report",
            payloads.REPORT_UUID,
            {"report_uuid": payloads.REPORT_UUID},
        ),
    ],
)
async def test_evidence_updates(
    client: Any,
    api: respx.MockRouter,
    method: str,
    path: str,
    argument: Any,
    body: dict[str, Any],
) -> None:
    route = api.patch(f"{EVIDENCE}/{path}").respond(json={"success": True})

    await run(getattr(client, method)(payloads.EVIDENCE_UUID, argument))

    assert json.loads(route.calls.last.request.content) == body


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda client: client.submit_evidence(""), "Entity identifier cannot be empty"),
        (
            lambda client: client.update_evidence_tag(payloads.EVIDENCE_UUID, ""),
            "Tag cannot be empty",
        ),
        (
            lambda client: client.add_evidence_to_report(payloads.EVIDENCE_UUID, ""),
            "Report UUID cannot be empty",
        ),
        (lambda client: client.list_evidence(page=0), "Page must be greater than 0"),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
