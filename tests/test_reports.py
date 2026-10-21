import json
from collections.abc import Callable
from typing import Any

import pytest
import respx

from pyfederation import ClassificationFlag, ContentInput, IncidentType

from . import payloads
from .utils import run

pytestmark = pytest.mark.anyio

REPORT = f"/reports/{payloads.REPORT_UUID}"


async def test_submit_report(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/reports").respond(
        json={"report": payloads.report(), "evidence": [payloads.evidence()]}
    )

    submission = await run(
        client.submit_report(
            "john@example.com",
            [ContentInput("Buy cheap watches"), ContentInput("Click this link", tag="phishing")],
            IncidentType.SPAM,
            "Sends unsolicited advertisements",
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        "reporting_entity": "john@example.com",
        "evidence": [
            {"text_content": "Buy cheap watches", "confidential": False},
            {"text_content": "Click this link", "tag": "phishing", "confidential": False},
        ],
        "incident_type": "SPAM",
        "report_message": "Sends unsolicited advertisements",
    }
    assert submission.report.incident_type is IncidentType.SPAM
    assert submission.evidence[0].uuid == payloads.EVIDENCE_UUID


async def test_submit_report_text(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/reports").respond(json={"report": payloads.report(), "evidence": []})

    await run(client.submit_report("john@example.com", "Buy cheap watches", IncidentType.SCAM))

    assert json.loads(route.calls.last.request.content) == {
        "reporting_entity": "john@example.com",
        "evidence": {"text_content": "Buy cheap watches", "confidential": False},
        "incident_type": "SCAM",
    }


async def test_delete_report(client: Any, api: respx.MockRouter) -> None:
    route = api.delete(REPORT).respond(json={"success": True})

    await run(client.delete_report(payloads.REPORT_UUID))

    assert route.called


async def test_get_report(client: Any, api: respx.MockRouter) -> None:
    api.get(REPORT).respond(json=payloads.report())

    report = await run(client.get_report(payloads.REPORT_UUID))

    assert report.message == "Sends unsolicited advertisements"


async def test_list_reports(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/reports").respond(json=[payloads.report()])

    await run(client.list_reports(category="UNASSIGNED", by="created", order="DESC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "limit": "100",
        "category": "UNASSIGNED",
        "by": "CREATED",
        "order": "DESC",
    }


async def test_list_opened_reports(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/reports/opened").respond(json=[payloads.report()])

    await run(client.list_opened_reports(by="incident_type"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "limit": "100",
        "by": "INCIDENT_TYPE",
    }


async def test_search_reports(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/reports/search").respond(json=[payloads.report()])

    await run(client.search_reports("advertisements"))

    assert route.calls.last.request.url.params["q"] == "advertisements"


async def test_list_report_evidence_records(client: Any, api: respx.MockRouter) -> None:
    route = api.get(f"{REPORT}/evidence").respond(json=[payloads.evidence()])

    evidence = await run(
        client.list_report_evidence_records(payloads.REPORT_UUID, include_confidential=True)
    )

    assert route.calls.last.request.url.params["include_confidential"] == "true"
    assert evidence[0].entity == payloads.ENTITY_UUID


async def test_close_report(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{REPORT}/close").respond(json={"success": True})

    await run(
        client.close_report(
            payloads.REPORT_UUID,
            ClassificationFlag.MALICIOUS,
            IncidentType.SPAM,
            payloads.TIMESTAMP,
        )
    )

    assert json.loads(route.calls.last.request.content) == {
        "classification_flag": "MALICIOUS",
        "blacklist_incident_type": "SPAM",
        "blacklist_expires": payloads.TIMESTAMP,
    }


async def test_close_report_without_actions(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{REPORT}/close").respond(json={"success": True})

    await run(client.close_report(payloads.REPORT_UUID))

    assert json.loads(route.calls.last.request.content) == {}


async def test_assign_operator_to_report(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{REPORT}/assign").respond(json={"success": True})

    await run(client.assign_operator_to_report(payloads.REPORT_UUID, payloads.OPERATOR_UUID))

    assert json.loads(route.calls.last.request.content) == {"operator": payloads.OPERATOR_UUID}


async def test_assign_report_to_self(client: Any, api: respx.MockRouter) -> None:
    route = api.patch(f"{REPORT}/assign").respond(json={"success": True})

    await run(client.assign_operator_to_report(payloads.REPORT_UUID))

    assert json.loads(route.calls.last.request.content) == {}


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (
            lambda client: client.submit_report("", "Spam", IncidentType.SPAM),
            "Reporting entity identifier cannot be empty",
        ),
        (
            lambda client: client.submit_report(payloads.ENTITY_UUID, "", IncidentType.SPAM),
            "Content cannot be empty",
        ),
        (
            lambda client: client.submit_report(payloads.ENTITY_UUID, [], IncidentType.SPAM),
            "Evidence cannot be empty",
        ),
        (
            lambda client: client.assign_operator_to_report(payloads.REPORT_UUID, ""),
            "Operator UUID cannot be empty",
        ),
        (lambda client: client.close_report(""), "Report UUID cannot be empty"),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
