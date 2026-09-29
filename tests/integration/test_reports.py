import time
from typing import Any

import pytest

from pyfederation import ClassificationFlag, ContentInput, IncidentType

from ..utils import run
from .conftest import Records

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def submit_report(client: Any, records: Records, entity_uuid: str) -> Any:
    submission = await run(
        client.submit_report(
            entity_uuid,
            [ContentInput("Buy cheap watches"), ContentInput("Click this link", tag="phishing")],
            IncidentType.SPAM,
            "Sends unsolicited advertisements",
        )
    )
    records.track("delete_report", submission.report.uuid)
    for evidence in submission.evidence:
        records.track("delete_evidence", evidence.uuid)

    return submission


async def test_submit_report(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()

    submission = await submit_report(client, records, entity_uuid)
    report = await run(client.get_report(submission.report.uuid))
    evidence = await run(client.list_report_evidence_records(report.uuid))

    assert report.reporting_entity == entity_uuid
    assert report.incident_type is IncidentType.SPAM
    assert report.message == "Sends unsolicited advertisements"
    assert report.opened
    assert {record.uuid for record in evidence} == {record.uuid for record in submission.evidence}


async def test_link_evidence_to_report(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    report = (await submit_report(client, records, entity_uuid)).report
    evidence_uuid = await records.evidence(entity_uuid)

    await run(client.add_evidence_to_report(evidence_uuid, report.uuid))

    assert (await run(client.get_evidence_record(evidence_uuid))).report == report.uuid


async def test_assign_and_close_report(client: Any, records: Records) -> None:
    operator = await run(client.get_self())
    entity_uuid = await records.entity()
    report = (await submit_report(client, records, entity_uuid)).report

    await run(client.assign_operator_to_report(report.uuid))
    opened = await run(client.list_opened_reports())
    assigned = await run(client.list_assigned_operator_reports(operator.uuid))

    assert report.uuid in [opened_report.uuid for opened_report in opened]
    assert report.uuid in [assigned_report.uuid for assigned_report in assigned]

    await run(
        client.close_report(
            report.uuid,
            ClassificationFlag.MALICIOUS,
            IncidentType.SPAM,
            int(time.time()) + 3600,
        )
    )
    closed = await run(client.get_report(report.uuid))
    blacklists = await run(client.list_entity_blacklist_records(entity_uuid))
    for blacklist in blacklists:
        records.track("delete_blacklist_record", blacklist.uuid)

    assert not closed.opened
    assert [blacklist.report for blacklist in blacklists] == [report.uuid]


async def test_list_and_search_reports(client: Any, records: Records) -> None:
    operator = await run(client.get_self())
    entity_uuid = await records.entity()
    report = (await submit_report(client, records, entity_uuid)).report

    listed = await run(client.list_reports(category="OPENED", by="created", order="DESC"))
    submitted = await run(client.list_operator_reports(operator.uuid, order="DESC"))
    for_entity = await run(client.list_entity_reports(entity_uuid))
    found = await run(client.search_reports("unsolicited advertisements"))

    assert report.uuid in [listed_report.uuid for listed_report in listed]
    assert report.uuid in [submitted_report.uuid for submitted_report in submitted]
    assert [entity_report.uuid for entity_report in for_entity] == [report.uuid]
    assert report.uuid in [found_report.uuid for found_report in found]
