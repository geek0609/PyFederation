from typing import Any

import pytest

from pyfederation import ClassificationFlag

from ..utils import run
from .conftest import Records, unique

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_submit_evidence(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()

    evidence_uuid = await records.evidence(
        entity_uuid, note="Seen in a group chat", tag="spam", metadata={"chat_id": 42}
    )
    evidence = await run(client.get_evidence_record(evidence_uuid))

    assert evidence.entity == entity_uuid
    assert evidence.text_content == "Integration test evidence"
    assert evidence.note == "Seen in a group chat"
    assert evidence.tag == "spam"
    assert evidence.metadata == {"chat_id": 42}
    assert not evidence.confidential


async def test_update_evidence(client: Any, records: Records) -> None:
    evidence_uuid = await records.evidence(await records.entity())

    await run(client.update_evidence_tag(evidence_uuid, "phishing"))
    await run(client.update_evidence_confidentiality(evidence_uuid, True))
    await run(client.classify_evidence(evidence_uuid, ClassificationFlag.MALICIOUS))
    evidence = await run(client.get_evidence_record(evidence_uuid))

    assert evidence.tag == "phishing"
    assert evidence.confidential
    assert evidence.classification_flag is ClassificationFlag.MALICIOUS


async def test_list_and_search_evidence(client: Any, records: Records) -> None:
    tag = unique("tag")
    evidence_uuid = await records.evidence(await records.entity(), tag=tag)

    listed = await run(client.list_evidence(by="created", order="DESC"))
    found = await run(client.search_evidence(tag))

    assert evidence_uuid in [evidence.uuid for evidence in listed]
    assert [evidence.uuid for evidence in found] == [evidence_uuid]


async def test_delete_evidence(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    evidence_uuid = await records.evidence(entity_uuid)

    await run(client.delete_evidence(evidence_uuid))

    evidence = await run(client.list_entity_evidence_records(entity_uuid))
    assert evidence_uuid not in [record.uuid for record in evidence]
