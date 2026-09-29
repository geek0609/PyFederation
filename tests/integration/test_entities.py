from typing import Any

import pytest

from pyfederation import EntityRelationshipType, FederationClientException

from ..utils import run
from .conftest import Records, unique

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_entity_identifiers(client: Any, records: Records) -> None:
    host = f"{unique('entity')}.com"
    entity_uuid = records.track(
        "delete_entity", await run(client.push_entity(host, "john", {"platform": "telegram"}))
    )

    by_uuid = await run(client.get_entity_record(entity_uuid))
    by_address = await run(client.get_entity_record(f"john@{host}"))
    by_hash = await run(client.get_entity_record(by_uuid.hash))

    assert by_uuid == by_address == by_hash
    assert by_uuid.metadata == {"platform": "telegram"}
    assert await run(client.push_entity(host, "john")) == entity_uuid


async def test_update_entity(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()

    await run(client.update_entity(entity_uuid, {"platform": "discord", "reports": 2}))
    await run(client.set_entity_whitelist(entity_uuid, True))
    entity = await run(client.get_entity_record(entity_uuid))

    assert entity.metadata == {"platform": "discord", "reports": 2}
    assert entity.whitelisted

    await run(client.clear_entity_reputation(entity_uuid))
    assert (await run(client.get_entity_record(entity_uuid))).reputation == 0


async def test_entity_relationships(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    alternative_uuid = await records.entity()

    await run(
        client.set_entity_relationship(
            alternative_uuid, entity_uuid, EntityRelationshipType.ALTERNATIVE
        )
    )
    alternative = await run(client.get_entity_record(alternative_uuid))
    result = await run(client.query_entity(entity_uuid))

    assert alternative.relationship_entity == entity_uuid
    assert alternative.relationship_type is EntityRelationshipType.ALTERNATIVE
    assert alternative_uuid in [related.uuid for related in result.related_entities]

    await run(client.clear_entity_relationship(alternative_uuid))
    assert (await run(client.get_entity_record(alternative_uuid))).relationship_entity is None


async def test_list_and_search_entities(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    entity = await run(client.get_entity_record(entity_uuid))

    listed = await run(client.list_entities(by="created", order="DESC"))
    found = await run(client.search_entities(entity.host))
    threats = await run(client.get_top_threats(5))

    assert entity_uuid in [listed_entity.uuid for listed_entity in listed]
    assert [found_entity.uuid for found_entity in found] == [entity_uuid]
    assert len(threats) <= 5


async def test_entity_records(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    evidence_uuid = await records.evidence(entity_uuid, confidential=True)

    public = await run(client.list_entity_evidence_records(entity_uuid))
    everything = await run(
        client.list_entity_evidence_records(entity_uuid, include_confidential=True)
    )
    audit_logs = await run(client.list_entity_audit_logs(entity_uuid))

    assert evidence_uuid not in [evidence.uuid for evidence in public]
    assert evidence_uuid in [evidence.uuid for evidence in everything]
    assert all(log.entity == entity_uuid for log in audit_logs)


async def test_delete_entity(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()

    await run(client.delete_entity(entity_uuid))

    with pytest.raises(FederationClientException) as raised:
        await run(client.get_entity_record(entity_uuid))
    assert raised.value.status_code == 404
