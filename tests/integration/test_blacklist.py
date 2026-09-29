import time
from typing import Any

import pytest

from pyfederation import IncidentType

from ..utils import run
from .conftest import Records

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_temporary_blacklist(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    expires = int(time.time()) + 3600

    blacklist_uuid = records.track(
        "delete_blacklist_record",
        await run(client.blacklist_entity(entity_uuid, IncidentType.SPAM, expires=expires)),
    )
    await run(client.extend_blacklist_record(blacklist_uuid, 600))
    record = await run(client.get_blacklist_record(blacklist_uuid))
    result = await run(client.query_entity(entity_uuid))

    assert record.entity == entity_uuid
    assert record.type is IncidentType.SPAM
    assert record.expires == expires + 600
    assert [blacklist.uuid for blacklist in result.active_blacklists] == [blacklist_uuid]
    assert result.suggested_action is not None


async def test_lift_blacklist(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    blacklist_uuid = records.track(
        "delete_blacklist_record",
        await run(client.blacklist_entity(entity_uuid, IncidentType.MALWARE)),
    )

    await run(client.lift_blacklist_record(blacklist_uuid))
    record = await run(client.get_blacklist_record(blacklist_uuid))
    active = await run(client.list_entity_blacklist_records(entity_uuid))
    everything = await run(client.list_entity_blacklist_records(entity_uuid, include_lifted=True))

    assert record.lifted
    assert record.expires is None
    assert active == []
    assert [blacklist.uuid for blacklist in everything] == [blacklist_uuid]


async def test_list_and_search_blacklist(client: Any, records: Records) -> None:
    operator = await run(client.get_self())
    entity_uuid = await records.entity()
    entity = await run(client.get_entity_record(entity_uuid))
    blacklist_uuid = records.track(
        "delete_blacklist_record",
        await run(client.blacklist_entity(entity_uuid, IncidentType.PHISHING)),
    )

    listed = await run(client.list_blacklist_records(category="PERMANENT", order="DESC"))
    created = await run(client.list_operator_blacklist(operator.uuid, order="DESC"))
    found = await run(client.search_blacklist(entity.host))

    assert blacklist_uuid in [record.uuid for record in listed]
    assert blacklist_uuid in [record.uuid for record in created]
    assert [record.uuid for record in found] == [blacklist_uuid]


async def test_delete_blacklist(client: Any, records: Records) -> None:
    entity_uuid = await records.entity()
    blacklist_uuid = await run(client.blacklist_entity(entity_uuid, IncidentType.SCAM))

    await run(client.delete_blacklist_record(blacklist_uuid))

    everything = await run(client.list_entity_blacklist_records(entity_uuid, include_lifted=True))
    assert everything == []
