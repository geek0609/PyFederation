from typing import Any

import pytest

from pyfederation import AuditLogType

from ..utils import run
from .conftest import Records

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_audit_logs(client: Any, records: Records) -> None:
    entity = await run(client.get_entity_record(await records.entity()))

    logs = await run(client.list_entity_audit_logs(entity.uuid))
    pushed = next(log for log in logs if log.type is AuditLogType.ENTITY_PUSHED)
    listed = await run(
        client.list_audit_logs(category="ENTITY_EVENTS", by="timestamp", order="DESC")
    )
    found = await run(client.search_audit_logs(entity.host))

    assert await run(client.get_audit_log_record(pushed.uuid)) == pushed
    assert pushed.uuid in [log.uuid for log in listed]
    assert pushed.uuid in [log.uuid for log in found]
