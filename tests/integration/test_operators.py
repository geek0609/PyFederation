from typing import Any

import pytest

from pyfederation import FederationClient, FederationClientException

from ..utils import run
from .conftest import ENDPOINT, Records, unique

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_operator_lifecycle(client: Any, records: Records) -> None:
    created = await records.operator()

    name = unique("renamed")
    await run(client.update_operator_name(created.uuid, name))
    await run(client.set_client_permissions(created.uuid, True))
    await run(client.set_management_permissions(created.uuid, True))
    await run(client.set_operator_permissions(created.uuid, True))
    await run(client.set_auto_assign(created.uuid, True))
    operator = await run(client.get_operator(created.uuid))

    assert operator.name == name
    assert operator.client_permissions
    assert operator.management_permissions
    assert operator.operator_permissions
    assert operator.auto_assign

    await run(client.disable_operator(created.uuid))
    assert (await run(client.get_operator(created.uuid))).disabled

    await run(client.enable_operator(created.uuid))
    assert not (await run(client.get_operator(created.uuid))).disabled


async def test_list_and_search_operators(client: Any, records: Records) -> None:
    created = await records.operator()
    operator = await run(client.get_operator(created.uuid))

    listed = await run(client.list_operators(category="ENABLED", by="created"))
    found = await run(client.search_operators(operator.name))

    assert all(not listed_operator.disabled for listed_operator in listed)
    assert [found_operator.uuid for found_operator in found] == [created.uuid]


async def test_operator_access_tokens(client: Any, records: Records) -> None:
    created = await records.operator()

    with FederationClient(ENDPOINT, created.access_token) as operator_client:
        assert operator_client.get_self().uuid == created.uuid

        new_token = operator_client.generate_access_token()
        assert operator_client.access_token == new_token
        assert operator_client.get_self().uuid == created.uuid

    regenerated_token = await run(client.generate_operator_access_token(created.uuid))
    with FederationClient(ENDPOINT, new_token) as revoked_client:
        with pytest.raises(FederationClientException):
            revoked_client.get_self()

        revoked_client.access_token = regenerated_token
        assert revoked_client.get_self().uuid == created.uuid


async def test_operator_records(client: Any, records: Records) -> None:
    operator = await run(client.get_self())
    entity_uuid = await records.entity()
    evidence_uuid = await records.evidence(entity_uuid)

    evidence = await run(client.list_operator_evidence(operator.uuid, order="DESC"))
    audit_logs = await run(client.list_operator_audit_logs(operator.uuid, order="DESC"))

    assert evidence_uuid in [record.uuid for record in evidence]
    assert all(log.operator == operator.uuid for log in audit_logs)
