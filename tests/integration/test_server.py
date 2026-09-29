from typing import Any

import pytest

from pyfederation import (
    AsyncFederationClient,
    ContentInput,
    FederationClient,
    FederationClientException,
    NamedEntityType,
    RecordType,
)

from ..utils import run
from .conftest import ENDPOINT, Records, unique

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_get_server_information(client: Any) -> None:
    information = await run(client.get_server_information())

    assert information.api_version
    assert information.operators >= 1


async def test_get_specification(client: Any) -> None:
    specification = await run(client.get_specification())

    assert "/scan" in specification["paths"]


async def test_invalid_access_token_is_rejected() -> None:
    with (
        FederationClient(ENDPOINT, "a" * 32) as client,
        pytest.raises(FederationClientException) as raised,
    ):
        client.get_self()

    assert raised.value.status_code in (401, 403)


async def test_anonymous_client_cannot_manage_operators() -> None:
    async with AsyncFederationClient(ENDPOINT) as client:
        with pytest.raises(FederationClientException) as raised:
            await client.create_operator(unique("operator"))

    assert raised.value.status_code == 401


async def test_search(client: Any, records: Records) -> None:
    host = f"{unique('searchable')}.com"
    records.track("delete_entity", await run(client.push_entity(host)))

    results = await run(client.search(host, [RecordType.ENTITY]))

    assert [result.record.host for result in results] == [host]


async def test_scan_content(client: Any, records: Records) -> None:
    author = await run(client.get_entity_record(await records.entity()))
    host = f"{unique('scanned')}.com"
    mentioned_uuid = records.track("delete_entity", await run(client.push_entity(host)))
    text = f"Visit https://{host}/offer now"

    scanned = await run(
        client.scan_content(
            [ContentInput(text), ContentInput("Second message")],
            author=f"{author.id}@{author.host}",
        )
    )

    assert scanned.author_entity.entity.uuid == author.uuid
    [mentioned] = scanned.resolved_entities
    assert mentioned.entity.uuid == mentioned_uuid
    assert mentioned.entity_position.type is NamedEntityType.URL
    assert text[mentioned.entity_position.offset :].startswith("https://")
