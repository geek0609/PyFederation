import os
import uuid
from collections.abc import AsyncIterator
from contextlib import suppress
from typing import Any

import pytest

from pyfederation import AsyncFederationClient, FederationClient, FederationClientException

from ..utils import run

ENDPOINT = os.environ.get("SERVER_ENDPOINT", "http://localhost:7000")
ACCESS_TOKEN = os.environ.get("SERVER_ACCESS_TOKEN", "abcdefghijklmnopqrstuvwxyz123456")


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class Records:
    """Creates records through a client and deletes them once the test is done."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self._created: list[tuple[str, str]] = []

    def track(self, delete_method: str, record_uuid: str) -> str:
        self._created.append((delete_method, record_uuid))
        return record_uuid

    async def entity(self) -> str:
        entity_uuid = await run(self.client.push_entity(f"{unique('pyfederation')}.com", "user"))
        return self.track("delete_entity", entity_uuid)

    async def evidence(self, entity_uuid: str, **options: Any) -> str:
        evidence_uuid = await run(
            self.client.submit_evidence(entity_uuid, "Integration test evidence", **options)
        )
        return self.track("delete_evidence", evidence_uuid)

    async def operator(self) -> Any:
        created = await run(self.client.create_operator(unique("operator")))
        self.track("delete_operator", created.uuid)
        return created

    async def cleanup(self) -> None:
        for delete_method, record_uuid in reversed(self._created):
            # The test may have deleted the record itself
            with suppress(FederationClientException):
                await run(getattr(self.client, delete_method)(record_uuid))


@pytest.fixture(params=["sync", "async"])
async def client(request: pytest.FixtureRequest) -> AsyncIterator[Any]:
    if request.param == "sync":
        with FederationClient(ENDPOINT, ACCESS_TOKEN) as sync_client:
            yield sync_client
    else:
        async with AsyncFederationClient(ENDPOINT, ACCESS_TOKEN) as async_client:
            yield async_client


@pytest.fixture
async def records(client: Any) -> AsyncIterator[Records]:
    tracked = Records(client)
    yield tracked
    await tracked.cleanup()
