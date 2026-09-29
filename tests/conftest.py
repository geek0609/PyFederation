import ssl
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest
import respx

from pyfederation import AsyncFederationClient, FederationClient

from .utils import ACCESS_TOKEN, ENDPOINT

# Loading the certificate store is slow, so every client shares one SSL context
SSL_CONTEXT = ssl.create_default_context()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=ENDPOINT) as router:
        yield router


@pytest.fixture(params=["sync", "async"])
async def client(request: pytest.FixtureRequest) -> AsyncIterator[Any]:
    """Yields each client, to be called through utils.run() so tests cover both."""
    if request.param == "sync":
        http_client = httpx.Client(verify=SSL_CONTEXT)
        with FederationClient(ENDPOINT, ACCESS_TOKEN, http_client) as sync_client:
            yield sync_client
    else:
        async_http_client = httpx.AsyncClient(verify=SSL_CONTEXT)
        async with AsyncFederationClient(ENDPOINT, ACCESS_TOKEN, async_http_client) as async_client:
            yield async_client
