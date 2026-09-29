"""Asynchronous client for Federation servers."""

import logging
from collections.abc import Sequence
from types import TracebackType
from typing import Any, Self

import httpx

from ._utils import (
    compact,
    evidence_payload,
    parse_list,
    search_params,
)
from .enums import RecordType
from .exceptions import FederationClientException
from .records import (
    ContentInput,
    ScannedContent,
    SearchResult,
    ServerInformation,
)

log = logging.getLogger(__name__)


class AsyncFederationClient:
    """Asynchronous API client for a Federation server.

    Every public method corresponds to an endpoint of the server and handles serialization,
    authentication and error mapping, raising FederationClientException when a request fails.

    List and search methods are paginated with a 1-based page and a limit of items per page, which
    the server caps at its configured maximum. Most of them also accept a category filter, a field
    to sort by and a sort order (ASC or DESC); the accepted values of each are listed in the server
    specification.

    Entities are identified by their UUID, SHA-256 hash or address, such as a domain, an email
    address or an IP address.

    Invalid arguments, such as an empty UUID or a page below 1, raise ValueError before any request
    is sent.

    To release the underlying connection pool, close the client with aclose() or use it as a
    context manager.
    """

    def __init__(
        self,
        endpoint: str,
        access_token: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """
        Args:
            endpoint: The base URL of the Federation server.
            access_token: The access token used for authentication, or None for anonymous access.
            http_client: The HTTP client used for all requests, closed together with this client.

        Raises:
            ValueError: If the endpoint is not a valid URL or the access token is invalid.
        """
        if not httpx.URL(endpoint).host:
            raise ValueError(f"Endpoint must be a valid URL: {endpoint}")

        self._endpoint = endpoint.rstrip("/")
        self._http_client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(30, write=60))
        self.access_token = access_token

    @property
    def endpoint(self) -> str:
        """The base URL of the Federation server."""
        return self._endpoint

    @property
    def access_token(self) -> str | None:
        """The access token used for authentication, or None for anonymous access."""
        return self._access_token

    @access_token.setter
    def access_token(self, access_token: str | None) -> None:
        if access_token is not None and (not access_token or any(map(str.isspace, access_token))):
            raise ValueError("Access token cannot be empty or contain whitespace")

        self._access_token = access_token

    async def aclose(self) -> None:
        """Closes the underlying HTTP client."""
        await self._http_client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def _send(
        self,
        method: str,
        path: str,
        error_message: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        headers = {"Accept": "application/json"}
        if self._access_token is not None:
            headers["Authorization"] = f"Bearer {self._access_token}"

        request = self._http_client.build_request(
            method,
            f"{self._endpoint}/{path}",
            params=params,
            json=json,
            data=data,
            files=files,
            headers=headers,
        )
        log.debug("%s request to %s", method, request.url)

        try:
            response = await self._http_client.send(request, stream=stream)
            if response.is_error:
                await response.aread()
                raise FederationClientException.from_response(response, error_message)
        except httpx.HTTPError as e:
            raise FederationClientException(f"{error_message}: {e}") from e

        return response

    async def _request(
        self,
        method: str,
        path: str,
        error_message: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
    ) -> Any:
        response = await self._send(
            method, path, error_message, params=params, json=json, data=data, files=files
        )
        if not response.content:
            return None

        try:
            return response.json()
        except ValueError as e:
            raise FederationClientException(
                f"{error_message}: Expected JSON response but received Content-Type: "
                f"{response.headers.get('Content-Type')}",
                response.status_code,
            ) from e

    async def get_server_information(self) -> ServerInformation:
        """Returns the server information including version, feature flags and record counts."""
        data = await self._request("GET", "info", "Failed to get server information")
        return ServerInformation.model_validate(data)

    async def get_specification(self) -> dict[str, Any]:
        """Returns the OpenAPI specification of the server."""
        spec: dict[str, Any] = await self._request(
            "GET", "specification", "Failed to get specification"
        )
        return spec

    async def search(
        self,
        query: str,
        types: Sequence[RecordType] | None = None,
        page: int = 1,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Searches across all record types.

        Args:
            query: The search query, at least 2 characters long.
            types: The record types to restrict the search to, or None for all types.
            page: The page number.
            limit: The number of results per record type.
        """
        params = search_params(query, page, limit, type=",".join(types) if types else None)
        data = await self._request(
            "GET", "search", f"Failed to search, query: {query}", params=params
        )
        return parse_list(SearchResult, data)

    async def scan_content(
        self,
        evidence: str | ContentInput | Sequence[ContentInput],
        author: str | None = None,
        top_k: int | None = None,
        threshold: float | None = None,
    ) -> ScannedContent:
        """Scans content for entities and blacklist records, and classifies it.

        Args:
            evidence: The text, content input or content inputs to scan.
            author: The UUID, SHA-256 hash or address of the author entity.
            top_k: The number of top classifications to return.
            threshold: The confidence threshold for classification.
        """
        payload = evidence_payload(evidence)
        items = payload if isinstance(payload, list) else [payload]
        if not any(item.get("text_content") for item in items):
            raise ValueError("At least one evidence record must contain text content")

        data = await self._request(
            "POST",
            "scan",
            "Failed to scan content",
            json=compact(evidence=payload, author=author, top_k=top_k, threshold=threshold),
        )
        return ScannedContent.model_validate(data)
