"""Asynchronous client for Federation servers."""

import logging
from collections.abc import Sequence
from types import TracebackType
from typing import Any, Self

import httpx

from ._utils import (
    compact,
    evidence_payload,
    page_params,
    parse_list,
    path_segment,
    require,
    search_params,
)
from .enums import RecordType
from .exceptions import FederationClientException
from .records import (
    AuditLog,
    BlacklistRecord,
    ContentInput,
    EvidenceRecord,
    OperatorCreated,
    OperatorRecord,
    ReportRecord,
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

    async def list_audit_logs(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Lists audit log entries."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = await self._request(
            "GET", "", f"Failed to list audit logs, page: {page}, limit: {limit}", params=params
        )
        return parse_list(AuditLog, data)

    async def get_audit_log_record(self, audit_log_uuid: str) -> AuditLog:
        """Returns an audit log entry by its UUID."""
        require(audit_log_uuid, "Audit log UUID")
        data = await self._request(
            "GET",
            f"audit/{path_segment(audit_log_uuid)}",
            f"Failed to get audit log record for UUID {audit_log_uuid}",
        )
        return AuditLog.model_validate(data)

    async def search_audit_logs(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Searches audit log entries."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = await self._request(
            "GET", "audit/search", f"Failed to search audit logs, query: {query}", params=params
        )
        return parse_list(AuditLog, data)

    async def create_operator(self, operator_name: str) -> OperatorCreated:
        """Creates an operator, returning its UUID and access token."""
        require(operator_name, "Operator name")
        data = await self._request(
            "POST",
            "operators",
            f"Failed to create operator with name {operator_name}",
            json={"name": operator_name},
        )
        return OperatorCreated.model_validate(data)

    async def delete_operator(self, operator_uuid: str) -> None:
        """Deletes an operator."""
        require(operator_uuid, "Operator UUID")
        await self._request(
            "DELETE",
            f"operators/{path_segment(operator_uuid)}",
            f"Failed to delete operator with UUID {operator_uuid}",
        )

    async def disable_operator(self, operator_uuid: str) -> None:
        """Disables an operator, preventing it from authenticating."""
        require(operator_uuid, "Operator UUID")
        await self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/disable",
            f"Failed to disable operator with UUID {operator_uuid}",
        )

    async def enable_operator(self, operator_uuid: str) -> None:
        """Enables a disabled operator."""
        require(operator_uuid, "Operator UUID")
        await self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/enable",
            f"Failed to enable operator with UUID {operator_uuid}",
        )

    async def get_operator(self, operator_uuid: str) -> OperatorRecord:
        """Returns an operator by its UUID."""
        require(operator_uuid, "Operator UUID")
        data = await self._request(
            "GET", f"operators/{path_segment(operator_uuid)}", "Failed to get operator"
        )
        return OperatorRecord.model_validate(data)

    async def get_self(self) -> OperatorRecord:
        """Returns the operator the client is authenticated as."""
        data = await self._request("GET", "operators/self", "Failed to get self operator")
        return OperatorRecord.model_validate(data)

    async def list_operators(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[OperatorRecord]:
        """Lists operators."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = await self._request(
            "GET",
            "operators",
            f"Failed to list operators, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(OperatorRecord, data)

    async def list_operator_audit_logs(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Lists the audit log entries of an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = await self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/audit",
            f"Failed to list audit logs for operator with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(AuditLog, data)

    async def list_operator_evidence(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists the evidence records submitted by an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(
            page, limit, include_confidential=include_confidential, by=by, order=order
        )
        data = await self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/evidence",
            f"Failed to list evidence records for operator with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    async def list_operator_blacklist(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        include_lifted: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[BlacklistRecord]:
        """Lists the blacklist records created by an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, include_lifted=include_lifted, by=by, order=order)
        data = await self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/blacklist",
            f"Failed to list operator blacklist records with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    async def set_operator_permissions(
        self, operator_uuid: str, has_operator_permissions: bool
    ) -> None:
        """Grants or revokes the permission to manage other operators."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if has_operator_permissions else "disable"
        await self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/operator-permissions",
            f"Failed to {action} the operator's operator permissions",
            json={"enabled": has_operator_permissions},
        )

    async def set_client_permissions(
        self, operator_uuid: str, has_client_permissions: bool
    ) -> None:
        """Grants or revokes the permission to submit data as a client."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if has_client_permissions else "disable"
        await self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/client-permissions",
            f"Failed to {action} the operator's client permissions",
            json={"enabled": has_client_permissions},
        )

    async def set_management_permissions(
        self, operator_uuid: str, has_management_permissions: bool
    ) -> None:
        """Grants or revokes the permission to manage the database."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if has_management_permissions else "disable"
        await self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/management-permissions",
            f"Failed to {action} the operator's management permissions",
            json={"enabled": has_management_permissions},
        )

    async def set_auto_assign(self, operator_uuid: str, auto_assign: bool) -> None:
        """Sets whether new reports are automatically assigned to an operator."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if auto_assign else "disable"
        await self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/auto-assign",
            f"Failed to {action} the operator's auto assign",
            json={"enabled": auto_assign},
        )

    async def generate_access_token(self, update: bool = True) -> str:
        """Generates a new access token for the authenticated operator, revoking the current one.

        Args:
            update: Whether the client should use the new access token from now on.
        """
        access_token: str = await self._request(
            "POST", "operators/refresh", "Failed to generate access token"
        )
        if update:
            self.access_token = access_token

        return access_token

    async def generate_operator_access_token(self, operator_uuid: str) -> str:
        """Generates a new access token for an operator, revoking its current one."""
        require(operator_uuid, "Operator UUID")
        access_token: str = await self._request(
            "POST",
            f"operators/{path_segment(operator_uuid)}/refresh",
            f"Failed to generate access token for operator with UUID {operator_uuid}",
        )
        return access_token

    async def search_operators(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[OperatorRecord]:
        """Searches operators."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = await self._request(
            "GET", "operators/search", f"Failed to search operators, query: {query}", params=params
        )
        return parse_list(OperatorRecord, data)

    async def update_operator_name(self, operator_uuid: str, new_name: str) -> None:
        """Renames an operator."""
        require(operator_uuid, "Operator UUID")
        require(new_name, "Operator name")
        await self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/update-name",
            f"Failed to update name for operator with UUID {operator_uuid}",
            json={"name": new_name},
        )

    async def list_operator_reports(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the reports submitted by an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = await self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/reports",
            f"Failed to list reports for operator {operator_uuid}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    async def list_assigned_operator_reports(
        self,
        operator_uuid: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the reports assigned to an operator."""
        require(operator_uuid, "Operator UUID")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = await self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/reports/assigned",
            f"Failed to list assigned reports for operator {operator_uuid}",
            params=params,
        )
        return parse_list(ReportRecord, data)
