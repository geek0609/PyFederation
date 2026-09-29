# Generated from async_client.py by scripts/unasync.py, do not edit.
"""Synchronous client for Federation servers."""

import logging
from collections.abc import Sequence
from types import TracebackType
from typing import Any, Self

import httpx

from ._utils import (
    compact,
    entity_path,
    evidence_payload,
    page_params,
    parse_list,
    path_segment,
    require,
    search_params,
)
from .enums import ClassificationFlag, EntityRelationshipType, IncidentType, RecordType
from .exceptions import FederationClientException
from .records import (
    AuditLog,
    BlacklistRecord,
    ContentInput,
    EntityQueryResult,
    EntityRecord,
    EvidenceRecord,
    FileAttachmentRecord,
    OperatorCreated,
    OperatorRecord,
    ReportRecord,
    ReportSubmission,
    ScannedContent,
    SearchResult,
    ServerInformation,
)

log = logging.getLogger(__name__)


class FederationClient:
    """Synchronous API client for a Federation server.

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

    To release the underlying connection pool, close the client with close() or use it as a
    context manager.
    """

    def __init__(
        self,
        endpoint: str,
        access_token: str | None = None,
        http_client: httpx.Client | None = None,
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
        self._http_client = http_client or httpx.Client(timeout=httpx.Timeout(30, write=60))
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

    def close(self) -> None:
        """Closes the underlying HTTP client."""
        self._http_client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _send(
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
            response = self._http_client.send(request, stream=stream)
            if response.is_error:
                response.read()
                raise FederationClientException.from_response(response, error_message)
        except httpx.HTTPError as e:
            raise FederationClientException(f"{error_message}: {e}") from e

        return response

    def _request(
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
        response = self._send(
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

    def get_server_information(self) -> ServerInformation:
        """Returns the server information including version, feature flags and record counts."""
        data = self._request("GET", "info", "Failed to get server information")
        return ServerInformation.model_validate(data)

    def get_specification(self) -> dict[str, Any]:
        """Returns the OpenAPI specification of the server."""
        spec: dict[str, Any] = self._request("GET", "specification", "Failed to get specification")
        return spec

    def search(
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
        data = self._request("GET", "search", f"Failed to search, query: {query}", params=params)
        return parse_list(SearchResult, data)

    def scan_content(
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

        data = self._request(
            "POST",
            "scan",
            "Failed to scan content",
            json=compact(evidence=payload, author=author, top_k=top_k, threshold=threshold),
        )
        return ScannedContent.model_validate(data)

    def list_audit_logs(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Lists audit log entries."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "", f"Failed to list audit logs, page: {page}, limit: {limit}", params=params
        )
        return parse_list(AuditLog, data)

    def get_audit_log_record(self, audit_log_uuid: str) -> AuditLog:
        """Returns an audit log entry by its UUID."""
        require(audit_log_uuid, "Audit log UUID")
        data = self._request(
            "GET",
            f"audit/{path_segment(audit_log_uuid)}",
            f"Failed to get audit log record for UUID {audit_log_uuid}",
        )
        return AuditLog.model_validate(data)

    def search_audit_logs(
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
        data = self._request(
            "GET", "audit/search", f"Failed to search audit logs, query: {query}", params=params
        )
        return parse_list(AuditLog, data)

    def create_operator(self, operator_name: str) -> OperatorCreated:
        """Creates an operator, returning its UUID and access token."""
        require(operator_name, "Operator name")
        data = self._request(
            "POST",
            "operators",
            f"Failed to create operator with name {operator_name}",
            json={"name": operator_name},
        )
        return OperatorCreated.model_validate(data)

    def delete_operator(self, operator_uuid: str) -> None:
        """Deletes an operator."""
        require(operator_uuid, "Operator UUID")
        self._request(
            "DELETE",
            f"operators/{path_segment(operator_uuid)}",
            f"Failed to delete operator with UUID {operator_uuid}",
        )

    def disable_operator(self, operator_uuid: str) -> None:
        """Disables an operator, preventing it from authenticating."""
        require(operator_uuid, "Operator UUID")
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/disable",
            f"Failed to disable operator with UUID {operator_uuid}",
        )

    def enable_operator(self, operator_uuid: str) -> None:
        """Enables a disabled operator."""
        require(operator_uuid, "Operator UUID")
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/enable",
            f"Failed to enable operator with UUID {operator_uuid}",
        )

    def get_operator(self, operator_uuid: str) -> OperatorRecord:
        """Returns an operator by its UUID."""
        require(operator_uuid, "Operator UUID")
        data = self._request(
            "GET", f"operators/{path_segment(operator_uuid)}", "Failed to get operator"
        )
        return OperatorRecord.model_validate(data)

    def get_self(self) -> OperatorRecord:
        """Returns the operator the client is authenticated as."""
        data = self._request("GET", "operators/self", "Failed to get self operator")
        return OperatorRecord.model_validate(data)

    def list_operators(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[OperatorRecord]:
        """Lists operators."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "operators",
            f"Failed to list operators, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(OperatorRecord, data)

    def list_operator_audit_logs(
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
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/audit",
            f"Failed to list audit logs for operator with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(AuditLog, data)

    def list_operator_evidence(
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
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/evidence",
            f"Failed to list evidence records for operator with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def list_operator_blacklist(
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
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/blacklist",
            f"Failed to list operator blacklist records with UUID {operator_uuid}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    def set_operator_permissions(self, operator_uuid: str, has_operator_permissions: bool) -> None:
        """Grants or revokes the permission to manage other operators."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if has_operator_permissions else "disable"
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/operator-permissions",
            f"Failed to {action} the operator's operator permissions",
            json={"enabled": has_operator_permissions},
        )

    def set_client_permissions(self, operator_uuid: str, has_client_permissions: bool) -> None:
        """Grants or revokes the permission to submit data as a client."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if has_client_permissions else "disable"
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/client-permissions",
            f"Failed to {action} the operator's client permissions",
            json={"enabled": has_client_permissions},
        )

    def set_management_permissions(
        self, operator_uuid: str, has_management_permissions: bool
    ) -> None:
        """Grants or revokes the permission to manage the database."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if has_management_permissions else "disable"
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/management-permissions",
            f"Failed to {action} the operator's management permissions",
            json={"enabled": has_management_permissions},
        )

    def set_auto_assign(self, operator_uuid: str, auto_assign: bool) -> None:
        """Sets whether new reports are automatically assigned to an operator."""
        require(operator_uuid, "Operator UUID")
        action = "enable" if auto_assign else "disable"
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/auto-assign",
            f"Failed to {action} the operator's auto assign",
            json={"enabled": auto_assign},
        )

    def generate_access_token(self, update: bool = True) -> str:
        """Generates a new access token for the authenticated operator, revoking the current one.

        Args:
            update: Whether the client should use the new access token from now on.
        """
        access_token: str = self._request(
            "POST", "operators/refresh", "Failed to generate access token"
        )
        if update:
            self.access_token = access_token

        return access_token

    def generate_operator_access_token(self, operator_uuid: str) -> str:
        """Generates a new access token for an operator, revoking its current one."""
        require(operator_uuid, "Operator UUID")
        access_token: str = self._request(
            "POST",
            f"operators/{path_segment(operator_uuid)}/refresh",
            f"Failed to generate access token for operator with UUID {operator_uuid}",
        )
        return access_token

    def search_operators(
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
        data = self._request(
            "GET", "operators/search", f"Failed to search operators, query: {query}", params=params
        )
        return parse_list(OperatorRecord, data)

    def update_operator_name(self, operator_uuid: str, new_name: str) -> None:
        """Renames an operator."""
        require(operator_uuid, "Operator UUID")
        require(new_name, "Operator name")
        self._request(
            "PATCH",
            f"operators/{path_segment(operator_uuid)}/update-name",
            f"Failed to update name for operator with UUID {operator_uuid}",
            json={"name": new_name},
        )

    def list_operator_reports(
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
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/reports",
            f"Failed to list reports for operator {operator_uuid}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def list_assigned_operator_reports(
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
        data = self._request(
            "GET",
            f"operators/{path_segment(operator_uuid)}/reports/assigned",
            f"Failed to list assigned reports for operator {operator_uuid}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def delete_entity(self, entity_identifier: str) -> None:
        """Deletes an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "DELETE",
            entity_path(entity_identifier),
            f"Failed to delete the entity {entity_identifier}",
        )

    def get_entity_record(self, entity_identifier: str) -> EntityRecord:
        """Returns an entity."""
        require(entity_identifier, "Entity identifier")
        data = self._request(
            "GET",
            entity_path(entity_identifier),
            f"Failed to get the entity record for {entity_identifier}",
        )
        return EntityRecord.model_validate(data)

    def query_entity(self, entity_identifier: str) -> EntityQueryResult:
        """Returns an entity with its relationship group, active blacklists and suggested action."""
        require(entity_identifier, "Entity identifier")
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/query",
            f"Failed to query entity {entity_identifier}",
        )
        return EntityQueryResult.model_validate(data)

    def list_entities(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EntityRecord]:
        """Lists entities."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "entities",
            f"Failed to list entities, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(EntityRecord, data)

    def get_top_threats(self, limit: int = 10) -> list[EntityRecord]:
        """Returns the entities with the lowest reputation."""
        if limit < 1:
            raise ValueError("Limit must be greater than 0")

        data = self._request(
            "GET",
            "entities/top-threats",
            f"Failed to retrieve top threats, limit: {limit}",
            params={"limit": limit},
        )
        return parse_list(EntityRecord, data)

    def list_entity_audit_logs(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[AuditLog]:
        """Lists the audit log entries of an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/audit",
            f"Failed to list audit logs for entity {entity_identifier}",
            params=params,
        )
        return parse_list(AuditLog, data)

    def list_entity_blacklist_records(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        include_lifted: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[BlacklistRecord]:
        """Lists the blacklist records of an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(page, limit, include_lifted=include_lifted, by=by, order=order)
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/blacklist",
            f"Failed to list blacklist records for entity {entity_identifier}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    def list_entity_evidence_records(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists the evidence records of an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(
            page, limit, include_confidential=include_confidential, by=by, order=order
        )
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/evidence",
            f"Failed to list evidence records for entity {entity_identifier}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def list_entity_reports(
        self,
        entity_identifier: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the reports made against an entity."""
        require(entity_identifier, "Entity identifier")
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            f"{entity_path(entity_identifier)}/reports",
            f"Failed to list reports for entity {entity_identifier}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def push_entity(
        self, host: str, id: str | None = None, metadata: dict[str, Any] | None = None
    ) -> str:
        """Registers an entity, returning its UUID. Pushing a known entity returns its UUID.

        Args:
            host: The domain or IP address of the entity.
            id: The local part of the entity address, such as the username of an email address.
            metadata: Arbitrary metadata to associate with the entity.
        """
        require(host, "Host")
        if id is not None:
            require(id, "Entity ID")

        entity_uuid: str = self._request(
            "POST",
            "entities",
            f"Failed to push entity with domain {host}",
            json=compact(host=host, id=id, metadata=metadata),
        )
        return entity_uuid

    def update_entity(self, entity_identifier: str, metadata: dict[str, Any]) -> None:
        """Replaces the metadata of an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "PATCH",
            entity_path(entity_identifier),
            f"Failed to update entity {entity_identifier}",
            json={"metadata": metadata},
        )

    def set_entity_whitelist(self, entity_identifier: str, whitelisted: bool) -> None:
        """Sets whether an entity is whitelisted."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "PATCH",
            f"{entity_path(entity_identifier)}/whitelist",
            f"Failed to set whitelist state for entity {entity_identifier}",
            json={"whitelisted": whitelisted},
        )

    def clear_entity_reputation(self, entity_identifier: str) -> None:
        """Resets the reputation of an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "PATCH",
            f"{entity_path(entity_identifier)}/clear-reputation",
            f"Failed to clear reputation for entity {entity_identifier}",
        )

    def set_entity_relationship(
        self,
        entity_identifier: str,
        related_entity_identifier: str,
        relationship_type: EntityRelationshipType,
    ) -> None:
        """Relates an entity to another entity, given by its UUID, SHA-256 hash or address."""
        require(entity_identifier, "Entity identifier")
        require(related_entity_identifier, "Related entity identifier")
        self._request(
            "PATCH",
            f"{entity_path(entity_identifier)}/relationship",
            f"Failed to set relationship for entity {entity_identifier}",
            json={
                "target_identifier": related_entity_identifier,
                "relationship_type": relationship_type,
            },
        )

    def clear_entity_relationship(self, entity_identifier: str) -> None:
        """Removes the relationship of an entity."""
        require(entity_identifier, "Entity identifier")
        self._request(
            "DELETE",
            f"{entity_path(entity_identifier)}/relationship",
            f"Failed to clear relationship for entity {entity_identifier}",
        )

    def search_entities(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EntityRecord]:
        """Searches entities."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "entities/search", f"Failed to search entities, query: {query}", params=params
        )
        return parse_list(EntityRecord, data)

    def delete_evidence(self, evidence_uuid: str) -> None:
        """Deletes an evidence record."""
        require(evidence_uuid, "Evidence UUID")
        self._request(
            "DELETE",
            f"evidence/{path_segment(evidence_uuid)}",
            f"Failed to delete evidence with UUID {evidence_uuid}",
        )

    def get_evidence_record(self, evidence_uuid: str) -> EvidenceRecord:
        """Returns an evidence record by its UUID."""
        require(evidence_uuid, "Evidence UUID")
        data = self._request(
            "GET",
            f"evidence/{path_segment(evidence_uuid)}",
            f"Failed to get evidence record with UUID {evidence_uuid}",
        )
        return EvidenceRecord.model_validate(data)

    def get_evidence_attachments(self, evidence_uuid: str) -> list[FileAttachmentRecord]:
        """Returns the file attachments of an evidence record."""
        require(evidence_uuid, "Evidence UUID")
        data = self._request(
            "GET",
            f"evidence/{path_segment(evidence_uuid)}/attachments",
            f"Failed to get evidence attachments for evidence with UUID {evidence_uuid}",
        )
        return parse_list(FileAttachmentRecord, data)

    def list_evidence(
        self,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists evidence records."""
        params = page_params(
            page,
            limit,
            include_confidential=include_confidential,
            category=category,
            by=by,
            order=order,
        )
        data = self._request(
            "GET",
            "evidence",
            f"Failed to list evidence records, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def submit_evidence(
        self,
        entity_identifier: str,
        text_content: str | None = None,
        note: str | None = None,
        tag: str | None = None,
        confidential: bool = False,
        metadata: dict[str, Any] | None = None,
        classification: ClassificationFlag | None = None,
    ) -> str:
        """Submits evidence about an entity, returning the UUID of the evidence record.

        Args:
            entity_identifier: The entity the evidence is about.
            text_content: The observed text content.
            note: A note by the operator.
            tag: A tag to categorize the evidence with.
            confidential: Whether the evidence is hidden from the public.
            metadata: Arbitrary metadata to associate with the evidence.
            classification: An immutable classification of the evidence, which requires management
                permissions and trains the server's classifier with the text content.
        """
        require(entity_identifier, "Entity identifier")
        payload = compact(
            entity_identifier=entity_identifier,
            text_content=text_content,
            note=note,
            tag=tag,
            confidential=confidential,
            metadata=metadata,
            classification=classification,
        )
        evidence_uuid: str = self._request(
            "POST",
            "evidence",
            f"Failed to submit evidence for entity {entity_identifier}",
            json=payload,
        )
        return evidence_uuid

    def update_evidence_confidentiality(self, evidence_uuid: str, confidential: bool) -> None:
        """Sets whether an evidence record is hidden from the public."""
        require(evidence_uuid, "Evidence UUID")
        action = "set" if confidential else "unset"
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/update-confidentiality",
            f"Failed to {action} confidentiality for evidence with UUID {evidence_uuid}",
            json={"confidential": confidential},
        )

    def update_evidence_tag(self, evidence_uuid: str, tag: str) -> None:
        """Sets the tag of an evidence record."""
        require(evidence_uuid, "Evidence UUID")
        require(tag, "Tag")
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/update-tag",
            f"Failed to update tag for evidence with UUID {evidence_uuid}",
            json={"tag": tag},
        )

    def classify_evidence(self, evidence_uuid: str, classification: ClassificationFlag) -> None:
        """Classifies an evidence record, training the server's classifier with its content."""
        require(evidence_uuid, "Evidence UUID")
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/classify",
            f"Failed to classify evidence with UUID {evidence_uuid}",
            json={"classification_flag": classification},
        )

    def search_evidence(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Searches evidence records."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "evidence/search", f"Failed to search evidence, query: {query}", params=params
        )
        return parse_list(EvidenceRecord, data)

    def add_evidence_to_report(self, evidence_uuid: str, report_uuid: str) -> None:
        """Links an evidence record to a report."""
        require(evidence_uuid, "Evidence UUID")
        require(report_uuid, "Report UUID")
        self._request(
            "PATCH",
            f"evidence/{path_segment(evidence_uuid)}/link-report",
            f"Failed to link evidence {evidence_uuid} to report {report_uuid}",
            json={"report_uuid": report_uuid},
        )

    def delete_report(self, report_uuid: str) -> None:
        """Deletes a report."""
        require(report_uuid, "Report UUID")
        self._request(
            "DELETE",
            f"reports/{path_segment(report_uuid)}",
            f"Failed to delete report {report_uuid}",
        )

    def submit_report(
        self,
        reporting_entity: str,
        evidence: str | ContentInput | Sequence[ContentInput],
        incident_type: IncidentType,
        report_message: str | None = None,
    ) -> ReportSubmission:
        """Reports an entity, creating an evidence record for each piece of evidence.

        Args:
            reporting_entity: The entity being reported.
            evidence: The text, content input or content inputs documenting the incident.
            incident_type: The type of the incident.
            report_message: A description of the incident.
        """
        require(reporting_entity, "Reporting entity identifier")
        if isinstance(evidence, str):
            require(evidence, "Content")

        payload = compact(
            reporting_entity=reporting_entity,
            evidence=evidence_payload(evidence),
            incident_type=incident_type,
            report_message=report_message,
        )
        data = self._request("POST", "reports", "Failed to submit report", json=payload)
        return ReportSubmission.model_validate(data)

    def list_reports(
        self,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists reports."""
        params = page_params(page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "reports",
            f"Failed to list reports, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def list_opened_reports(
        self,
        page: int = 1,
        limit: int = 100,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Lists the opened reports assigned to the authenticated operator."""
        params = page_params(page, limit, by=by, order=order)
        data = self._request(
            "GET",
            "reports/opened",
            f"Failed to list opened reports, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(ReportRecord, data)

    def get_report(self, report_uuid: str) -> ReportRecord:
        """Returns a report by its UUID."""
        require(report_uuid, "Report UUID")
        data = self._request(
            "GET", f"reports/{path_segment(report_uuid)}", f"Failed to get report {report_uuid}"
        )
        return ReportRecord.model_validate(data)

    def list_report_evidence_records(
        self,
        report_uuid: str,
        page: int = 1,
        limit: int = 100,
        include_confidential: bool = False,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[EvidenceRecord]:
        """Lists the evidence records of a report."""
        require(report_uuid, "Report UUID")
        params = page_params(
            page,
            limit,
            include_confidential=include_confidential,
            category=category,
            by=by,
            order=order,
        )
        data = self._request(
            "GET",
            f"reports/{path_segment(report_uuid)}/evidence",
            f"Failed to list evidence records for report {report_uuid}",
            params=params,
        )
        return parse_list(EvidenceRecord, data)

    def close_report(
        self,
        report_uuid: str,
        classification: ClassificationFlag | None = None,
        blacklist_incident_type: IncidentType | None = None,
        blacklist_expires: int | None = None,
    ) -> None:
        """Closes a report assigned to the authenticated operator.

        Args:
            report_uuid: The report to close.
            classification: A classification to assign to the evidence records of the report.
            blacklist_incident_type: The incident type to blacklist the reported entity with, or
                None to close the report without blacklisting it.
            blacklist_expires: When the blacklist expires, or None for a permanent blacklist.
        """
        require(report_uuid, "Report UUID")
        payload = compact(
            classification_flag=classification,
            blacklist_incident_type=blacklist_incident_type,
            blacklist_expires=blacklist_expires,
        )
        self._request(
            "PATCH",
            f"reports/{path_segment(report_uuid)}/close",
            f"Failed to close report {report_uuid}",
            json=payload,
        )

    def assign_operator_to_report(self, report_uuid: str, operator_uuid: str | None = None) -> None:
        """Assigns a report to an operator, or to the authenticated operator if none is given."""
        require(report_uuid, "Report UUID")
        if operator_uuid is not None:
            require(operator_uuid, "Operator UUID")

        self._request(
            "PATCH",
            f"reports/{path_segment(report_uuid)}/assign",
            f"Failed to assign an operator to report {report_uuid}",
            json=compact(operator=operator_uuid),
        )

    def search_reports(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[ReportRecord]:
        """Searches reports."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET", "reports/search", f"Failed to search reports, query: {query}", params=params
        )
        return parse_list(ReportRecord, data)

    def blacklist_entity(
        self,
        entity_identifier: str,
        incident_type: IncidentType,
        report_uuid: str | None = None,
        expires: int | None = None,
    ) -> str:
        """Blacklists an entity, returning the UUID of the blacklist record.

        Args:
            entity_identifier: The entity to blacklist.
            incident_type: The type of the incident the entity is blacklisted for.
            report_uuid: The report supporting the decision.
            expires: When the blacklist expires, or None for a permanent blacklist.
        """
        require(entity_identifier, "Entity identifier")
        if expires is not None and expires < 0:
            raise ValueError("The expires parameter must be a positive integer or None")

        payload = compact(
            entity_identifier=entity_identifier,
            type=incident_type,
            report_uuid=report_uuid,
            expires=expires,
        )
        blacklist_uuid: str = self._request(
            "POST", "blacklist", f"Failed to blacklist entity {entity_identifier}", json=payload
        )
        return blacklist_uuid

    def delete_blacklist_record(self, blacklist_record_uuid: str) -> None:
        """Deletes a blacklist record."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        self._request(
            "DELETE",
            f"blacklist/{path_segment(blacklist_record_uuid)}",
            f"Failed to delete blacklist record with UUID {blacklist_record_uuid}",
        )

    def get_blacklist_record(self, blacklist_record_uuid: str) -> BlacklistRecord:
        """Returns a blacklist record by its UUID."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        data = self._request(
            "GET",
            f"blacklist/{path_segment(blacklist_record_uuid)}",
            f"Failed to get blacklist record with UUID {blacklist_record_uuid}",
        )
        return BlacklistRecord.model_validate(data)

    def lift_blacklist_record(self, blacklist_record_uuid: str) -> None:
        """Lifts a blacklist record, ending it before it expires."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        self._request(
            "PATCH",
            f"blacklist/{path_segment(blacklist_record_uuid)}/lift",
            f"Failed to lift blacklist record with UUID {blacklist_record_uuid}",
        )

    def extend_blacklist_record(self, blacklist_record_uuid: str, seconds: int) -> None:
        """Extends the expiry of a temporary blacklist record by a number of seconds."""
        require(blacklist_record_uuid, "Blacklist record UUID")
        if seconds <= 0:
            raise ValueError("Extension seconds must be positive")

        self._request(
            "PATCH",
            f"blacklist/{path_segment(blacklist_record_uuid)}/extend",
            f"Failed to extend blacklist record with UUID {blacklist_record_uuid}",
            json={"seconds": seconds},
        )

    def list_blacklist_records(
        self,
        page: int = 1,
        limit: int = 100,
        include_lifted: bool = False,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[BlacklistRecord]:
        """Lists blacklist records."""
        params = page_params(
            page,
            limit,
            include_lifted=include_lifted,
            category=category,
            by=by,
            order=order,
        )
        data = self._request(
            "GET",
            "blacklist",
            f"Failed to list blacklist records, page: {page}, limit: {limit}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)

    def search_blacklist(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        category: str | None = None,
        by: str | None = None,
        order: str | None = None,
    ) -> list[BlacklistRecord]:
        """Searches blacklist records."""
        params = search_params(query, page, limit, category=category, by=by, order=order)
        data = self._request(
            "GET",
            "blacklist/search",
            f"Failed to search blacklist records, query: {query}",
            params=params,
        )
        return parse_list(BlacklistRecord, data)
