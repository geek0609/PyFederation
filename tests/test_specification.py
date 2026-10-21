"""Checks the clients against the OpenAPI specification of FederationLib.

The specification in fixtures/ is the one FederationLib 2.0.0 serves at /specification.
"""

import json
from enum import StrEnum
from pathlib import Path
from typing import Any

import pytest

from pyfederation import (
    AsyncFederationClient,
    ClassificationFlag,
    ContentType,
    EntityRelationshipType,
    FederationClient,
    IncidentType,
    NamedEntityType,
    RecordType,
    SuggestedAction,
)

SPECIFICATION = json.loads(
    (Path(__file__).parent / "fixtures" / "specification.json").read_text(encoding="utf-8")
)

OPERATIONS = {
    ("GET", "/"): "list_audit_logs",
    ("GET", "/audit/search"): "search_audit_logs",
    ("GET", "/audit/{uuid}"): "get_audit_log_record",
    ("GET", "/info"): "get_server_information",
    ("GET", "/specification"): "get_specification",
    ("GET", "/search"): "search",
    ("POST", "/scan"): "scan_content",
    ("GET", "/operators"): "list_operators",
    ("POST", "/operators"): "create_operator",
    ("POST", "/operators/refresh"): "generate_access_token",
    ("GET", "/operators/search"): "search_operators",
    ("GET", "/operators/self"): "get_self",
    ("GET", "/operators/{uuid}"): "get_operator",
    ("DELETE", "/operators/{uuid}"): "delete_operator",
    ("GET", "/operators/{uuid}/audit"): "list_operator_audit_logs",
    ("GET", "/operators/{uuid}/blacklist"): "list_operator_blacklist",
    ("PATCH", "/operators/{uuid}/configuration"): "update_operator_configuration",
    ("PATCH", "/operators/{uuid}/disable"): "disable_operator",
    ("PATCH", "/operators/{uuid}/enable"): "enable_operator",
    ("GET", "/operators/{uuid}/evidence"): "list_operator_evidence",
    ("PATCH", "/operators/{uuid}/permissions"): "update_operator_permissions",
    ("POST", "/operators/{uuid}/refresh"): "generate_operator_access_token",
    ("GET", "/operators/{uuid}/reports"): "list_operator_reports",
    ("GET", "/operators/{uuid}/reports/assigned"): "list_assigned_operator_reports",
    ("PATCH", "/operators/{uuid}/update-name"): "update_operator_name",
    ("GET", "/entities"): "list_entities",
    ("POST", "/entities"): "push_entity",
    ("GET", "/entities/search"): "search_entities",
    ("GET", "/entities/top-threats"): "get_top_threats",
    ("GET", "/entities/{identifier}"): "get_entity_record",
    ("DELETE", "/entities/{identifier}"): "delete_entity",
    ("PATCH", "/entities/{identifier}"): "update_entity",
    ("GET", "/entities/{identifier}/audit"): "list_entity_audit_logs",
    ("GET", "/entities/{identifier}/blacklist"): "list_entity_blacklist_records",
    ("PATCH", "/entities/{identifier}/clear-reputation"): "clear_entity_reputation",
    ("GET", "/entities/{identifier}/evidence"): "list_entity_evidence_records",
    ("GET", "/entities/{identifier}/query"): "query_entity",
    ("PATCH", "/entities/{identifier}/relationship"): "set_entity_relationship",
    ("DELETE", "/entities/{identifier}/relationship"): "clear_entity_relationship",
    ("GET", "/entities/{identifier}/reports"): "list_entity_reports",
    ("PATCH", "/entities/{identifier}/whitelist"): "set_entity_whitelist",
    ("GET", "/evidence"): "list_evidence",
    ("POST", "/evidence"): "submit_evidence",
    ("GET", "/evidence/search"): "search_evidence",
    ("GET", "/evidence/{uuid}"): "get_evidence_record",
    ("DELETE", "/evidence/{uuid}"): "delete_evidence",
    ("GET", "/evidence/{uuid}/attachments"): "get_evidence_attachments",
    ("PATCH", "/evidence/{uuid}/classify"): "classify_evidence",
    ("PATCH", "/evidence/{uuid}/link-report"): "add_evidence_to_report",
    ("PATCH", "/evidence/{uuid}/update-confidentiality"): "update_evidence_confidentiality",
    ("PATCH", "/evidence/{uuid}/update-tag"): "update_evidence_tag",
    ("GET", "/reports"): "list_reports",
    ("POST", "/reports"): "submit_report",
    ("GET", "/reports/opened"): "list_opened_reports",
    ("GET", "/reports/search"): "search_reports",
    ("GET", "/reports/{uuid}"): "get_report",
    ("DELETE", "/reports/{uuid}"): "delete_report",
    ("PATCH", "/reports/{uuid}/assign"): "assign_operator_to_report",
    ("PATCH", "/reports/{uuid}/close"): "close_report",
    ("GET", "/reports/{uuid}/evidence"): "list_report_evidence_records",
    ("GET", "/blacklist"): "list_blacklist_records",
    ("POST", "/blacklist"): "blacklist_entity",
    ("GET", "/blacklist/search"): "search_blacklist",
    ("GET", "/blacklist/{uuid}"): "get_blacklist_record",
    ("DELETE", "/blacklist/{uuid}"): "delete_blacklist_record",
    ("PATCH", "/blacklist/{uuid}/extend"): "extend_blacklist_record",
    ("PATCH", "/blacklist/{uuid}/lift"): "lift_blacklist_record",
    ("GET", "/attachments"): "list_attachments",
    ("POST", "/attachments"): "upload_file_attachment",
    # PUT is an alias of POST for uploading attachments
    ("PUT", "/attachments"): "upload_file_attachment",
    ("GET", "/attachments/search"): "search_attachments",
    ("GET", "/attachments/{uuid}"): "download_attachment",
    ("DELETE", "/attachments/{uuid}"): "delete_attachment",
    ("GET", "/attachments/{uuid}/info"): "get_attachment_info",
}


def test_every_operation_is_implemented() -> None:
    operations = {
        (method.upper(), path)
        for path, methods in SPECIFICATION["paths"].items()
        for method in methods
    }
    assert operations == OPERATIONS.keys()


@pytest.mark.parametrize("client_type", [FederationClient, AsyncFederationClient])
@pytest.mark.parametrize("method", sorted(set(OPERATIONS.values())))
def test_client_implements(client_type: type, method: str) -> None:
    assert callable(getattr(client_type, method, None))


def request_property(path: str, method: str, name: str) -> Any:
    content = SPECIFICATION["paths"][path][method]["requestBody"]["content"]
    return content["application/json"]["schema"]["properties"][name]


def query_parameter(path: str, method: str, name: str) -> Any:
    parameters = SPECIFICATION["paths"][path][method]["parameters"]
    return next(parameter for parameter in parameters if parameter["name"] == name)["schema"]


def record_property(record: str, name: str) -> Any:
    return SPECIFICATION["components"]["schemas"][record]["properties"][name]


@pytest.mark.parametrize(
    ("enum", "schema"),
    [
        (IncidentType, request_property("/blacklist", "post", "type")),
        (IncidentType, request_property("/reports", "post", "incident_type")),
        (
            IncidentType,
            request_property("/reports/{uuid}/close", "patch", "blacklist_incident_type"),
        ),
        (
            ClassificationFlag,
            request_property("/reports/{uuid}/close", "patch", "classification_flag"),
        ),
        (
            ClassificationFlag,
            request_property("/evidence/{uuid}/classify", "patch", "classification_flag"),
        ),
        (
            EntityRelationshipType,
            request_property("/entities/{identifier}/relationship", "patch", "relationship_type"),
        ),
        (RecordType, query_parameter("/search", "get", "type")),
        (SuggestedAction, record_property("EntityQueryResult", "suggested_action")),
        (IncidentType, request_property("/scan", "post", "concerns")["items"]),
        (IncidentType, record_property("Detection", "concern")),
        (ContentType, record_property("ContentInput", "content_type")),
        (NamedEntityType, record_property("ResolvedEntityPosition", "type")),
        (ContentType, record_property("ServerInformation", "scan_content_types")["items"]),
        (IncidentType, record_property("ServerInformation", "concerns")["items"]),
    ],
)
def test_enums_cover_the_specification(enum: type[StrEnum], schema: Any) -> None:
    # The server compares enum values case-insensitively
    specified = {value.upper() for value in schema["enum"] if value is not None}
    assert specified <= {value.upper() for value in enum}
