"""Sample server responses."""

from typing import Any

ENTITY_UUID = "0198f41f-3b3a-7c52-8f3e-3c1bd1b0b6a1"
EVIDENCE_UUID = "0198f41f-5d0e-7a8b-9c1d-2e3f4a5b6c7d"
OPERATOR_UUID = "0198f41f-0000-7000-8000-000000000000"
AUDIT_LOG_UUID = "0198f41f-9999-7000-8000-000000000000"
BLACKLIST_UUID = "0198f41f-7777-7000-8000-000000000000"
REPORT_UUID = "0198f41f-8888-7000-8000-000000000000"
TIMESTAMP = 1735689600


def entity(**overrides: Any) -> dict[str, Any]:
    return {
        "uuid": ENTITY_UUID,
        "hash": "b" * 64,
        "host": "example.com",
        "id": "john",
        "metadata": None,
        "whitelisted": False,
        "reputation": 0,
        "reputation_last_updated": None,
        "relationship_entity": None,
        "relationship_type": None,
        "created": TIMESTAMP,
        "updated": TIMESTAMP,
        **overrides,
    }


def evidence(**overrides: Any) -> dict[str, Any]:
    return {
        "uuid": EVIDENCE_UUID,
        "entity": ENTITY_UUID,
        "operator": OPERATOR_UUID,
        "confidential": False,
        "text_content": "Buy cheap watches",
        "note": None,
        "tag": "spam",
        "report": None,
        "metadata": {"source": "telegram"},
        "classification_flag": "SUSPICIOUS",
        "created": TIMESTAMP,
        "updated": TIMESTAMP,
        **overrides,
    }


def audit_log(**overrides: Any) -> dict[str, Any]:
    return {
        "uuid": AUDIT_LOG_UUID,
        "operator": OPERATOR_UUID,
        "entity": ENTITY_UUID,
        "blacklist": None,
        "evidence": None,
        "file_attachment": None,
        "type": "ENTITY_PUSHED",
        "message": "Entity pushed",
        "timestamp": TIMESTAMP,
        **overrides,
    }


def operator(**overrides: Any) -> dict[str, Any]:
    return {
        "uuid": OPERATOR_UUID,
        "name": "root",
        "disabled": False,
        "client_permissions": True,
        "management_permissions": True,
        "operator_permissions": True,
        "auto_assign": False,
        "created": TIMESTAMP,
        "updated": TIMESTAMP,
        **overrides,
    }


def blacklist(**overrides: Any) -> dict[str, Any]:
    return {
        "uuid": BLACKLIST_UUID,
        "operator": OPERATOR_UUID,
        "entity": ENTITY_UUID,
        "report": REPORT_UUID,
        "type": "SPAM",
        "lifted": False,
        "lifted_by": None,
        "expires": TIMESTAMP + 86400,
        "created": TIMESTAMP,
        **overrides,
    }


def report(**overrides: Any) -> dict[str, Any]:
    return {
        "uuid": REPORT_UUID,
        "submitting_operator": OPERATOR_UUID,
        "reporting_entity": ENTITY_UUID,
        "assigned_operator": None,
        "automated": False,
        "incident_type": "SPAM",
        "opened": True,
        "message": "Sends unsolicited advertisements",
        "created": TIMESTAMP,
        "updated": TIMESTAMP,
        **overrides,
    }


def server_information() -> dict[str, Any]:
    return {
        "name": "Federation Server",
        "api_version": "2026.1",
        "public_audit_logs": True,
        "public_evidence": True,
        "public_blacklist": True,
        "public_entities": True,
        "public_reports": False,
        "public_entity_metadata": False,
        "public_scan_content": False,
        "public_query_entity": True,
        "search_enabled": True,
        "public_search": True,
        "search_types": ["ENTITY", "EVIDENCE"],
        "public_search_types": ["ENTITY"],
        "public_audit_logs_visibility": ["ENTITY_PUSHED"],
        "audit_log_records": 10,
        "blacklist_records": 2,
        "known_entities": 5,
        "evidence_records": 3,
        "file_attachment_records": 0,
        "operators": 1,
        "reports": 1,
    }
