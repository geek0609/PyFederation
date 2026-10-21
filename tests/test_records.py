from typing import Any

import pytest

from pyfederation.enums import AuditLogType, IncidentType, NamedEntityType, RecordType
from pyfederation.records import (
    AuditLog,
    BlacklistRecord,
    EntityQueryResult,
    EntityRecord,
    EvidenceRecord,
    OperatorCreated,
    OperatorRecord,
    ResolvedEntityPosition,
    ScannedContent,
    SearchResult,
    ServerInformation,
)

from . import payloads


def test_entity_metadata_is_decoded_from_json_string() -> None:
    record = EntityRecord.model_validate(payloads.entity(metadata='{"platform": "telegram"}'))
    assert record.metadata == {"platform": "telegram"}


def test_entity_metadata_accepts_an_object() -> None:
    record = EntityRecord.model_validate(payloads.entity(metadata={"platform": "telegram"}))
    assert record.metadata == {"platform": "telegram"}


@pytest.mark.parametrize(
    ("host", "id", "telephone"),
    [
        ("e164.arpa", "14155550123", True),
        ("E164.ARPA", "14155550123", True),
        ("e164.arpa", None, False),
        ("example.com", "14155550123", False),
    ],
)
def test_entity_is_telephone(host: str, id: str | None, telephone: bool) -> None:
    assert EntityRecord.model_validate(payloads.entity(host=host, id=id)).is_telephone is telephone


def test_unknown_fields_are_ignored() -> None:
    record = EntityRecord.model_validate(payloads.entity(introduced_later=True))
    assert not hasattr(record, "introduced_later")


@pytest.mark.parametrize(
    ("record_type", "payload", "expected"),
    [
        (RecordType.ENTITY, payloads.entity(), EntityRecord),
        (RecordType.EVIDENCE, payloads.evidence(), EvidenceRecord),
        (RecordType.AUDIT_LOG, payloads.audit_log(), AuditLog),
        (RecordType.OPERATOR, payloads.operator(), OperatorRecord),
    ],
)
def test_search_result_record_is_typed_by_record_type(
    record_type: RecordType, payload: dict[str, Any], expected: type
) -> None:
    result = SearchResult.model_validate({"type": record_type, "record": payload})
    assert isinstance(result.record, expected)


def test_scanned_content_resolves_nested_entities() -> None:
    content = ScannedContent.model_validate(
        {
            "author_entity": None,
            "resolved_entities": [
                {
                    "entity": payloads.entity(host="spam.example"),
                    "entity_position": {"offset": 10, "length": 12, "type": "domain"},
                    "active_blacklists": [],
                    "parent_entity": {
                        "entity": payloads.entity(),
                        "entity_position": None,
                        "active_blacklists": [],
                        "parent_entity": None,
                    },
                }
            ],
            "classification": None,
            "scan_results": {},
            "risk_score": 0,
        }
    )

    resolved = content.resolved_entities[0]
    assert resolved.entity_position is not None
    assert resolved.entity_position.type is NamedEntityType.DOMAIN
    assert resolved.parent_entity is not None
    assert resolved.parent_entity.entity.host == "example.com"


def test_unrecognized_incident_and_audit_log_types_are_read_as_other() -> None:
    assert BlacklistRecord.model_validate(payloads.blacklist(type="NEW")).type is IncidentType.OTHER
    assert AuditLog.model_validate(payloads.audit_log(type="NEW")).type is AuditLogType.OTHER


def test_other_unrecognized_values_are_read_as_none() -> None:
    entity = EntityRecord.model_validate(payloads.entity(relationship_type="NEW"))
    position = ResolvedEntityPosition.model_validate({"offset": 0, "length": 4, "type": "new"})
    query = EntityQueryResult.model_validate(
        {
            "entity_record": payloads.entity(),
            "related_entities": [],
            "active_blacklists": [],
            "suggested_action": "NEW",
        }
    )

    assert entity.relationship_type is None
    assert position.type is None
    assert query.suggested_action is None


def test_unrecognized_values_are_left_out_of_lists() -> None:
    payload = payloads.server_information()
    payload["search_types"] = ["ENTITY", "NEW"]

    assert ServerInformation.model_validate(payload).search_types == [RecordType.ENTITY]


@pytest.mark.parametrize(("published", "allowed"), [(None, True), (True, True), (False, False)])
def test_illegal_content_is_allowed_unless_the_server_declines_it(
    published: bool | None, allowed: bool
) -> None:
    payload = payloads.server_information()
    if published is not None:
        payload["allow_illegal_content"] = published

    assert ServerInformation.model_validate(payload).illegal_content_allowed is allowed


def test_access_tokens_are_left_out_of_the_representation() -> None:
    created = OperatorCreated.model_validate(
        {"uuid": payloads.OPERATOR_UUID, "access_token": "secret-token"}
    )

    assert "secret-token" not in repr(created)
