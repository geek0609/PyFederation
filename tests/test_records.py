from typing import Any

import pytest

from pyfederation.enums import NamedEntityType, RecordType
from pyfederation.records import (
    AuditLog,
    EntityRecord,
    EvidenceRecord,
    OperatorCreated,
    OperatorRecord,
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
