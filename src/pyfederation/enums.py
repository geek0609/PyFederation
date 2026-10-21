from enum import StrEnum
from typing import Self


class AuditLogType(StrEnum):
    """Every type of event that can appear in the Federation audit log.

    A type this client does not recognize is read as OTHER.
    """

    OPERATOR_CREATED = "OPERATOR_CREATED"
    OPERATOR_DELETED = "OPERATOR_DELETED"
    OPERATOR_DISABLED = "OPERATOR_DISABLED"
    OPERATOR_ENABLED = "OPERATOR_ENABLED"
    OPERATOR_UPDATED = "OPERATOR_UPDATED"
    ATTACHMENT_UPLOADED = "ATTACHMENT_UPLOADED"
    ATTACHMENT_DELETED = "ATTACHMENT_DELETED"
    EVIDENCE_SUBMITTED = "EVIDENCE_SUBMITTED"
    EVIDENCE_UPDATED = "EVIDENCE_UPDATED"
    EVIDENCE_DELETED = "EVIDENCE_DELETED"
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_SUBMITTED = "REPORT_SUBMITTED"
    REPORT_OPERATOR_ASSIGNED = "REPORT_OPERATOR_ASSIGNED"
    REPORT_CLOSED = "REPORT_CLOSED"
    REPORT_DELETED = "REPORT_DELETED"
    ENTITY_DELETED = "ENTITY_DELETED"
    ENTITY_BLACKLISTED = "ENTITY_BLACKLISTED"
    ENTITY_PUSHED = "ENTITY_PUSHED"
    ENTITY_UPDATED = "ENTITY_UPDATED"
    BLACKLIST_DELETED = "BLACKLIST_DELETED"
    BLACKLIST_LIFTED = "BLACKLIST_LIFTED"
    BLACKLIST_EXTENDED = "BLACKLIST_EXTENDED"
    OTHER = "OTHER"

    @classmethod
    def _missing_(cls, value: object) -> Self:
        return cls.OTHER


class ClassificationFlag(StrEnum):
    """Classification assigned to scanned content or evidence."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    NORMAL = "NORMAL"


class EntityRelationshipType(StrEnum):
    """Nature of a relationship between two entities."""

    ALTERNATIVE = "ALTERNATIVE"
    PROXY = "PROXY"
    CHILD = "CHILD"


class IncidentType(StrEnum):
    """Categories of security incidents attached to blacklist records and reports.

    An incident type this client does not recognize is read as OTHER.
    """

    SPAM = "SPAM"
    SCAM = "SCAM"
    SERVICE_ABUSE = "SERVICE_ABUSE"
    ILLEGAL_CONTENT = "ILLEGAL_CONTENT"
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    ADVERTISING = "ADVERTISING"
    TRACKING = "TRACKING"
    OTHER = "OTHER"

    @classmethod
    def _missing_(cls, value: object) -> Self:
        return cls.OTHER


class NamedEntityType(StrEnum):
    """Type of a named entity extracted during content scanning."""

    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    TELEPHONE = "telephone"


class RecordType(StrEnum):
    """Types of records that can be stored, searched and retrieved from a Federation server."""

    ENTITY = "ENTITY"
    EVIDENCE = "EVIDENCE"
    BLACKLIST = "BLACKLIST"
    REPORT = "REPORT"
    ATTACHMENT = "ATTACHMENT"
    AUDIT_LOG = "AUDIT_LOG"
    OPERATOR = "OPERATOR"


class SuggestedAction(StrEnum):
    """Recommended action for an entity, based on its assessed risk."""

    BLOCK_CONTENT = "BLOCK_CONTENT"
    TEMPORARILY_BLOCK_ENTITY = "TEMPORARILY_BLOCK_ENTITY"
    PERMANENTLY_BLOCK_ENTITY = "PERMANENTLY_BLOCK_ENTITY"
    CAUTION = "CAUTION"
