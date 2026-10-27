# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-21

This release follows version `2.0` of the OFD Specification and [JFederation](https://github.com/nosial/JFederation)
2.0.1, it is not compatible with servers implementing OFD 1.x.

### Breaking
 - `OperatorRecord` carries its permission groups in `permissions` (`OperatorPermissions`: `client`, `management`,
   `operator`) and its settings in `configuration` (`OperatorConfiguration`: `auto_assign_reports`,
   `auto_assign_automated_reports`, `is_bot`), replacing `client_permissions`, `management_permissions`,
   `operator_permissions` and `auto_assign`. `configuration` is `None` when the server does not disclose it, which it
   only does to the operator itself and to operators with operator permissions; the `auto_assign_reports`,
   `auto_assign_automated_reports`, `auto_assigned` and `is_bot` properties read it
 - `set_operator_permissions()`, `set_client_permissions()` and `set_management_permissions()` use
   `PATCH /operators/{uuid}/permissions`, and `set_auto_assign()` uses `PATCH /operators/{uuid}/configuration` and opts
   in to (or out of) both ordinary and automated reports. Granting management permissions also grants client
   permissions, which they inherit, so revoking client permissions from an operator that keeps management permissions
   is rejected with HTTP 409
 - `ContentClassification.classification_flag` and `ResolvedEntityPosition.type` are `None` when the server returns a
   value this client does not recognize
 - Ordering values for `by` are sent uppercase (e.g. `CREATED`) as OFD 2.0 defines, instead of lowercase
 - Search queries must contain at least 2 non-whitespace characters

### Added
 - `update_operator_permissions()` and `update_operator_configuration()`, which take partial updates (`None` leaves a
   member unchanged) and return the updated object, and `set_bot()`
 - Content types: `ContentType` (`TEXT`, `EMAIL`, `SMS`, `WEB_PAGE`, `HOSTNAME`, `URL`), the `content_type` and
   `context` of `ContentInput` and `EvidenceRecord`, and the `content_type` and `context` arguments of
   `submit_evidence()`
 - Concerns: the `concerns` argument of `scan_content()` and `query_entity()`, which assess only the given incident
   types
 - `ScannedContent.detections` and the `Detection` record
 - `ADVERTISING` and `TRACKING` incident types, and the `TELEPHONE` named entity type
 - The `types` argument of `list_blacklist_records()` and `search_blacklist()`, which filter blacklist records by
   incident type
 - `EvidenceRecord.automated`: evidence created by the server or submitted by a bot operator is automated and created
   confidential
 - `AuditLog.report`, the report an audit log entry refers to
 - `EntityRecord.is_telephone` and `EntityRecord.TELEPHONE_ENTITY_HOST`
 - `ServerInformation` members `public_telephone_entities`, `collects_public_scan_content`, `allow_url_uploads`,
   `scan_content_types`, `concerns` and `default_concerns`, with the `url_uploads_allowed` and `api_major_version`
   properties
 - `upload_file_attachment_by_url()` to upload an attachment by URL, the server retrieves the file from the URL
   itself. `upload_file_attachment_from_url()` still downloads the file and uploads it

### Changed
 - Entity identifiers are percent-encoded in request paths, so entity addresses containing `+`, `%`, `#` or other
   reserved characters reach the server unchanged
 - Values a server publishes that this client does not recognize, which a minor version of OFD may add, are
   tolerated: an unrecognized incident type or audit log type is read as `OTHER`, other unrecognized values are read
   as `None` and left out of lists, and search results of an unrecognized record type are left out
 - `classify_evidence()` replaces the classification of evidence that is already classified, as OFD 2.0 defines
 - The report supporting a blacklist record may concern another entity than the one being blacklisted, and
   `blacklist_entity()` rejects an empty report UUID
 - `FileAttachmentRecord.evidence` is `None` instead of an empty string when the server reports no associated
   evidence record
 - `download_attachment()` never replaces an existing file or symbolic link, raising `ValueError` instead as
   FederationLib's client does, and removes the partial file of a download that fails


## [1.0.0] - 2026-10-13

The first release, a port of [JFederation](https://github.com/nosial/JFederation) 1.0.13. This release follows
version `v1.0-R4` of the OFD Specification.

### Added
 - `FederationClient` and `AsyncFederationClient`, covering every method of the Federation server API: server
   information, search, content scanning, audit logs, operators, entities, evidence, reports, blacklist records and
   file attachments.
 - Records and enums for every object the server returns.
 - `FederationClientException`, raised for every failed request with the HTTP status code and the server's message.
