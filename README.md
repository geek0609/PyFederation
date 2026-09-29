# PyFederation

PyFederation is a Python client library for the Federated Database protocol. It implements the
[Open Federated Database](https://github.com/nosial/OFD-Specification) specification and follows the design of the
reference implementation, [FederationLib](https://github.com/nosial/FederationLib), and of its Java counterpart,
[JFederation](https://github.com/nosial/JFederation), from which it is ported.

## Features

- Works with any OFD-compliant Federation server
- Content scanning with entity resolution, classification, and risk assessment
- Every method of the server API: operators, records, evidence, reports, blacklist records, file
  attachments, audit logs, search, and server information
- Pagination, category filters, and sorting on every listing and search endpoint
- Synchronous and asynchronous clients, `FederationClient` and `AsyncFederationClient`, with the same methods
- All errors are mapped to a single exception carrying the HTTP status code and server message

## Table of Contents

<!-- TOC -->
* [PyFederation](#pyfederation)
  * [Features](#features)
  * [Table of Contents](#table-of-contents)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
  * [Usage](#usage)
    * [Connecting to a server](#connecting-to-a-server)
    * [Asynchronous client](#asynchronous-client)
    * [Content scanning](#content-scanning)
    * [Searching records](#searching-records)
    * [Operators](#operators)
    * [Entities](#entities)
    * [Evidence](#evidence)
    * [Reports](#reports)
    * [Blacklist records](#blacklist-records)
    * [File attachments](#file-attachments)
    * [Pagination and sorting](#pagination-and-sorting)
  * [Error handling](#error-handling)
  * [Testing](#testing)
* [License](#license)
<!-- TOC -->

## Prerequisites

- **Python 3.11 or newer**
- **A running Federation server** for anything other than constructing a client, the reference
  implementation is [FederationLib](https://github.com/nosial/FederationLib), which includes a
  dockerized server deployment

Dependencies are HTTPX for HTTP transport and Pydantic for the records.

## Installation

To use the library, install it from the source of this repository:

```sh
pip install .
```

## Usage

All functionality is exposed through the `FederationClient` class. Each method maps to a REST endpoint of the
Federation server and handles serialization, authentication, and error mapping.

### Connecting to a server

A client is constructed with the base URL of the Federation server and an optional operator access
token. A client without a token operates anonymously against the server's public endpoints:

```python
from pyfederation import FederationClient

# Anonymous client
client = FederationClient("https://federation.example.com")

# Authenticated client with an operator access token
client = FederationClient("https://federation.example.com", "access-token")
```

The access token can be changed at any time during the lifetime of the client:

```python
client.access_token = "new-token"  # switch authentication
client.access_token = None  # revert to anonymous access
```

Clients should be closed when no longer needed to release the underlying HTTP connection pool, or
used as a context manager:

```python
client.close()

with FederationClient("https://federation.example.com", "access-token") as client:
    ...
```

For custom HTTP settings (timeouts, proxies, TLS, etc.) an existing `httpx.Client` can be passed to
the constructor instead:

```python
import httpx

http_client = httpx.Client(timeout=15)

client = FederationClient("https://federation.example.com", "access-token", http_client)
```

Server information, including the server name, API version, feature flags (which record types are
publicly visible), and total record counts, is available through `get_server_information()`, the raw
OpenAPI specification of the server is available through `get_specification()`:

```python
info = client.get_server_information()
print(f"Server {info.name}, API version {info.api_version}")
print(f"Known entities: {info.known_entities}, reports: {info.reports}")
```

### Asynchronous client

`AsyncFederationClient` has the same methods as `FederationClient`, as coroutines, and is closed with
`aclose()` or used as an async context manager:

```python
from pyfederation import AsyncFederationClient

async with AsyncFederationClient("https://federation.example.com", "access-token") as client:
    info = await client.get_server_information()
```

### Content scanning

Content scanning accepts text, a `ContentInput`, or a list of inputs. Each input can carry text, an
operator note, tag, confidentiality flag, and metadata; at least one input must contain text:

| Method                                             | Return Type      | Description                      |
|----------------------------------------------------|------------------|----------------------------------|
| `scan_content(evidence, author, top_k, threshold)` | `ScannedContent` | Scans one or more content inputs |

Scanning content and inspecting the classification result:

```python
from pyfederation import ContentInput

scan = client.scan_content(ContentInput("Suspicious message to inspect"), "author@example.com")

classification = scan.classification
print(
    f"Classification {classification.classification_flag} with "
    f"{classification.confidence:.1%} confidence, detected language: {classification.detected_language}"
)
```

### Searching records

The global search queries all record types with an optional type filter. The search query must be at
least 2 characters:

```python
from pyfederation import RecordType

# Search all record types
results = client.search("author@example.com")

# Search only entity and blacklist records, page 1, 25 per page
results = client.search("author@example.com", [RecordType.ENTITY, RecordType.BLACKLIST], 1, 25)
```

`SearchResult` records carry the matched `type` and the `record`, resolved to the record class of
the matched type.

### Operators

Operators are the accounts of the Federation server. Every change to the data is made by an
operator, and each operator holds permissions that decide what it may do.

| Method                                                                           | Description                                                                          |
|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `create_operator(name)`                                                          | Creates a new operator, returns the raw access token (only exposed at creation time) |
| `get_operator(uuid)` / `get_self()`                                              | Returns an operator record / the currently authenticated operator                    |
| `list_operators(page, limit, category, by, order)`                               | Lists operators with optional filters                                                |
| `search_operators(query, page, limit, category, by, order)`                      | Searches operators by name                                                           |
| `update_operator_name(uuid, name)`                                               | Updates the display name of an operator                                              |
| `delete_operator(uuid)`                                                          | Deletes an operator                                                                  |
| `disable_operator(uuid)` / `enable_operator(uuid)`                               | Disables / enables an operator account                                               |
| `set_operator_permissions(uuid, enabled)`                                        | Sets whether the operator has operator-level permissions                             |
| `set_client_permissions(uuid, enabled)`                                          | Sets whether the operator has client-level permissions                               |
| `set_management_permissions(uuid, enabled)`                                      | Sets whether the operator has management-level permissions                           |
| `set_auto_assign(uuid, enabled)`                                                 | Sets whether reports are automatically assigned to the operator                      |
| `generate_access_token(update)`                                                  | Refreshes the current operator's token, optionally updating the client               |
| `generate_operator_access_token(uuid)`                                           | Refreshes another operator's token                                                   |
| `list_operator_audit_logs(uuid, ...)`                                            | Lists the audit log entries of an operator                                           |
| `list_operator_evidence(uuid, ...)`                                              | Lists the evidence an operator submitted                                             |
| `list_operator_blacklist(uuid, ...)`                                             | Lists the blacklist records created by an operator                                   |
| `list_operator_reports(uuid, ...)` / `list_assigned_operator_reports(uuid, ...)` | Lists the reports submitted by / assigned to an operator                             |

Creating an operator and generating a new token:

```python
created = client.create_operator("my-application")
print(f"Operator UUID: {created.uuid}")

# The raw token is only returned once at creation time, store it securely
token = created.access_token

refreshed = client.generate_access_token(True)  # refresh and update this client
```

### Entities

Entities are the subjects tracked by the federation: users, domains, IP addresses, or any other
identifier present in scanned content.

| Method                                                     | Description                                                       |
|------------------------------------------------------------|-------------------------------------------------------------------|
| `get_entity_record(identifier)`                            | Returns the record of an entity by identifier                     |
| `query_entity(identifier)`                                 | Returns an entity's relationship group and active blacklist state |
| `search_entities(query, page, limit, category, by, order)` | Searches entities by identifier                                   |
| `list_entities(page, limit, category, by, order)`          | Lists entities                                                    |
| `get_top_threats(limit)`                                   | Lists the highest-risk entities                                   |
| `update_entity(identifier, metadata)`                      | Updates the metadata of an entity                                 |
| `delete_entity(identifier)`                                | Deletes an entity                                                 |
| `set_entity_whitelist(identifier, whitelisted)`            | (Un)whitelists an entity                                          |
| `clear_entity_reputation(identifier)`                      | Clears the accumulated reputation of an entity                    |
| `set_entity_relationship(identifier, related_id, type)`    | Sets the relationship between two entities                        |
| `clear_entity_relationship(identifier)`                    | Clears the relationship of an entity                              |
| `push_entity(host, id, metadata)`                          | Registers an entity with the server                               |
| `list_entity_audit_logs(identifier, ...)`                  | Lists the audit log entries involving an entity                   |
| `list_entity_blacklist_records(identifier, ...)`           | Lists the blacklist records against an entity                     |
| `list_entity_evidence_records(identifier, ...)`            | Lists the evidence submitted against an entity                    |
| `list_entity_reports(identifier, ...)`                     | Lists the reports submitted against an entity                     |

Entities are identified by their UUID, SHA-256 hash, or address, such as `example.com` or
`john@example.com`.

### Evidence

Evidence records are the supporting data attached to entities, either when submitting a report or
manually by operators, and can hold text content, attachments, tags, notes, and confidentiality
flags:

| Method                                                                                         | Description                                  |
|------------------------------------------------------------------------------------------------|----------------------------------------------|
| `submit_evidence(identifier, text_content, note, tag, confidential, metadata, classification)` | Submits evidence with all optional fields    |
| `list_evidence(page, limit, include_confidential, category, by, order)`                        | Lists evidence records                       |
| `search_evidence(query, page, limit, category, by, order)`                                     | Searches evidence records                    |
| `get_evidence_record(uuid)`                                                                    | Returns a single evidence record             |
| `get_evidence_attachments(uuid)`                                                               | Lists the attachments of an evidence record  |
| `update_evidence_confidentiality(uuid, confidential)`                                          | Updates the confidentiality flag of evidence |
| `update_evidence_tag(uuid, tag)`                                                               | Updates the tag of evidence                  |
| `classify_evidence(uuid, classification)`                                                      | Classifies evidence                          |
| `add_evidence_to_report(evidence_uuid, report_uuid)`                                           | Attaches evidence to a report                |
| `delete_evidence(uuid)`                                                                        | Deletes an evidence record                   |

Confidential evidence is hidden from unauthenticated clients by default, listing endpoints
support an `include_confidential` parameter to include them when the operator has the appropriate
permissions.

### Reports

Reports are the central mechanism of the federation server. A report is submitted against an entity,
groups one or more pieces of evidence, and can be classified, assigned to operators, and closed:

| Method                                                                           | Description                                                                      |
|----------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| `submit_report(entity, evidence, incident_type, report_message)`                 | Submits one or more evidence items with a report                                 |
| `list_reports(page, limit, category, by, order)`                                 | Lists reports                                                                    |
| `list_opened_reports(page, limit, by, order)`                                    | Lists the opened reports assigned to the current operator                        |
| `search_reports(query, page, limit, category, by, order)`                        | Searches reports by content                                                      |
| `get_report(uuid)`                                                               | Returns a single report                                                          |
| `list_report_evidence_records(report_uuid, ...)`                                 | Lists evidence associated with a report                                          |
| `close_report(uuid, classification, blacklist_incident_type, blacklist_expires)` | Closes a report, optionally classifying its evidence and blacklisting the entity |
| `assign_operator_to_report(report_uuid, operator_uuid)`                          | Assigns an operator to a report                                                  |
| `delete_report(uuid)`                                                            | Deletes a report                                                                 |

`submit_report` returns a `ReportSubmission` object with the created `report` and its list of
`evidence` records. Upload attachments separately against an evidence record.

### Blacklist records

Blacklist records are the server's mitigation mechanism. An operator blacklists an entity with an
incident type and, optionally, the report backing the decision:

| Method                                                                     | Description                                                            |
|----------------------------------------------------------------------------|------------------------------------------------------------------------|
| `blacklist_entity(identifier, incident_type, report_uuid)`                 | Blacklists an entity permanently                                       |
| `blacklist_entity(identifier, incident_type, report_uuid, expires)`        | Blacklists an entity with an expiration timestamp (Unix epoch seconds) |
| `list_blacklist_records(page, limit, include_lifted, category, by, order)` | Lists blacklist entries                                                |
| `search_blacklist(query, page, limit, category, by, order)`                | Searches blacklist entries                                             |
| `get_blacklist_record(uuid)`                                               | Returns a single blacklist record                                      |
| `lift_blacklist_record(uuid)`                                              | Lifts the blacklist entry of an entity                                 |
| `extend_blacklist_record(uuid, seconds)`                                   | Extends the blacklist of an entity by the given seconds                |
| `delete_blacklist_record(uuid)`                                            | Deletes a blacklist record                                             |

### File attachments

Evidence records support file attachments with uploads from disk or URL, and note attachments (plain-text content):

| Method                                                                    | Description                                        |
|---------------------------------------------------------------------------|----------------------------------------------------|
| `upload_file_attachment(evidence_uuid, local_file_path)`                  | Uploads a local file attachment                    |
| `upload_file_attachment(evidence_uuid, local_file_path, file_name)`       | Uploads a local file attachment with a custom name |
| `upload_file_attachment_from_url(evidence_uuid, file_url)`                | Uploads an attachment from a reachable URL         |
| `upload_file_attachment_from_url(evidence_uuid, file_url, max_file_size)` | Uploads an attachment from a URL with a size limit |
| `upload_note_attachment(evidence_uuid, file_name, content)`               | Uploads a plain-text note attachment               |
| `download_attachment(attachment_uuid, directory_path)`                    | Downloads an attachment into the given directory   |
| `get_attachment_info(uuid)`                                               | Returns the metadata of an attachment              |
| `list_attachments(page, limit, category, by, order)`                      | Lists attachments                                  |
| `search_attachments(query, page, limit, category, by, order)`             | Searches attachments                               |
| `delete_attachment(uuid)`                                                 | Deletes an attachment                              |

URL uploads default to a maximum file size of 50 MB, matching the FederationLib client default, the
limit can be raised per request.

### Pagination and sorting

Every listing and search endpoint accepts the same pagination and sorting arguments: `page` (1-based)
and `limit` (minimum 1), followed by an optional category filter, `by` (the field to sort by,
case-insensitive), and `order` (`"ASC"` or `"DESC"`), for example:

```python
# Defaults: page 1, limit 100
entities = client.list_entities()

# Explicit pagination
entities = client.list_entities(2, 50)

# Pagination with a category filter, sorted by reputation ascending
entities = client.list_entities(2, 50, "WHITELISTED", "reputation", "ASC")
```

The argument order is the same for every endpoint.

## Error handling

All failures are raised as `FederationClientException`, carrying the HTTP status code of the
response and, when the server returns one, its error message:

```python
from pyfederation import FederationClientException

try:
    client.get_entity_record("non-existent-entity")
except FederationClientException as e:
    print(f"Request failed with status {e.status_code}: {e}")
```

Failures without a response, such as connection errors, have a status code of 0. Invalid arguments,
such as an empty UUID, a page below 1, a search query shorter than 2 characters, or an access token
that is empty or contains whitespace, are rejected by the client immediately with a `ValueError`.

## Testing

The unit tests run without a server:

```sh
pip install -e . --group dev
pytest
```

The integration tests run against a live Federation server, and the repository includes a
[docker-compose.yml](docker-compose.yml) that brings up the reference
[FederationLib](https://github.com/nosial/FederationLib) server, MariaDB, and Redis on `http://localhost:7000`:

```sh
docker compose up -d
pytest -m integration
```

By default the tests expect the server at `http://localhost:7000` with access token
`abcdefghijklmnopqrstuvwxyz123456` (matching the compose defaults). To test against a different
server, set the `SERVER_ENDPOINT` and `SERVER_ACCESS_TOKEN` environment variables:

```sh
SERVER_ENDPOINT=http://localhost:7000 SERVER_ACCESS_TOKEN=my-token pytest -m integration
```

The synchronous client, `client.py`, is generated from the asynchronous client, `async_client.py`,
run `python scripts/unasync.py` after changing it.

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
