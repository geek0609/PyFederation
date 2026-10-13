# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-13

The first release, a port of [JFederation](https://github.com/nosial/JFederation) 1.0.13. This release follows
version `v1.0-R4` of the OFD Specification.

### Added
 - `FederationClient` and `AsyncFederationClient`, covering every method of the Federation server API: server
   information, search, content scanning, audit logs, operators, entities, evidence, reports, blacklist records and
   file attachments.
 - Records and enums for every object the server returns.
 - `FederationClientException`, raised for every failed request with the HTTP status code and the server's message.
