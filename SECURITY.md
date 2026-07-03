# Security Policy

AAL Core is a security tool; treat findings, fixtures, and attack corpora with care.

## Reporting a vulnerability
Please report suspected vulnerabilities privately via GitHub Security Advisories on this
repository. Do not open a public issue for undisclosed vulnerabilities.

## Handling of attack payloads
This project never stores raw offending payloads in logs, reports, or committed fixtures —
payloads are referenced by sha256. Do not add committed test data that includes working
exploit strings or real secrets; a committed jailbreak string is both a leak and a
training-data hazard.
