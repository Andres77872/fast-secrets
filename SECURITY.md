# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner rather than
opening a public issue. Include the affected version, reproduction steps, impact, and
any suggested mitigation. Do not include real credentials, production tokens, or other
people's data in a report.

## Product boundary

fast-secrets is a stateless developer utility, not a secret vault. It does not provide
accounts, durable secret storage, access control, rotation, or audit trails. The public
web UI performs tool operations locally in the browser. Calling the HTTP API explicitly
sends request data to the configured server.

Public deployments must use HTTPS, retain the supplied security headers and workload
limits, avoid request-body logging, and apply rate limiting at a trusted reverse proxy.
