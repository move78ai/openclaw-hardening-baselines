# Network egress controls (baseline)

Agent runtimes are best treated as high-risk automation: assume compromise and constrain blast radius.

## Baseline recommendation
Deny outbound egress by default on the agent host / container and explicitly allow only:
- the approved LLM endpoints
- required SaaS APIs
- internal enterprise services needed for the use case

If your org cannot do deny-by-default, implement a proxy-based allowlist and monitor exceptions.

## Practical patterns

### Pattern A: Egress via HTTP proxy allowlist (recommended)
1) Force the agent host/container to use an explicit proxy (`HTTPS_PROXY`, `HTTP_PROXY`)
2) Configure the proxy with an allowlist of domains
3) Log all CONNECT/HTTPS requests

Artifacts:
- `policies/domain-allowlist.txt`
- `policies/domain-blocklist.txt`

### Pattern B: Linux host-level allowlist (aggressive)
This is environment-specific. Example UFW approach (illustrative only):
- default deny outgoing
- allow outgoing to DNS resolver
- allow outgoing to proxy only

> Do not copy/paste into production without testing.

## What to log (minimum)
- destination domain + IP
- TLS SNI (if available at proxy)
- volume (bytes) and request counts
- timestamps
- mapping to agent identity (service account or container id)
