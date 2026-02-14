# Threat model (practical)

This baseline targets the failure modes we see repeatedly with agentic AI runtimes:

## 1) Exposure / remote access
- Control UI / gateway reachable from untrusted networks
- weak or missing authentication
- reverse proxy misconfiguration (treating external traffic as trusted)

Baseline controls
- bind to `127.0.0.1` by default
- require a reverse proxy boundary if remote access is needed
- IP allowlisting + VPN (preferred) + SSO/MFA (required for real-world)

## 2) Over-privileged execution
- agent runs as a human user or with admin/root privileges
- agent can read/write broad filesystem paths and credentials

Baseline controls
- run as non-root
- minimize writable mounts
- isolate execution environment (VM/container)

## 3) Uncontrolled egress / data exfil
- agent can call arbitrary external endpoints
- skills/plugins can beacon out or exfiltrate secrets

Baseline controls
- egress allowlist (deny by default on the agent host or via proxy)
- block “agent-to-agent” networks unless explicitly required

## 4) Skill supply-chain risk
- users install unreviewed third-party skills/extensions
- malicious skills can steal tokens, credentials, source code, etc.

Baseline controls
- allowlist-only skill policy
- require review + change control before enabling skills in production

## 5) Prompt injection / memory poisoning
- agents ingest untrusted content and later execute instructions based on it

Baseline controls
- “lethal trifecta” avoidance: do not combine (a) sensitive data access, (b) untrusted inputs,
  and (c) external communication without approvals and monitoring
- human-in-the-loop for dangerous actions (write / deploy / pay / share)
