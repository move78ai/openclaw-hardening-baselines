# OpenClaw Hardening Baselines (Community)

Goal: give OpenClaw deployers a *runnable* baseline that reduces the most common enterprise failures:
- public / unsafe exposure
- over-privileged execution
- uncontrolled egress
- unreviewed skills/extensions

This repo is intentionally baseline-only (no platform, no SaaS).

## What’s included
- Hardened Docker Compose starter (`baselines/docker-compose/docker-compose.yml`)
- Example reverse proxy config (TLS, auth boundary) (`baselines/reverse-proxy/`)
- Egress allowlist patterns + example firewall rules (`docs/network-egress.md`, `policies/domain-allowlist.txt`)
- Skill governance scaffolding (allowlist/blocklist templates) (`policies/skill-*.yml`, `docs/skill-governance.md`)
- `act-check` drift check that produces a simple JSON score (`scripts/act-check.sh`)

## Quick start (Docker)
1) Copy the baseline:
bash
cp -r baselines/docker-compose ./openclaw-baseline
cd openclaw-baseline


2) Review and set environment values in `.env`:
- bind gateway/control UI to `127.0.0.1` unless you *really* know why you need public access
- run behind a reverse proxy with strong auth if remote access is required

3) Start:
bash
docker compose up -d


4) Run drift check:
bash
../scripts/act-check.sh --output ./act-check.json
cat ./act-check.json


## Feedback (help improve the baseline)
- If this baseline was useful, star the repo (it helps other teams find it).
- If you find gaps, open a GitHub Issue with:
  - your deployment context (Docker / VM / k8s)
  - which check failed (paste `act-check.json` with secrets redacted)
  - what you expected vs what happened
- PRs are welcome for additional hardening patterns and drift checks.

## Support & warranty
No warranty. Use at your own risk. See `LICENSE` and `docs/DISCLAIMER.md`.

## Contributing
PRs welcome. Please see `CONTRIBUTING.md`.
