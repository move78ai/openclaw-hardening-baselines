# Skill governance (allowlist-only)

## Policy
- Default stance: block new skills unless approved.
- “Approved” means:
  - known publisher/maintainer
  - code reviewed (or at least behavior tested in a sandbox)
  - permissions understood (filesystem/network/tool access)
  - documented business owner + expiry date

## Repo artifacts
- `policies/skill-allowlist.yml` (what’s permitted)
- `policies/skill-blocklist.yml` (what’s forbidden)

## Minimal workflow (no tooling required)
1) Intake request (who, what for, what data)
2) Review (static + behavioral)
3) Approve for specific scope + time window
4) Monitor + re-review after updates
