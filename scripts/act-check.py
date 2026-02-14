#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

@dataclass
class CheckResult:
    id: str
    title: str
    status: str  # PASS/WARN/FAIL/INFO
    details: str
    remediation: str = ""

def run(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 99, "", str(e)

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def check_openclaw_binary() -> CheckResult:
    p = which("openclaw")
    if not p:
        return CheckResult(
            id="bin.openclaw",
            title="OpenClaw binary present",
            status="WARN",
            details="openclaw binary not found in PATH. If OpenClaw is installed elsewhere, adjust PATH.",
            remediation="Install OpenClaw on this host or run this check on the OpenClaw host/container.",
        )
    return CheckResult(
        id="bin.openclaw",
        title="OpenClaw binary present",
        status="PASS",
        details=f"Found: {p}",
    )

def check_openclaw_version() -> CheckResult:
    p = which("openclaw")
    if not p:
        return CheckResult("bin.version", "OpenClaw version", "INFO", "Skipped (openclaw not in PATH).")
    rc, out, err = run(["openclaw", "--version"], timeout=5)
    if rc == 0 and out:
        return CheckResult("bin.version", "OpenClaw version", "INFO", out)
    return CheckResult("bin.version", "OpenClaw version", "INFO", f"Could not read version. stderr={err}")

def check_security_audit() -> CheckResult:
    # Best-effort: if OpenClaw provides a built-in audit, run it.
    p = which("openclaw")
    if not p:
        return CheckResult("audit.security", "Built-in security audit", "INFO", "Skipped (openclaw not in PATH).")
    # Try a few known patterns without assuming exact CLI stability.
    candidates = [
        ["openclaw", "security", "audit"],
        ["openclaw", "security", "audit", "--deep"],
    ]
    for c in candidates:
        rc, out, err = run(c, timeout=20)
        if rc == 0 and (out or err):
            text = out if out else err
            status = "WARN" if re.search(r"\bFAIL\b|\bWARN\b", text, re.IGNORECASE) else "INFO"
            return CheckResult(
                "audit.security",
                "Built-in security audit",
                status,
                text[:2000] + ("..." if len(text) > 2000 else ""),
                remediation="Review the audit output and apply recommended fixes; re-run after changes.",
            )
    return CheckResult(
        "audit.security",
        "Built-in security audit",
        "INFO",
        "No built-in audit command detected (or it failed).",
        remediation="If OpenClaw has a security audit command in your version, wire it into this check.",
    )

def check_listening_sockets() -> CheckResult:
    # Look for a process named "openclaw" listening on 0.0.0.0 (or :::).
    ss = which("ss")
    netstat = which("netstat")

    cmd = None
    if ss:
        cmd = ["ss", "-lntp"]
    elif netstat:
        cmd = ["netstat", "-lntp"]
    else:
        return CheckResult("net.listen", "Listening exposure", "INFO", "No ss/netstat available; skipped.")

    rc, out, err = run(cmd, timeout=10)
    if rc != 0:
        return CheckResult("net.listen", "Listening exposure", "INFO", f"Failed to run {cmd}: {err}")

    lines = out.splitlines()
    findings = []
    for ln in lines:
        low = ln.lower()
        if "openclaw" in low or "clawdbot" in low or "moltbot" in low:
            # naive parse: if it contains 0.0.0.0 or ::: then it's broadly bound
            if "0.0.0.0" in ln or "[::]:" in ln or ":::".encode() and ":::".decode() in ln:
                findings.append(ln.strip())

    if findings:
        return CheckResult(
            "net.listen",
            "Listening exposure",
            "FAIL",
            "Agent appears to be listening on a broad interface:\n- " + "\n- ".join(findings[:10]),
            remediation="Bind to 127.0.0.1 by default; place a reverse proxy/VPN/SSO boundary in front if remote access is required.",
        )
    return CheckResult(
        "net.listen",
        "Listening exposure",
        "PASS",
        "No agent listeners found bound to 0.0.0.0/::: (best-effort).",
    )

def check_sensitive_dirs() -> CheckResult:
    # Best-effort checks for common local config dirs. If they exist and are world-readable, flag.
    home = Path.home()
    candidates = [home / ".openclaw", home / ".clawdbot", home / ".moltbot"]
    bad = []
    found = []
    for p in candidates:
        if p.exists():
            found.append(str(p))
            st = p.stat()
            # world-readable/executable bits
            if st.st_mode & 0o077:
                bad.append(str(p))

    if not found:
        return CheckResult("fs.secrets", "Local agent data permissions", "INFO", "No known agent dirs found in home.")
    if bad:
        return CheckResult(
            "fs.secrets",
            "Local agent data permissions",
            "FAIL",
            "Directories with permissive permissions: " + ", ".join(bad),
            remediation="Set permissions to 700 for directories and 600 for files; ensure secrets are not world-readable.",
        )
    return CheckResult("fs.secrets", "Local agent data permissions", "PASS", "Found dirs with restrictive permissions.")

def score(results: List[CheckResult]) -> int:
    # Simple weighted scoring.
    s = 100
    for r in results:
        if r.status == "FAIL":
            s -= 25
        elif r.status == "WARN":
            s -= 10
    return max(0, min(100, s))

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    results = [
        check_openclaw_binary(),
        check_openclaw_version(),
        check_security_audit(),
        check_listening_sockets(),
        check_sensitive_dirs(),
    ]
    out: Dict[str, Any] = {
        "tool": "act-check",
        "generated_at_utc": datetime.utcnow().isoformat() + "Z",
        "score": score(results),
        "results": [r.__dict__ for r in results],
        "next_steps": [
            "If score < 80: review FAIL/WARN items and remediate.",
            "If something looks wrong or ambiguous, open an issue with your redacted output and environment details.",
        ],
    }

    Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
