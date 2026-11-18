#!/usr/bin/env python3
"""Read-only Linux inventory proof of concept. Uses only Python stdlib.

NOT a hardened endpoint agent: no signed update protocol, encrypted offline queue,
privileged telemetry, or verified mTLS. Do not deploy on production endpoints.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import sys
from urllib.request import Request, urlopen
from urllib.parse import urlsplit


def snapshot():
    if sys.platform != "linux":
        raise RuntimeError("Linux only")
    machine_id = Path("/etc/machine-id")
    if not machine_id.is_file():
        raise RuntimeError("No stable /etc/machine-id; collector will not invent one")
    # Send an opaque stable reference, never machine-id itself.
    ref = hashlib.sha256((machine_id.read_text().strip() + ":onesa-security-v1").encode()).hexdigest()[:32]
    host = socket.gethostname()
    return {"external_ref": "linux-" + ref, "category": "endpoint", "label": host[:150], "os_family": "linux"}


def send(api_base, credential_file, ca_file, ssh_posture=False):
    parsed = urlsplit(api_base)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path.rstrip("/"):
        raise ValueError("An HTTPS origin is required")
    secret_path = Path(credential_file)
    if (secret_path.stat().st_mode & 0o077) != 0:
        raise ValueError("Collector credential file must be chmod 600")
    token = secret_path.read_text(encoding="utf-8").strip()
    # This is a development collector with a token, not an mTLS-capable production agent.
    req = Request(api_base + "/v1/collector/assets", data=json.dumps(snapshot()).encode(),
                  headers={"Authorization": "Collector " + token, "Content-Type": "application/json"}, method="POST")
    context = ssl.create_default_context(cafile=ca_file)
    with urlopen(req, timeout=7, context=context) as resp:
        if resp.status != 200:
            raise RuntimeError("Collector request refused")
    if ssh_posture:
        for finding in inspect_sshd_baseline():
            finding.pop("limitations")
            finding["asset_ref"] = snapshot()["external_ref"]
            request = Request(api_base + "/v1/collector/findings", data=json.dumps(finding).encode(),
                              headers={"Authorization": "Collector " + token, "Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=7, context=context) as resp:
                if resp.status != 200:
                    raise RuntimeError("Posture finding rejected")
    print("Host inventory snapshot accepted (no credential output)")


def inspect_sshd_baseline(sshd_config_path="/etc/ssh/sshd_config"):
    """Read-only configuration-file hint, NOT a claim of effective SSH daemon posture.

    Does not follow include/drop-in overrides; operators must verify with `sshd -T`.
    No private configuration contents are uploaded.
    """
    path = Path(sshd_config_path)
    if not path.is_file():
        return []
    data = path.read_text(encoding="utf-8", errors="replace")
    if len(data) > 1_000_000:
        raise ValueError("SSH configuration file unexpectedly large")
    seen = {}
    for raw in data.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("permitrootlogin", "passwordauthentication"):
            # OpenSSH's first-wins directive semantics are affected by Include and Match blocks.
            seen.setdefault(parts[0].lower(), parts[1].split("#",1)[0].strip().lower())
    reported = []
    for key, val, title, severity in [
        ("permitrootlogin", "yes", "SSH config file explicitly permits root login", "high"),
        ("passwordauthentication", "yes", "SSH config file explicitly enables password authentication", "medium"),
    ]:
        if seen.get(key) != val:
            continue
        digest = hashlib.sha256((str(path)+key+val).encode()).hexdigest()[:16]
        reported.append({"external_id": "ssh-posture-" + key, "category": "configuration", "severity": severity,
                         "title": title, "evidence_ref": "read-only-file-" + digest,
                         "limitations": "Declared configuration may be overridden; inspect effective sshd -T before remediation"})
    return reported


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", required=True, help="HTTPS API origin")
    parser.add_argument("--credential-file", required=True)
    parser.add_argument("--ca-file", default=None)
    parser.add_argument("--read-only-ssh-posture", action="store_true", help="Report literal SSH config hints; verify effective sshd -T independently")
    args = parser.parse_args()
    send(args.api.rstrip("/"), args.credential_file, args.ca_file, args.read_only_ssh_posture)
