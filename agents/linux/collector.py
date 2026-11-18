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


def send(api_base, credential_file, ca_file):
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
    print("Host inventory snapshot accepted (no credential output)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", required=True, help="HTTPS API origin")
    parser.add_argument("--credential-file", required=True)
    parser.add_argument("--ca-file", default=None)
    args = parser.parse_args()
    send(args.api.rstrip("/"), args.credential_file, args.ca_file)
