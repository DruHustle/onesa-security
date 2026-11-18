"""Read-only upstream SDK drift watch. Never auto-upgrade production dependencies.

Reports latest available versions against verified lockfile pins. Network errors
produce an explicit non-success status; they are not interpreted as no drift.
"""
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def get_json(url):
    req = Request(url, headers={"User-Agent": "OnesaSecuritySDKDriftCheck/1.0"})
    with urlopen(req, timeout=12) as response:
        return json.load(response)


def report():
    lock = json.loads((ROOT / "apps/web/package-lock.json").read_text())
    pkgs = lock["packages"]
    results = []
    for name in ("@auth0/nextjs-auth0", "next"):
        pinned = pkgs["node_modules/" + name]["version"]
        latest = get_json("https://registry.npmjs.org/" + quote(name, safe="") + "/latest")["version"]
        results.append({"ecosystem": "npm", "package": name, "pinned": pinned, "latest": latest, "changed": pinned != latest})
    python_baselines = json.loads((ROOT / "scripts/sdk-python-baseline.json").read_text())
    for name, pinned in python_baselines.items():
        latest = get_json("https://pypi.org/pypi/" + quote(name) + "/json")["info"]["version"]
        results.append({"ecosystem": "pypi", "package": name, "pinned": pinned, "latest": latest, "changed": pinned != latest})
    return results


if __name__ == "__main__":
    out = Path(os.environ.get("ONESA_SDK_DRIFT_REPORT", "/tmp/onesa-sdk-drift.json"))
    try:
        data = report()
        result = {"source": "public package registries", "status": "drift" if any(x["changed"] for x in data) else "current", "packages": data}
    except Exception as exc:
        result = {"status": "unavailable", "message": type(exc).__name__, "packages": []}
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if result["status"] != "current":
        raise SystemExit(1 if result["status"] == "drift" else 2)
