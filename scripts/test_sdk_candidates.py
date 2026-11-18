"""Run security and compatibility checks against drifted SDK candidates.

This harness is intentionally non-promoting: it runs in the scheduled GitHub
workflow's disposable checkout and never commits dependency updates.
"""
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "sdk-drift-report.json"


def run(command, *, cwd=ROOT):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def main():
    report = json.loads(REPORT_PATH.read_text())
    if report.get("status") != "drift":
        report["candidate_compatibility"] = {
            "outcome": "skipped",
            "reason": "No version candidates because registry status is " + str(report.get("status", "missing")),
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n")
        print("Candidate suites skipped because the package registry result is unavailable or current.")
        return 0

    changed = [item for item in report.get("packages", []) if item.get("changed")]
    python_specs = []
    npm_specs = []
    for item in changed:
        package, version = item.get("package", ""), item.get("latest", "")
        if not re.fullmatch(r"[A-Za-z0-9@/._+-]+", package) or not re.fullmatch(r"[A-Za-z0-9.+-]+", version):
            raise ValueError("Registry returned an invalid package name or version")
        if item.get("ecosystem") == "pypi":
            python_specs.append(f"{package}=={version}")
        elif item.get("ecosystem") == "npm":
            npm_specs.append(f"{package}@{version}")

    run([sys.executable, "-m", "pip", "install", "-e", "./services/api[test]", *python_specs])
    run([sys.executable, "-m", "pip", "install", "pip-audit>=2.9,<3"])
    run([sys.executable, "services/api/tests/setup_postgres_ci.py"])
    run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT / "services/api")
    run([sys.executable, "-m", "pip_audit", "--strict", "--progress-spinner", "off", "./services/api"])
    run([sys.executable, "tests/benchmark_guardrail.py"], cwd=ROOT / "services/api")
    run([sys.executable, "-m", "compileall", "-q", "services/api/app", "agents/linux"])
    run([sys.executable, "-m", "unittest", "-q", "test_collector.py", "test_posture.py"], cwd=ROOT / "agents/linux")
    run([sys.executable, "-m", "unittest", "discover", "-s", ".", "-p", "test_*.py", "-q"], cwd=ROOT / "agents/python")

    web = ROOT / "apps/web"
    run(["npm", "install", "--save-exact", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", *npm_specs], cwd=web)
    run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=web)
    run(["npm", "audit", "--omit=dev"], cwd=web)
    run(["npm", "run", "typecheck"], cwd=web)
    run(["npm", "run", "build"], cwd=web)
    run(["node", "scripts/smoke-unconfigured.mjs"], cwd=web)
    print("All changed SDK candidates passed compatibility and security checks; no dependencies were promoted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
