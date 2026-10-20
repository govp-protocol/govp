"""Verify the public synthetic example in a network-isolated Linux container."""

import argparse
import errno
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = (
    "python:3.12-slim-bookworm@sha256:"
    "2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d"
)


def run(command, *, check=True):
    return subprocess.run(
        command, text=True, capture_output=True, check=check, timeout=300,
    )


def network_control():
    interfaces = sorted(name for _, name in socket.if_nameindex())
    routes = Path("/proc/net/route").read_text()
    if interfaces != ["lo"] or len(routes.strip().splitlines()) != 1:
        raise RuntimeError("Expected loopback only and no IPv4 routes")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(2)
        try:
            probe.connect(("1.1.1.1", 443))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise RuntimeError("Expected ENETUNREACH") from error
        else:
            raise RuntimeError("External network connection succeeded")
    return {
        "interfaces": interfaces, "ipv4_routes": routes,
        "external_ipv4_probe": "ENETUNREACH",
        "limit": "Loopback remains available; this does not deny every socket.",
    }


def verify_inside():
    before = network_control()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("The pinned wheels target Linux x86_64")
    run([sys.executable, "-m", "venv", "/tmp/verify-venv"])
    python = "/tmp/verify-venv/bin/python"
    install = run([
        python, "-m", "pip", "--isolated", "--disable-pip-version-check",
        "install", "--no-index", "--no-cache-dir", "--require-hashes",
        "--find-links", "/wheels", "-r", "/requirements.txt",
    ])
    self_test = run([python, "-m", "govp", "self-test"])
    cases = []
    for name, record, asset, exit_code, signature, asset_ok in [
        ("original", "agent-record.govp.txt", "agent-record.json", 0, True, True),
        ("changed_asset", "agent-record.govp.txt",
         "agent-record.tampered.json", 1, True, False),
        ("changed_record", "agent-record.tampered.govp.txt",
         "agent-record.json", 1, False, True),
    ]:
        result = run([
            python, "-m", "govp", "verify", f"/fixture/{record}",
            "--asset", f"/fixture/{asset}", "--json",
        ], check=False)
        verdict = json.loads(result.stdout)
        checks = verdict["checks"]
        if (
            result.returncode != exit_code
            or verdict["ok"] != (exit_code == 0)
            or checks["signature"] is not signature
            or checks["asset"] is not asset_ok
            or checks["canonical"] is not None
        ):
            raise RuntimeError(f"{name}: unexpected result {result}")
        cases.append({
            "case": name, "exit_code": result.returncode,
            "verdict": verdict, "stderr": result.stderr,
        })
    fixture = Path("/fixture")
    statement = json.loads((fixture / "agent-record.json").read_text())
    output_hash = hashlib.sha256((fixture / "operation-A.txt").read_bytes()).hexdigest()
    if statement["synthetic"] is not True:
        raise RuntimeError("Expected the synthetic fixture")
    if output_hash != statement["events"][2]["artifact_sha256"]:
        raise RuntimeError("Output A does not match its declared hash")
    print(json.dumps({
        "scope": "Synthetic fixture on an isolated execution host, not an independent audit",
        "python": platform.python_version(), "machine": platform.machine(),
        "uid": os.getuid(), "network_before": before,
        "network_after": network_control(),
        "installation": {"stdout": install.stdout, "stderr": install.stderr},
        "self_test": {"stdout": self_test.stdout, "exit_code": self_test.returncode},
        "cases": cases, "output_A_digest_matches_statement": True,
    }, indent=2))


def verify_on_host(wheels):
    requirements = ROOT / "tools/agent-record-offline-requirements.txt"
    fixture = ROOT / "examples/agent-record"
    script = Path(__file__).resolve()
    run(["docker", "pull", "--platform", "linux/amd64", IMAGE])
    image = json.loads(run(["docker", "image", "inspect", IMAGE]).stdout)[0]
    command = [
        "docker", "create", "--platform", "linux/amd64", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=256m",
        "--user", "65534:65534", "--env", "PYTHONDONTWRITEBYTECODE=1",
    ]
    for source, destination in [
        (fixture, "/fixture"), (wheels, "/wheels"),
        (requirements, "/requirements.txt"), (script, "/verify.py"),
    ]:
        command.extend(["--mount", f"type=bind,src={source},dst={destination},readonly"])
    command.extend([image["Id"], "python", "/verify.py", "--inside"])
    container = run(command).stdout.strip()
    try:
        result = run(["docker", "start", "--attach", container], check=False)
        inspected = json.loads(run(["docker", "inspect", container]).stdout)[0]
        config = inspected["HostConfig"]
        security = {
            "network_mode": config["NetworkMode"], "privileged": config["Privileged"],
            "readonly_rootfs": config["ReadonlyRootfs"], "cap_drop": config["CapDrop"],
            "security_opt": config["SecurityOpt"], "user": inspected["Config"]["User"],
            "bind_mounts": [
                {"destination": m["Destination"], "rw": m["RW"]}
                for m in inspected["Mounts"] if m["Type"] == "bind"
            ],
        }
        if (
            security["network_mode"] != "none" or security["privileged"]
            or not security["readonly_rootfs"] or security["cap_drop"] != ["ALL"]
            or security["user"] != "65534:65534"
            or not any(s.startswith("no-new-privileges") for s in security["security_opt"])
            or any(m["rw"] for m in security["bind_mounts"])
        ):
            raise RuntimeError("Container settings do not match the requested isolation")
        if result.returncode or inspected["State"]["ExitCode"]:
            raise RuntimeError(f"Offline check failed: {result.stdout}\n{result.stderr}")
        inputs = sorted(fixture.iterdir()) + sorted(wheels.iterdir()) + [script, requirements]
        report = {
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "host_platform": platform.platform(),
            "github": {key: os.environ.get(key) for key in [
                "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
            ]},
            "image_requested": IMAGE, "image_id": image["Id"],
            "image_repo_digests": image.get("RepoDigests", []),
            "container_security": security, "container_exit_code": inspected["State"]["ExitCode"],
            "inputs": [
                {"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in inputs if p.is_file()
            ],
            "verification": json.loads(result.stdout),
        }
        # Markers allow extraction from ordinary Actions logs without artifact storage.
        print("BEGIN_AGENT_OFFLINE_REPORT")
        print(json.dumps(report, indent=2))
        print("END_AGENT_OFFLINE_REPORT")
    finally:
        run(["docker", "rm", "-f", container])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--wheels", type=Path)
    args = parser.parse_args()
    if args.inside:
        verify_inside()
    elif args.wheels and args.wheels.is_dir():
        verify_on_host(args.wheels.resolve())
    else:
        parser.error("--wheels must identify a prepared local wheel directory")


if __name__ == "__main__":
    main()
