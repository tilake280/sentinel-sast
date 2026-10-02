#!/usr/bin/env python3
"""End-to-end check: a signed webhook results in a worker scan, stored and served.

    webhook -> gateway -> scan_jobs -> worker -> triage -> scan_results -> gateway -> Postgres

This drives the real binaries over the real broker and database. Nothing is
mocked except GitHub: the gateway is pointed at a small local server that
serves demo/vulnerable-app in raw.githubusercontent.com's URL layout, so the
check does not depend on a public repository or on network access.

Prerequisites
-------------
1. Infrastructure up:           docker compose up -d
2. Worker built:                cd worker && make
3. Go toolchain on PATH (the gateway is built by this script).

If Postgres is not on localhost:5432, export DATABASE_URL (gateway) and
SENTINEL_DATABASE_URL (triage layer) first, as described in .env.example.

Usage
-----
    ai-layer/venv/bin/python scripts/e2e_webhook.py

By default the script starts its own gateway, worker and triage layer on
dedicated ports and queues, so it does not interfere with instances you already
have running, and stops them when it finishes. Exit status is 0 only if every
check passed.

    --no-triage     run the worker with triage disabled (findings are UNTRIAGED)
    --keep-running  leave the gateway up afterwards, for looking at the result
                    in the frontend (GATEWAY_URL is printed)
    --verbose       print the output of the spawned processes on failure

The scan it creates is left in the database under the repository name
"sentinel-e2e/vulnerable-app" so it can be inspected in the UI.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "demo" / "vulnerable-app"
WORKER = ROOT / "worker" / "build" / "sentinel-worker"
GATEWAY_BIN = ROOT / "gateway" / "gateway"
VENV_PYTHON = ROOT / "ai-layer" / "venv" / "bin" / "python"

REPOSITORY = "sentinel-e2e/vulnerable-app"
COMMIT = "0123456789abcdef0123456789abcdef01234567"

# The three demo sources, plus one file the gateway must filter out and one it
# must skip because it does not exist at the commit.
PUSHED_FILES = [
    "src/routes/users.js",
    "services/importer.py",
    "internal/api/handlers.go",
    "README.md",
    "src/removed-later.js",
]
SCANNED_FILES = PUSHED_FILES[:3]

VERDICTS = {"ESCALATED", "SUPPRESSED", "UNTRIAGED"}


class Failure(Exception):
    pass


# ---- Small helpers ---------------------------------------------------------


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def http_json(method: str, url: str, body: bytes | None = None, headers: dict | None = None):
    """Returns (status, parsed JSON or None).

    An HTTP error status is returned, not raised. A server that is not
    accepting connections yet gives status 0, so callers can poll with this.
    """
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = error.code
    except (urllib.error.URLError, OSError):
        return 0, None
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, None


def wait_for(description: str, predicate, timeout: float = 30.0, interval: float = 0.25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise Failure(f"timed out after {timeout:.0f}s waiting for {description}")


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---- Stand-in for raw.githubusercontent.com --------------------------------


class ContentHandler(http.server.BaseHTTPRequestHandler):
    """Serves CORPUS at /{owner}/{repo}/{commit}/{path}."""

    requests: list[str] = []

    def do_GET(self):  # noqa: N802 (name fixed by the base class)
        prefix = f"/{REPOSITORY}/{COMMIT}/"
        ContentHandler.requests.append(self.path)

        if not self.path.startswith(prefix):
            self.send_error(404)
            return
        target = (CORPUS / self.path[len(prefix):]).resolve()
        if CORPUS.resolve() not in target.parents or not target.is_file():
            self.send_error(404)
            return

        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # keep the check's own output readable
        pass


# ---- Process management ----------------------------------------------------


class Spawned:
    def __init__(self):
        self.processes: list[tuple[str, subprocess.Popen, Path]] = []

    def start(self, name: str, argv: list[str], cwd: Path, env: dict, log_dir: Path):
        log_path = log_dir / f"{name}.log"
        log = open(log_path, "w")
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append((name, process, log_path))
        return process, log_path

    def check_alive(self):
        for name, process, log_path in self.processes:
            if process.poll() is not None:
                tail = log_path.read_text()[-2000:]
                raise Failure(f"{name} exited with status {process.returncode}:\n{tail}")

    def stop(self, keep: set[str] = frozenset()):
        for name, process, _ in reversed(self.processes):
            if name in keep or process.poll() is not None:
                continue
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    def dump(self):
        for name, _, log_path in self.processes:
            print(f"\n----- {name} log ({log_path}) -----")
            print(log_path.read_text()[-4000:])


# ---- The check -------------------------------------------------------------


def run(args) -> int:
    checks: list[tuple[bool, str]] = []

    def check(condition: bool, label: str, detail: str = "") -> bool:
        checks.append((bool(condition), label))
        mark = "PASS" if condition else "FAIL"
        print(f"  [{mark}] {label}" + (f"\n         {detail}" if detail and not condition else ""))
        return bool(condition)

    # ---- Preflight ---------------------------------------------------------
    rabbit_host = os.getenv("RABBITMQ_HOST", "localhost")
    rabbit_port = int(os.getenv("RABBITMQ_PORT", "5672"))
    if not port_open(rabbit_host, rabbit_port):
        raise Failure(f"RabbitMQ is not reachable at {rabbit_host}:{rabbit_port}. "
                      "Start the infrastructure: docker compose up -d")
    if not WORKER.exists():
        raise Failure(f"{WORKER} not found. Build it: cd worker && make")
    for path in SCANNED_FILES:
        if not (CORPUS / path).is_file():
            raise Failure(f"demo file missing: {CORPUS / path}")

    print("building gateway ...")
    build = subprocess.run(["go", "build", "-o", str(GATEWAY_BIN), "."], cwd=ROOT / "gateway",
                           capture_output=True, text=True,
                           env={**os.environ, "GOTOOLCHAIN": os.getenv("GOTOOLCHAIN", "local")})
    if build.returncode != 0:
        raise Failure(f"gateway did not build:\n{build.stdout}{build.stderr}")

    log_dir = Path(os.getenv("E2E_LOG_DIR", "/tmp")) / f"sentinel-e2e-{os.getpid()}"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Dedicated queues, so a worker or gateway already running against the
    # default ones neither steals this job nor receives its result.
    run_id = uuid.uuid4().hex[:8]
    scan_queue = f"e2e_scan_jobs_{run_id}"
    results_queue = f"e2e_scan_results_{run_id}"
    secret = secrets.token_hex(16)

    content_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ContentHandler)
    content_port = content_server.server_address[1]
    threading.Thread(target=content_server.serve_forever, daemon=True).start()

    gateway_port = free_port()
    triage_port = free_port()
    gateway_url = f"http://127.0.0.1:{gateway_port}"
    triage_url = f"http://127.0.0.1:{triage_port}/api/v1/triage"

    base_env = {**os.environ, "SCAN_QUEUE": scan_queue, "RESULTS_QUEUE": results_queue}
    spawned = Spawned()
    keep: set[str] = set()

    try:
        # ---- Start the pipeline --------------------------------------------
        if not args.no_triage:
            spawned.start("triage",
                          [str(VENV_PYTHON), "-m", "uvicorn", "main:app", "--port", str(triage_port),
                           "--log-level", "warning"],
                          ROOT / "ai-layer", base_env, log_dir)
            wait_for("the triage layer to start", lambda: (
                spawned.check_alive(),
                http_json("GET", f"http://127.0.0.1:{triage_port}/health")[0] == 200)[1])

        worker_argv = [str(WORKER)] + (["--no-triage"] if args.no_triage else [])
        _, worker_log = spawned.start("worker", worker_argv, ROOT / "worker",
                                      {**base_env, "TRIAGE_URL": triage_url}, log_dir)
        wait_for("the worker to connect to RabbitMQ", lambda: (
            spawned.check_alive(), "waiting for scan jobs" in worker_log.read_text())[1])

        spawned.start("gateway", [str(GATEWAY_BIN)], ROOT / "gateway",
                      {**base_env,
                       "GATEWAY_ADDR": f"127.0.0.1:{gateway_port}",
                       "GITHUB_WEBHOOK_SECRET": secret,
                       "GITHUB_RAW_BASE_URL": f"http://127.0.0.1:{content_port}"},
                      log_dir)
        wait_for("the gateway to start", lambda: (
            spawned.check_alive(), port_open("127.0.0.1", gateway_port))[1])

        print(f"\npipeline up: gateway {gateway_url}, queues {scan_queue} / {results_queue}\n")

        # ---- A push event --------------------------------------------------
        delivery = str(uuid.uuid4())
        payload = json.dumps({
            "ref": "refs/heads/main",
            "after": COMMIT,
            "repository": {"full_name": REPOSITORY},
            "commits": [
                {"added": PUSHED_FILES, "modified": [], "removed": []},
                {"added": [], "modified": [], "removed": []},
            ],
        }).encode()
        webhook = f"{gateway_url}/api/v1/webhook"

        def deliver(signature: str | None, delivery_id: str = delivery):
            headers = {"Content-Type": "application/json", "X-GitHub-Event": "push",
                       "X-GitHub-Delivery": delivery_id}
            if signature is not None:
                headers["X-Hub-Signature-256"] = signature
            return http_json("POST", webhook, payload, headers)

        print("signature validation")
        status, _ = deliver(None)
        check(status == 401, "an unsigned webhook is rejected with 401", f"got {status}")
        status, _ = deliver(sign("not-the-secret", payload))
        check(status == 401, "a webhook signed with the wrong secret is rejected with 401",
              f"got {status}")
        status, body = http_json("GET", f"{gateway_url}/api/v1/scans/{delivery}")
        check(status == 404, "a rejected webhook created no scan", f"got {status}: {body}")

        print("\nwebhook to scan")
        status, body = deliver(sign(secret, payload))
        accepted = check(status == 202 and body and body.get("status") == "accepted",
                         "a correctly signed push is accepted with 202", f"got {status}: {body}")
        if not accepted:
            raise Failure("the gateway did not accept the signed webhook")
        scan_id = body["scan_id"]
        check(scan_id == delivery, "the scan id is the GitHub delivery id")
        check(body.get("files") == 4,
              "non-source files are filtered before fetching (4 of 5 pushed paths kept)",
              f"got files={body.get('files')}")

        def scan_finished():
            spawned.check_alive()
            code, doc = http_json("GET", f"{gateway_url}/api/v1/scans/{scan_id}")
            if code == 200 and doc["scan"]["status"] != "PENDING":
                return doc
            return None

        document = wait_for("the scan to leave PENDING", scan_finished, timeout=45)
        scan, findings = document["scan"], document["findings"]

        check(scan["status"] == "COMPLETED", "the scan reached COMPLETED",
              f"status={scan['status']} error={scan.get('error')}")
        check(scan["repository"] == REPOSITORY and scan["commit"] == COMMIT and
              scan["ref"] == "refs/heads/main",
              "the stored scan carries the push's repository, commit and ref")
        check(scan["files_scanned"] == len(SCANNED_FILES),
              f"the worker scanned the {len(SCANNED_FILES)} fetched source files",
              f"files_scanned={scan['files_scanned']}")
        check(scan.get("worker_version", "") != "", "the result records the worker version")

        fetched = [p for p in ContentHandler.requests]
        check(all(p.startswith(f"/{REPOSITORY}/{COMMIT}/") for p in fetched) and
              not any(p.endswith("README.md") for p in fetched),
              "sources were fetched at the pushed commit, and README.md was never requested",
              f"requests: {fetched}")

        print("\nfindings and verdicts")
        check(len(findings) > 0 and len(findings) == scan["findings"],
              f"findings were stored ({len(findings)})")
        check(all(f["verdict"] in VERDICTS for f in findings),
              "every finding carries a verdict")
        counted = {v: sum(1 for f in findings if f["verdict"] == v) for v in VERDICTS}
        check(counted["ESCALATED"] == scan["escalated"] and
              counted["SUPPRESSED"] == scan["suppressed"] and
              counted["UNTRIAGED"] == scan["untriaged"],
              "the scan's verdict totals match its findings", f"{counted} vs {scan}")

        classes = {f["vulnerability"] for f in findings}
        languages = {f["file"].rsplit(".", 1)[-1] for f in findings}
        check({"SQL Injection", "Command Injection"} <= classes,
              "the demo's SQL injection and command injection were found",
              f"classes: {sorted(classes)}")
        check(languages == {"js", "py", "go"}, "findings came from all three languages",
              f"languages: {sorted(languages)}")

        if args.no_triage:
            check(counted["UNTRIAGED"] == len(findings),
                  "with triage disabled every finding is UNTRIAGED, none counted as escalated")
        else:
            check(counted["ESCALATED"] > 0 and counted["UNTRIAGED"] == 0,
                  "the triage layer gave a verdict on every finding",
                  f"{counted}")
            check(all(f["triage_reason"] for f in findings),
                  "every verdict comes with the triage layer's reason")

        print("\nidempotency and read API")
        status, body = deliver(sign(secret, payload))
        check(status == 200 and body and body.get("status") == "duplicate",
              "redelivering the same webhook does not start a second scan",
              f"got {status}: {body}")
        status, listing = http_json("GET", f"{gateway_url}/api/v1/scans?limit=200")
        check(status == 200 and any(s["id"] == scan_id for s in listing["scans"]),
              "the scan appears in GET /api/v1/scans")
        status, stats = http_json("GET", f"{gateway_url}/api/v1/stats")
        check(status == 200 and stats["completed"] >= 1 and stats["findings"] >= len(findings),
              "GET /api/v1/stats includes it", f"{stats}")

        # ---- Summary -------------------------------------------------------
        passed = sum(1 for ok, _ in checks if ok)
        print(f"\n{passed}/{len(checks)} checks passed")
        print(f"scan {scan_id}: {scan['files_scanned']} files, {len(findings)} findings — "
              f"{counted['ESCALATED']} escalated, {counted['SUPPRESSED']} suppressed, "
              f"{counted['UNTRIAGED']} untriaged")
        by_class: dict[str, int] = {}
        for finding in findings:
            by_class[finding["vulnerability"]] = by_class.get(finding["vulnerability"], 0) + 1
        for name, count in sorted(by_class.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {count:3d}  {name}")

        failed = passed != len(checks)
        if failed and args.verbose:
            spawned.dump()

        if args.keep_running and not failed:
            keep = {"gateway"}
            print(f"\ngateway left running: GATEWAY_URL={gateway_url}")
            print("stop it with: kill " + " ".join(
                str(p.pid) for n, p, _ in spawned.processes if n == "gateway"))
        return 1 if failed else 0

    except Failure:
        if args.verbose:
            spawned.dump()
        else:
            print(f"(process logs are in {log_dir}; rerun with --verbose to print them)")
        raise
    finally:
        spawned.stop(keep)
        content_server.shutdown()
        if "gateway" not in keep:
            delete_queues(rabbit_host, rabbit_port, [scan_queue, results_queue])


def delete_queues(host: str, port: int, queues: list[str]) -> None:
    """Removes the run's dedicated queues so repeated runs leave nothing behind."""
    try:
        import pika
    except ImportError:
        return
    try:
        credentials = pika.PlainCredentials(os.getenv("RABBITMQ_USER", "guest"),
                                            os.getenv("RABBITMQ_PASSWORD", "guest"))
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=host, port=port, credentials=credentials))
        channel = connection.channel()
        for queue in queues:
            channel.queue_delete(queue=queue)
        connection.close()
    except Exception as error:  # cleanup is best-effort
        print(f"(could not delete the e2e queues: {error})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--no-triage", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    try:
        return run(args)
    except Failure as failure:
        print(f"\nFAILED: {failure}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
