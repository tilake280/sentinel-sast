"""Background import service.

Demo corpus for Sentinel SAST -- Python half. Same structure as the JavaScript
file: real vulnerabilities first, then the safe code that naive scanners flag.
"""

import hashlib
import html
import os
import pickle
import shlex
import subprocess

import requests
import yaml
from flask import Flask, redirect, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


# ---------------------------------------------------------------------------
# REAL VULNERABILITIES
# ---------------------------------------------------------------------------


@app.route("/import")
def import_records():
    """SQL injection: request data concatenated into the statement."""
    cursor = connection.cursor()
    source = request.args["source"]
    cursor.execute("SELECT * FROM imports WHERE source = '" + source + "'")
    return cursor.fetchall()


@app.route("/convert")
def convert():
    """Command injection: os.system runs its argument through a shell."""
    target = request.args["target"]
    os.system("convert /tmp/in.png " + target)
    return "ok"


@app.route("/restore", methods=["POST"])
def restore():
    """Insecure deserialization: pickle can instantiate arbitrary objects."""
    return str(pickle.loads(request.data))


@app.route("/config", methods=["POST"])
def load_config():
    """yaml.load without SafeLoader constructs arbitrary Python objects."""
    return str(yaml.load(request.data))


@app.route("/proxy")
def proxy():
    """SSRF: the request destination is attacker-chosen."""
    return requests.get(request.args["url"]).text


@app.route("/next")
def go_next():
    """Open redirect: the destination is attacker-chosen."""
    return redirect(request.args["next"])


@app.route("/read")
def read_file():
    """Path traversal: the filename comes from the request."""
    name = request.args["name"]
    with open("/var/data/" + name) as handle:
        return handle.read()


def run_command(cmd):
    """Interprocedural: the sink lives here, the source lives in the caller."""
    subprocess.run(cmd, shell=True)


@app.route("/backup")
def backup():
    run_command("tar czf /tmp/backup.tgz " + request.args["dir"])
    return "started"


def digest(payload):
    """Weak cryptography: MD5 is collision-broken."""
    return hashlib.md5(payload).hexdigest()


# ---------------------------------------------------------------------------
# SAFE CODE THAT NAIVE SCANNERS FLAG ANYWAY
# ---------------------------------------------------------------------------


@app.route("/records")
def records_by_id():
    """Parameter binding -- psycopg2 escapes the bound value."""
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM records WHERE id = %s", (request.args["id"],))
    return cursor.fetchall()


@app.route("/records-typed")
def records_by_int():
    """Numeric coercion: an int cannot carry a SQL payload."""
    cursor = connection.cursor()
    record_id = int(request.args["id"])
    cursor.execute("SELECT * FROM records WHERE id = " + str(record_id))
    return cursor.fetchall()


@app.route("/safe-convert")
def safe_convert():
    """shlex.quote makes the value safe to place in a shell string."""
    target = shlex.quote(request.args["target"])
    os.system("convert /tmp/in.png " + target)
    return "ok"


@app.route("/safe-run")
def safe_run():
    """Argument-vector form with a constant binary; no shell is involved."""
    subprocess.run(["git", "status"], cwd="/srv/repo", check=True)
    return "ok"


@app.route("/safe-read")
def safe_read():
    """secure_filename strips traversal sequences."""
    name = secure_filename(request.args["name"])
    with open("/var/data/" + name) as handle:
        return handle.read()


@app.route("/safe-render")
def safe_render():
    """Escaped before rendering."""
    return "<p>" + html.escape(request.args["name"]) + "</p>"


def log_request(name):
    """A tainted value reaching a logging sink is Low severity, not Critical."""
    app.logger.info("user requested: " + name)


API_KEY = os.environ["IMPORTER_API_KEY"]  # not a hardcoded secret
