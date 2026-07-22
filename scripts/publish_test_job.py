#!/usr/bin/env python3
"""Publish a sample scan job onto the RabbitMQ queue the C++ worker consumes.

Usage:  ai-layer/venv/bin/python scripts/publish_test_job.py
"""

import json
import os
import uuid

import pika

QUEUE = os.getenv("SCAN_QUEUE", "scan_jobs")
HOST = os.getenv("RABBITMQ_HOST", "localhost")
PORT = int(os.getenv("RABBITMQ_PORT", "5672"))

# A file mixing genuine vulnerabilities with patterns the AI layer has learned
# to dismiss, so one job exercises both verdict paths.
VULNERABLE_JS = """\
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const term = req.query.term;
  console.log('search term was: ' + req.query.term);
  db.query('SELECT * FROM products WHERE name = ' + term);
  res.send('ok');
});

app.get('/profile', (req, res) => {
  const name = req.query.name;
  document.getElementById('greeting').innerHTML = name;
  element.textContent = req.query.subtitle;
});

app.post('/calc', (req, res) => {
  eval(req.body.expression);
});
"""

VULNERABLE_PY = """\
import os
import subprocess

def ping(request):
    host = request.args.get('host')
    os.system("ping -c 1 " + host)

def safe_lookup(cursor, kind):
    cursor.execute('SELECT * FROM events WHERE kind = %s', (kind,))

def read_config(request):
    path = request.args.get('path')
    return open(path).read()
"""

# Code that the taint engine flags -- user input really does reach a query/file
# sink -- but which is safe in practice. This is exactly the noise the AI layer
# exists to suppress, so it exercises the suppression path.
SAFE_BUT_FLAGGED_JS = """\
app.get('/user/:id', (req, res) => {
  db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
});

app.get('/events', (req, res) => {
  const kind = req.query.kind;
  cursor.execute('SELECT * FROM events WHERE kind = %s', (kind,));
});
"""

VULNERABLE_GO = """\
package main

import (
	"net/http"
	"os/exec"
)

func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	exec.Command("ping", "-c", "1", host)
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	// Constant query: not attacker controlled, must not be reported.
	db.Query("SELECT count(*) FROM users")
}
"""

job = {
    "job_id": str(uuid.uuid4())[:8],
    "repository": "acme/webapp",
    "commit": "a1b2c3d",
    "files": [
        {"path": "src/routes/user.js", "content": VULNERABLE_JS},
        {"path": "api/handlers.py", "content": VULNERABLE_PY},
        {"path": "src/routes/safe.js", "content": SAFE_BUT_FLAGGED_JS},
        {"path": "internal/api/handlers.go", "content": VULNERABLE_GO},
    ],
}

connection = pika.BlockingConnection(pika.ConnectionParameters(host=HOST, port=PORT))
channel = connection.channel()
channel.queue_declare(queue=QUEUE, durable=True)
channel.basic_publish(
    exchange="",
    routing_key=QUEUE,
    body=json.dumps(job),
    properties=pika.BasicProperties(delivery_mode=2),
)
connection.close()

print(f"Published job {job['job_id']} ({len(job['files'])} files) to '{QUEUE}'")
