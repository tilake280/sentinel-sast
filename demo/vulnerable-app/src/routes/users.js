// Express user routes.
//
// Demo corpus for Sentinel SAST. Contains both real vulnerabilities and code
// that *looks* vulnerable but is not -- the second group is the interesting
// half, because that is what a naive scanner reports and a developer stops
// reading the tool over.

const express = require('express');
const mysql = require('mysql2');
const child_process = require('child_process');
const path = require('path');
const fs = require('fs');
const escapeHtml = require('escape-html');

const router = express.Router();
const db = mysql.createConnection({ host: 'localhost', user: 'app' });
const logger = winston.createLogger({});

// ---------------------------------------------------------------------------
// REAL VULNERABILITIES
// ---------------------------------------------------------------------------

// SQL injection: request data concatenated straight into the statement.
router.get('/search', (req, res) => {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'", (err, rows) => {
    res.json(rows);
  });
});

// SQL injection across three hops. A single top-to-bottom pass would still
// catch this one; the fixpoint matters for the reversed-order case below.
router.get('/lookup', (req, res) => {
  const raw = req.query.id;
  const trimmed = raw;
  const target = trimmed;
  db.query('SELECT * FROM users WHERE id = ' + target);
});

// Command injection: attacker controls part of the shell string.
router.get('/ping', (req, res) => {
  const host = req.query.host;
  child_process.exec('ping -c 1 ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

// Path traversal: the filename comes from the request.
router.get('/download', (req, res) => {
  const file = req.query.file;
  fs.readFile('/var/data/' + file, (err, data) => {
    res.send(data);
  });
});

// SSRF: the request destination is attacker-chosen.
router.post('/fetch-avatar', async (req, res) => {
  const url = req.body.avatarUrl;
  const response = await fetch(url);
  res.json(await response.json());
});

// Interprocedural: neither function contains a source-to-sink flow on its own.
function runReport(sql) {
  return db.query(sql);
}

router.get('/report', (req, res) => {
  runReport('SELECT * FROM reports WHERE owner = ' + req.query.owner);
});

// Wrong sanitizer for the sink. HTML-escaping does nothing for SQL, and this
// is exactly the case a boolean taint model cannot express.
router.get('/by-email', (req, res) => {
  const email = escapeHtml(req.query.email);
  db.query("SELECT * FROM users WHERE email = '" + email + "'");
});

// ---------------------------------------------------------------------------
// SAFE CODE THAT NAIVE SCANNERS FLAG ANYWAY
// ---------------------------------------------------------------------------

// Parameterised query. Shares almost every token with the vulnerable version
// above, but the driver binds the value rather than splicing it in.
router.get('/by-id', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.params.id], (err, rows) => {
    res.json(rows);
  });
});

// Numeric coercion: a number cannot carry a SQL payload.
router.get('/page', (req, res) => {
  const page = parseInt(req.query.page, 10);
  db.query('SELECT * FROM users LIMIT 20 OFFSET ' + page);
});

// RegExp.exec, not child_process.exec. Name-based sink matching reports this;
// receiver-type inference does not.
const USERNAME_PATTERN = /^[a-z0-9_]{3,20}$/;
router.get('/validate', (req, res) => {
  const ok = USERNAME_PATTERN.exec(req.query.username);
  res.json({ valid: Boolean(ok) });
});

// Correctly escaped before rendering.
router.get('/greeting', (req, res) => {
  const el = document.getElementById('greeting');
  el.innerHTML = escapeHtml(req.query.name);
});

// Path reduced to a basename, so traversal sequences cannot escape the root.
router.get('/safe-download', (req, res) => {
  const file = path.basename(req.query.file);
  fs.readFile('/var/data/' + file, (err, data) => res.send(data));
});

// A constant query with no user input anywhere near it.
router.get('/stats', (req, res) => {
  db.query('SELECT COUNT(*) AS total FROM users');
});

// Reviewed and accepted: the table name comes from an internal enum, not the
// request. The directive records who decided that and why, and must sit on or
// directly above the flagged line.
router.get('/admin/dump', (req, res) => {
  // sentinel:ignore sql-injection -- table name is from an internal allowlist, reviewed 2026-03-11
  db.query('SELECT * FROM ' + INTERNAL_TABLES[req.query.table]);
});

module.exports = router;
