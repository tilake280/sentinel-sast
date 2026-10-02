package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrScanNotFound is returned by GetScan for an id with no row.
var ErrScanNotFound = errors.New("scan not found")

// Store is everything the gateway needs from persistence. It is an interface
// so the HTTP handlers can be tested against an in-memory implementation; the
// Postgres one has its own test against a real database.
type Store interface {
	// CreateScan inserts a PENDING scan. created is false when a scan with
	// that id already exists, which is how a redelivered webhook is detected.
	CreateScan(ctx context.Context, scan Scan) (created bool, err error)

	// FailScan marks a scan FAILED with the reason.
	FailScan(ctx context.Context, id, reason string) error

	// SaveResult records a worker's result: the scan's final state and its
	// findings, atomically. A result for an unknown id creates the scan, so
	// jobs published straight to the queue still show up. Saving the same
	// result twice leaves one copy of the findings.
	SaveResult(ctx context.Context, result ScanResult) error

	ListScans(ctx context.Context, limit int) ([]Scan, error)
	GetScan(ctx context.Context, id string) (Scan, []Finding, error)
	Stats(ctx context.Context) (Stats, error)
}

const schema = `
CREATE TABLE IF NOT EXISTS scans (
    id             TEXT PRIMARY KEY,
    repository     TEXT NOT NULL,
    commit_sha     TEXT NOT NULL DEFAULT '',
    ref            TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL,
    error          TEXT NOT NULL DEFAULT '',
    files_queued   INTEGER NOT NULL DEFAULT 0,
    files_scanned  INTEGER NOT NULL DEFAULT 0,
    findings       INTEGER NOT NULL DEFAULT 0,
    escalated      INTEGER NOT NULL DEFAULT 0,
    suppressed     INTEGER NOT NULL DEFAULT 0,
    untriaged      INTEGER NOT NULL DEFAULT 0,
    worker_version TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS findings (
    id                BIGSERIAL PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file              TEXT NOT NULL,
    line              INTEGER NOT NULL DEFAULT 0,
    col               INTEGER NOT NULL DEFAULT 0,
    vulnerability     TEXT NOT NULL,
    class             TEXT NOT NULL DEFAULT '',
    rule_id           TEXT NOT NULL DEFAULT '',
    cwe               TEXT NOT NULL DEFAULT '',
    severity          TEXT NOT NULL,
    confidence        TEXT NOT NULL DEFAULT '',
    message           TEXT NOT NULL DEFAULT '',
    snippet           TEXT NOT NULL DEFAULT '',
    remediation       TEXT NOT NULL DEFAULT '',
    function_name     TEXT NOT NULL DEFAULT '',
    trace             JSONB NOT NULL DEFAULT '[]',
    verdict           TEXT NOT NULL,
    triage_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    triage_reason     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings (scan_id);
`

// PostgresStore is the Store backed by the project's Postgres.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects and creates the tables if they are missing.
func NewPostgresStore(ctx context.Context, url string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Close() { s.pool.Close() }

func (s *PostgresStore) CreateScan(ctx context.Context, scan Scan) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO scans (id, repository, commit_sha, ref, status, files_queued)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO NOTHING`,
		scan.ID, scan.Repository, scan.Commit, scan.Ref, StatusPending, scan.FilesQueued)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) FailScan(ctx context.Context, id, reason string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scans SET status = $2, error = $3, completed_at = now() WHERE id = $1`,
		id, StatusFailed, reason)
	return err
}

func (s *PostgresStore) SaveResult(ctx context.Context, result ScanResult) error {
	status := StatusCompleted
	if result.Status == StatusFailed {
		status = StatusFailed
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	// Rollback after a successful Commit is a no-op.
	defer tx.Rollback(ctx)

	// The upsert covers a result whose scan row was never created: a job
	// published straight to the queue rather than through a webhook.
	_, err = tx.Exec(ctx, `
		INSERT INTO scans (id, repository, commit_sha, status, error, files_scanned, findings,
		                   escalated, suppressed, untriaged, worker_version, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
		ON CONFLICT (id) DO UPDATE SET
		    status = EXCLUDED.status,
		    error = EXCLUDED.error,
		    files_scanned = EXCLUDED.files_scanned,
		    findings = EXCLUDED.findings,
		    escalated = EXCLUDED.escalated,
		    suppressed = EXCLUDED.suppressed,
		    untriaged = EXCLUDED.untriaged,
		    worker_version = EXCLUDED.worker_version,
		    completed_at = EXCLUDED.completed_at`,
		result.JobID, result.Repository, result.Commit, status, result.Error,
		result.Summary.FilesScanned, len(result.Findings), result.Summary.Escalated,
		result.Summary.Suppressed, result.Summary.Untriaged, result.WorkerVersion)
	if err != nil {
		return fmt.Errorf("upsert scan: %w", err)
	}

	// The broker delivers at least once, so the same result can arrive twice.
	// Replacing rather than appending keeps that from doubling the findings.
	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE scan_id = $1`, result.JobID); err != nil {
		return fmt.Errorf("clear findings: %w", err)
	}

	for _, f := range result.Findings {
		trace := string(f.Trace)
		if trace == "" {
			trace = "[]"
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO findings (scan_id, file, line, col, vulnerability, class, rule_id, cwe,
			                      severity, confidence, message, snippet, remediation,
			                      function_name, trace, verdict, triage_confidence, triage_reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb,
			        $16, $17, $18)`,
			result.JobID, f.File, f.Line, f.Column, f.Vulnerability, f.Class, f.RuleID, f.CWE,
			f.Severity, f.Confidence, f.Message, f.Snippet, f.Remediation, f.Function, trace,
			f.Verdict, f.TriageConfidence, f.TriageReason)
		if err != nil {
			return fmt.Errorf("insert finding %s:%d: %w", f.File, f.Line, err)
		}
	}

	return tx.Commit(ctx)
}

const scanColumns = `id, repository, commit_sha, ref, status, error, files_queued, files_scanned,
	findings, escalated, suppressed, untriaged, worker_version, created_at, completed_at`

func scanInto(row pgx.Row, scan *Scan) error {
	return row.Scan(&scan.ID, &scan.Repository, &scan.Commit, &scan.Ref, &scan.Status, &scan.Error,
		&scan.FilesQueued, &scan.FilesScanned, &scan.Findings, &scan.Escalated, &scan.Suppressed,
		&scan.Untriaged, &scan.WorkerVersion, &scan.CreatedAt, &scan.CompletedAt)
}

func (s *PostgresStore) ListScans(ctx context.Context, limit int) ([]Scan, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scanColumns+` FROM scans ORDER BY created_at DESC, id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scans := []Scan{}
	for rows.Next() {
		var scan Scan
		if err := scanInto(rows, &scan); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

func (s *PostgresStore) GetScan(ctx context.Context, id string) (Scan, []Finding, error) {
	var scan Scan
	err := scanInto(s.pool.QueryRow(ctx, `SELECT `+scanColumns+` FROM scans WHERE id = $1`, id), &scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scan{}, nil, ErrScanNotFound
	}
	if err != nil {
		return Scan{}, nil, err
	}

	// Escalated first, then by severity: the order a reviewer wants to read in.
	rows, err := s.pool.Query(ctx, `
		SELECT id, file, line, col, vulnerability, class, rule_id, cwe, severity, confidence,
		       message, snippet, remediation, function_name, trace, verdict,
		       triage_confidence, triage_reason
		FROM findings
		WHERE scan_id = $1
		ORDER BY CASE verdict WHEN 'ESCALATED' THEN 0 WHEN 'UNTRIAGED' THEN 1 ELSE 2 END,
		         CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
		                       WHEN 'LOW' THEN 3 ELSE 4 END,
		         file, line, id`, id)
	if err != nil {
		return Scan{}, nil, err
	}
	defer rows.Close()

	findings := []Finding{}
	for rows.Next() {
		var f Finding
		var trace []byte
		if err := rows.Scan(&f.ID, &f.File, &f.Line, &f.Column, &f.Vulnerability, &f.Class,
			&f.RuleID, &f.CWE, &f.Severity, &f.Confidence, &f.Message, &f.Snippet, &f.Remediation,
			&f.Function, &trace, &f.Verdict, &f.TriageConfidence, &f.TriageReason); err != nil {
			return Scan{}, nil, err
		}
		f.Trace = trace
		findings = append(findings, f)
	}
	return scan, findings, rows.Err()
}

func (s *PostgresStore) Stats(ctx context.Context) (Stats, error) {
	var stats Stats
	err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE status = 'PENDING'),
		       count(*) FILTER (WHERE status = 'COMPLETED'),
		       count(*) FILTER (WHERE status = 'FAILED'),
		       coalesce(sum(findings), 0),
		       coalesce(sum(escalated), 0),
		       coalesce(sum(suppressed), 0),
		       coalesce(sum(untriaged), 0)
		FROM scans`).Scan(&stats.Scans, &stats.Pending, &stats.Completed, &stats.Failed,
		&stats.Findings, &stats.Escalated, &stats.Suppressed, &stats.Untriaged)
	return stats, err
}
