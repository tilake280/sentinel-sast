package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// The handler tests use an in-memory Store. This runs the same expectations
// against the real one, because the SQL is where the mistakes would be.
//
// It needs a Postgres to talk to, so it is opt-in:
//
//	GATEWAY_TEST_DATABASE_URL=postgres://sentinel:password@localhost:5432/sentinel_db go test ./...
//
// Every row it writes has an id under a prefix unique to the run, and is
// deleted afterwards; it does not touch anything else in the database.
func TestPostgresStore(t *testing.T) {
	url := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL is not set; skipping the Postgres store test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := NewPostgresStore(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer store.Close()

	prefix := fmt.Sprintf("storetest-%d-", time.Now().UnixNano())
	defer store.pool.Exec(context.Background(), `DELETE FROM scans WHERE id LIKE $1`, prefix+"%")

	before, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}

	// ---- CreateScan and redelivery ----------------------------------------
	id := prefix + "a"
	scan := Scan{ID: id, Repository: "acme/web", Commit: testCommit, Ref: "refs/heads/main", FilesQueued: 2}

	created, err := store.CreateScan(ctx, scan)
	if err != nil || !created {
		t.Fatalf("CreateScan = %v, %v; want created", created, err)
	}
	created, err = store.CreateScan(ctx, scan)
	if err != nil || created {
		t.Errorf("second CreateScan = %v, %v; want not created", created, err)
	}

	got, findings, err := store.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.Status != StatusPending || got.Repository != "acme/web" || got.Commit != testCommit ||
		got.Ref != "refs/heads/main" || got.FilesQueued != 2 || got.CompletedAt != nil ||
		got.CreatedAt.IsZero() {
		t.Errorf("pending scan = %+v", got)
	}
	if findings == nil || len(findings) != 0 {
		t.Errorf("pending scan findings = %v, want an empty non-nil slice", findings)
	}

	// ---- SaveResult -------------------------------------------------------
	var result ScanResult
	if err := json.Unmarshal([]byte(workerResult), &result); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	result.JobID = id

	// Twice, as an at-least-once broker may deliver it.
	for delivery := 1; delivery <= 2; delivery++ {
		if err := store.SaveResult(ctx, result); err != nil {
			t.Fatalf("SaveResult (delivery %d): %v", delivery, err)
		}
	}

	got, findings, err = store.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("GetScan after result: %v", err)
	}
	if got.Status != StatusCompleted || got.CompletedAt == nil || got.Findings != 3 ||
		got.Escalated != 1 || got.Suppressed != 1 || got.Untriaged != 1 || got.FilesScanned != 2 ||
		got.WorkerVersion != "0.3.0" {
		t.Errorf("completed scan = %+v", got)
	}
	// What the webhook recorded survives the result.
	if got.Ref != "refs/heads/main" || got.FilesQueued != 2 {
		t.Errorf("result overwrote webhook fields: ref=%q files_queued=%d", got.Ref, got.FilesQueued)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings after two deliveries, want 3", len(findings))
	}

	// Review order: escalated, then untriaged, then suppressed.
	order := []string{findings[0].Verdict, findings[1].Verdict, findings[2].Verdict}
	if order[0] != "ESCALATED" || order[1] != "UNTRIAGED" || order[2] != "SUPPRESSED" {
		t.Errorf("verdict order = %v", order)
	}

	first := findings[0]
	if first.File != "src/routes/users.js" || first.Line != 7 || first.Column != 3 ||
		first.Vulnerability != "SQL Injection" || first.Class != "sql-injection" ||
		first.CWE != "CWE-89" || first.Severity != "CRITICAL" || first.Confidence != "HIGH" ||
		first.Function != "search" || first.TriageConfidence != 0.33 ||
		first.TriageReason != "nothing similar" || first.ID == 0 {
		t.Errorf("finding = %+v", first)
	}
	var trace []map[string]any
	if err := json.Unmarshal(first.Trace, &trace); err != nil || len(trace) != 1 ||
		trace[0]["line"] != float64(6) {
		t.Errorf("trace = %s (%v)", first.Trace, err)
	}

	// ---- A result with no scan row behind it ------------------------------
	orphan := result
	orphan.JobID = prefix + "b"
	if err := store.SaveResult(ctx, orphan); err != nil {
		t.Fatalf("SaveResult (no scan row): %v", err)
	}
	if got, _, err := store.GetScan(ctx, orphan.JobID); err != nil ||
		got.Status != StatusCompleted || got.Repository != "acme/web" {
		t.Errorf("orphan scan = %+v, %v", got, err)
	}

	// ---- FailScan ---------------------------------------------------------
	failing := prefix + "c"
	if _, err := store.CreateScan(ctx, Scan{ID: failing, Repository: "acme/web"}); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := store.FailScan(ctx, failing, "could not queue the job"); err != nil {
		t.Fatalf("FailScan: %v", err)
	}
	if got, _, _ := store.GetScan(ctx, failing); got.Status != StatusFailed ||
		got.Error != "could not queue the job" || got.CompletedAt == nil {
		t.Errorf("failed scan = %+v", got)
	}

	// ---- Not found --------------------------------------------------------
	if _, _, err := store.GetScan(ctx, prefix+"missing"); !errors.Is(err, ErrScanNotFound) {
		t.Errorf("GetScan(missing) err = %v, want ErrScanNotFound", err)
	}

	// ---- Stats and listing ------------------------------------------------
	after, err := store.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if after.Scans-before.Scans != 3 || after.Completed-before.Completed != 2 ||
		after.Failed-before.Failed != 1 || after.Findings-before.Findings != 6 ||
		after.Escalated-before.Escalated != 2 || after.Suppressed-before.Suppressed != 2 ||
		after.Untriaged-before.Untriaged != 2 {
		t.Errorf("stats delta: before %+v after %+v", before, after)
	}

	scans, err := store.ListScans(ctx, 200)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	seen := 0
	for _, s := range scans {
		if len(s.ID) > len(prefix) && s.ID[:len(prefix)] == prefix {
			seen++
		}
	}
	if seen != 3 {
		t.Errorf("ListScans returned %d of this run's 3 scans", seen)
	}

	// ---- Cascade ----------------------------------------------------------
	if _, err := store.pool.Exec(ctx, `DELETE FROM scans WHERE id = $1`, id); err != nil {
		t.Fatalf("delete scan: %v", err)
	}
	var orphaned int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_id = $1`, id).
		Scan(&orphaned); err != nil || orphaned != 0 {
		t.Errorf("findings left after their scan was deleted: %d (%v)", orphaned, err)
	}
}
