package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ---- Fakes -----------------------------------------------------------------

// memoryStore is the Store the handler tests run against. It keeps the same
// promises as PostgresStore -- duplicate detection, replace-on-save, upsert of
// unknown scans -- so a test that passes here describes real behaviour. The
// Postgres implementation is checked against the same expectations in
// store_test.go.
type memoryStore struct {
	mu       sync.Mutex
	scans    map[string]Scan
	findings map[string][]Finding
	failOn   string // method name that should return an error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{scans: map[string]Scan{}, findings: map[string][]Finding{}}
}

var errStoreDown = errors.New("store is down")

func (m *memoryStore) CreateScan(_ context.Context, scan Scan) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOn == "CreateScan" {
		return false, errStoreDown
	}
	if _, exists := m.scans[scan.ID]; exists {
		return false, nil
	}
	scan.Status = StatusPending
	scan.CreatedAt = time.Now()
	m.scans[scan.ID] = scan
	return true, nil
}

func (m *memoryStore) FailScan(_ context.Context, id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	scan := m.scans[id]
	scan.Status, scan.Error = StatusFailed, reason
	m.scans[id] = scan
	return nil
}

func (m *memoryStore) SaveResult(_ context.Context, result ScanResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOn == "SaveResult" {
		return errStoreDown
	}
	scan, exists := m.scans[result.JobID]
	if !exists {
		scan = Scan{ID: result.JobID, Repository: result.Repository, Commit: result.Commit,
			CreatedAt: time.Now()}
	}
	scan.Status = StatusCompleted
	if result.Status == StatusFailed {
		scan.Status = StatusFailed
	}
	now := time.Now()
	scan.CompletedAt = &now
	scan.Error = result.Error
	scan.FilesScanned = result.Summary.FilesScanned
	scan.Findings = len(result.Findings)
	scan.Escalated = result.Summary.Escalated
	scan.Suppressed = result.Summary.Suppressed
	scan.Untriaged = result.Summary.Untriaged
	scan.WorkerVersion = result.WorkerVersion
	m.scans[result.JobID] = scan
	m.findings[result.JobID] = append([]Finding{}, result.Findings...)
	return nil
}

func (m *memoryStore) ListScans(_ context.Context, limit int) ([]Scan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	scans := []Scan{}
	for _, scan := range m.scans {
		scans = append(scans, scan)
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].CreatedAt.After(scans[j].CreatedAt) })
	if len(scans) > limit {
		scans = scans[:limit]
	}
	return scans, nil
}

func (m *memoryStore) GetScan(_ context.Context, id string) (Scan, []Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	scan, exists := m.scans[id]
	if !exists {
		return Scan{}, nil, ErrScanNotFound
	}
	return scan, append([]Finding{}, m.findings[id]...), nil
}

func (m *memoryStore) Stats(_ context.Context) (Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var stats Stats
	for _, scan := range m.scans {
		stats.Scans++
		switch scan.Status {
		case StatusPending:
			stats.Pending++
		case StatusCompleted:
			stats.Completed++
		case StatusFailed:
			stats.Failed++
		}
		stats.Findings += scan.Findings
		stats.Escalated += scan.Escalated
		stats.Suppressed += scan.Suppressed
		stats.Untriaged += scan.Untriaged
	}
	return stats, nil
}

type published struct {
	queue string
	body  []byte
}

type fakePublisher struct {
	mu       sync.Mutex
	messages []published
	err      error
}

func (p *fakePublisher) Publish(_ context.Context, queue string, body []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.messages = append(p.messages, published{queue, append([]byte{}, body...)})
	return nil
}

// fakeFetcher serves file contents keyed by path and records what was asked.
type fakeFetcher struct {
	files    map[string][]byte
	errs     map[string]error
	requests []string
}

func (f *fakeFetcher) Fetch(_ context.Context, repository, commit, path string) ([]byte, error) {
	f.requests = append(f.requests, fmt.Sprintf("%s@%s:%s", repository, commit, path))
	if err, failing := f.errs[path]; failing {
		return nil, err
	}
	content, exists := f.files[path]
	if !exists {
		return nil, ErrFileNotFound
	}
	return content, nil
}

// ---- Harness ---------------------------------------------------------------

const testSecret = "it's a secret to everybody"

type harness struct {
	app       *fiber.App
	store     *memoryStore
	publisher *fakePublisher
	fetcher   *fakeFetcher
}

func newHarness(secret string) *harness {
	h := &harness{
		store:     newMemoryStore(),
		publisher: &fakePublisher{},
		fetcher:   &fakeFetcher{files: map[string][]byte{}, errs: map[string]error{}},
	}
	h.app = NewApp(Deps{
		Store:     h.store,
		Publisher: h.publisher,
		Fetcher:   h.fetcher,
		Secret:    secret,
		ScanQueue: "scan_jobs",
		// Inline, so the fetch-and-publish step has finished by the time the
		// request returns and the test can assert on it directly.
		Dispatch: func(work func()) { work() },
	})
	return h
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type response struct {
	status int
	body   map[string]any
	raw    string
}

func (h *harness) do(t *testing.T, req *http.Request) response {
	t.Helper()
	resp, err := h.app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := response{status: resp.StatusCode, raw: string(raw)}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

func (h *harness) get(t *testing.T, path string) response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	return h.do(t, req)
}

// webhook posts a delivery. signature "" means "sign it correctly".
func (h *harness) webhook(t *testing.T, event, delivery string, body []byte, signature string) response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	switch signature {
	case "":
		req.Header.Set("X-Hub-Signature-256", sign(testSecret, body))
	case "none":
	default:
		req.Header.Set("X-Hub-Signature-256", signature)
	}
	return h.do(t, req)
}

const testCommit = "4f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a39"

// pushPayload is a GitHub push event trimmed to the fields the gateway reads.
func pushPayload(repository, after string, commits ...map[string][]string) []byte {
	list := []map[string][]string{}
	list = append(list, commits...)
	body, _ := json.Marshal(map[string]any{
		"ref":        "refs/heads/main",
		"after":      after,
		"repository": map[string]string{"full_name": repository},
		"commits":    list,
	})
	return body
}

// ---- Health ----------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	h := newHarness(testSecret)
	got := h.get(t, "/api/v1/health")
	if got.status != 200 {
		t.Fatalf("status = %d, want 200", got.status)
	}
	want := `{"message":"Sentinel API Gateway is running","status":"online"}`
	if got.raw != want {
		t.Errorf("body = %s, want %s", got.raw, want)
	}
}

// ---- Signature validation --------------------------------------------------

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	valid := sign(testSecret, body)

	cases := []struct {
		name   string
		secret string
		body   []byte
		header string
		want   bool
	}{
		{"correct signature", testSecret, body, valid, true},
		{"wrong secret", "another secret", body, valid, false},
		{"body tampered after signing", testSecret, []byte(`{"hello":"w0rld"}`), valid, false},
		{"missing header", testSecret, body, "", false},
		{"sha1 scheme is not accepted", testSecret, body, "sha1=" + valid[len("sha256="):], false},
		{"hex without the scheme prefix", testSecret, body, valid[len("sha256="):], false},
		{"not hex", testSecret, body, "sha256=zzzz", false},
		{"truncated digest", testSecret, body, valid[:len(valid)-2], false},
		{"empty secret never verifies", "", body, sign("", body), false},
	}
	for _, tc := range cases {
		if got := verifySignature(tc.secret, tc.body, tc.header); got != tc.want {
			t.Errorf("%s: verifySignature = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestWebhookRejectsUnsignedDelivery(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.files["src/app.js"] = []byte("eval(req.query.x)")
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"src/app.js"}})

	got := h.webhook(t, "push", "d-1", body, "none")
	if got.status != 401 {
		t.Fatalf("status = %d, want 401 (%s)", got.status, got.raw)
	}
	if len(h.store.scans) != 0 || len(h.publisher.messages) != 0 {
		t.Errorf("an unsigned delivery created %d scan(s) and published %d job(s)",
			len(h.store.scans), len(h.publisher.messages))
	}
}

func TestWebhookRejectsForgedSignature(t *testing.T) {
	h := newHarness(testSecret)
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"src/app.js"}})

	// Signed with the wrong key, and signed correctly but for a different body.
	for name, signature := range map[string]string{
		"wrong key":      sign("not the secret", body),
		"different body": sign(testSecret, []byte(`{}`)),
	} {
		got := h.webhook(t, "push", "d-1", body, signature)
		if got.status != 401 {
			t.Errorf("%s: status = %d, want 401", name, got.status)
		}
	}
	if len(h.store.scans) != 0 {
		t.Errorf("a forged delivery created a scan")
	}
}

func TestWebhookRefusedWhenSecretUnset(t *testing.T) {
	h := newHarness("")
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"src/app.js"}})

	// Even a delivery "signed" with the empty secret must not get through.
	got := h.webhook(t, "push", "d-1", body, sign("", body))
	if got.status != 503 {
		t.Fatalf("status = %d, want 503 (%s)", got.status, got.raw)
	}
	if len(h.store.scans) != 0 {
		t.Errorf("a delivery was accepted with no secret configured")
	}
}

// ---- Event handling --------------------------------------------------------

func TestWebhookPing(t *testing.T) {
	h := newHarness(testSecret)
	got := h.webhook(t, "ping", "d-ping", []byte(`{"zen":"Keep it logically awesome."}`), "")
	if got.status != 200 || got.body["status"] != "pong" {
		t.Errorf("ping: status = %d body = %s", got.status, got.raw)
	}
}

func TestWebhookIgnoresEventsItDoesNotScan(t *testing.T) {
	h := newHarness(testSecret)
	got := h.webhook(t, "issues", "d-2", []byte(`{"action":"opened"}`), "")
	if got.status != 202 || got.body["status"] != "ignored" {
		t.Fatalf("status = %d body = %s", got.status, got.raw)
	}
	if len(h.store.scans) != 0 {
		t.Errorf("a non-push event created a scan")
	}
}

func TestWebhookPushQueuesAScan(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.files["src/routes/users.js"] = []byte("db.query('SELECT ' + req.query.id);\n")
	h.fetcher.files["services/importer.py"] = []byte("import os\nos.system(request.args['c'])\n")

	body := pushPayload("acme/web", testCommit,
		map[string][]string{
			"added":    {"src/routes/users.js", "README.md", "scratch/tmp.js"},
			"modified": {"services/importer.py"},
			"removed":  {"internal/old.go"},
		},
		// A later commit in the same push removes a file the first one added.
		map[string][]string{"removed": {"scratch/tmp.js"}},
	)

	got := h.webhook(t, "push", "delivery-123", body, "")
	if got.status != 202 || got.body["status"] != "accepted" {
		t.Fatalf("status = %d body = %s", got.status, got.raw)
	}
	if got.body["scan_id"] != "delivery-123" {
		t.Errorf("scan_id = %v, want the delivery id", got.body["scan_id"])
	}

	// 1. The scan was recorded.
	scan, exists := h.store.scans["delivery-123"]
	if !exists {
		t.Fatalf("no scan row was created")
	}
	if scan.Status != StatusPending || scan.Repository != "acme/web" || scan.Commit != testCommit ||
		scan.Ref != "refs/heads/main" || scan.FilesQueued != 2 {
		t.Errorf("scan row = %+v", scan)
	}

	// 2. Only scannable files that survived the push were fetched, at the
	//    pushed commit.
	wantRequests := []string{
		"acme/web@" + testCommit + ":src/routes/users.js",
		"acme/web@" + testCommit + ":services/importer.py",
	}
	if strings.Join(h.fetcher.requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Errorf("fetched %v, want %v", h.fetcher.requests, wantRequests)
	}

	// 3. One job was published, in the shape the worker parses.
	if len(h.publisher.messages) != 1 {
		t.Fatalf("published %d message(s), want 1", len(h.publisher.messages))
	}
	message := h.publisher.messages[0]
	if message.queue != "scan_jobs" {
		t.Errorf("published to %q, want scan_jobs", message.queue)
	}
	var job ScanJob
	if err := json.Unmarshal(message.body, &job); err != nil {
		t.Fatalf("job is not valid JSON: %v", err)
	}
	if job.JobID != "delivery-123" || job.Repository != "acme/web" || job.Commit != testCommit {
		t.Errorf("job header = %+v", job)
	}
	if len(job.Files) != 2 || job.Files[0].Path != "src/routes/users.js" ||
		job.Files[0].Content != "db.query('SELECT ' + req.query.id);\n" ||
		job.Files[1].Path != "services/importer.py" {
		t.Errorf("job files = %+v", job.Files)
	}
}

func TestWebhookRedeliveryDoesNotScanTwice(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.files["a.py"] = []byte("x = 1\n")
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"a.py"}})

	first := h.webhook(t, "push", "delivery-9", body, "")
	second := h.webhook(t, "push", "delivery-9", body, "")

	if first.status != 202 {
		t.Fatalf("first delivery: status = %d", first.status)
	}
	if second.status != 200 || second.body["status"] != "duplicate" {
		t.Errorf("redelivery: status = %d body = %s", second.status, second.raw)
	}
	if len(h.publisher.messages) != 1 {
		t.Errorf("published %d job(s) for one delivery id, want 1", len(h.publisher.messages))
	}
}

func TestWebhookWithoutDeliveryIDStillGetsAScanID(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.files["a.go"] = []byte("package main\n")
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"a.go"}})

	got := h.webhook(t, "push", "", body, "")
	id, _ := got.body["scan_id"].(string)
	if got.status != 202 || len(id) < 16 {
		t.Fatalf("status = %d scan_id = %q", got.status, id)
	}
	if _, exists := h.store.scans[id]; !exists {
		t.Errorf("no scan row for generated id %q", id)
	}
}

func TestWebhookIgnoresPushWithNothingToScan(t *testing.T) {
	h := newHarness(testSecret)
	cases := map[string][]byte{
		"only unsupported files": pushPayload("acme/web", testCommit,
			map[string][]string{"added": {"README.md", "Dockerfile", "logo.png"}}),
		"no commits": pushPayload("acme/web", testCommit),
		"branch deleted": pushPayload("acme/web", strings.Repeat("0", 40),
			map[string][]string{"added": {"a.js"}}),
	}
	for name, body := range cases {
		got := h.webhook(t, "push", "", body, "")
		if got.status != 202 || got.body["status"] != "ignored" {
			t.Errorf("%s: status = %d body = %s", name, got.status, got.raw)
		}
	}
	if len(h.store.scans) != 0 || len(h.publisher.messages) != 0 {
		t.Errorf("an empty push created %d scan(s), %d job(s)", len(h.store.scans),
			len(h.publisher.messages))
	}
}

func TestWebhookRejectsMalformedPush(t *testing.T) {
	h := newHarness(testSecret)
	cases := map[string][]byte{
		"not JSON":                      []byte(`{"ref": `),
		"repository climbs out":         pushPayload("../../etc", testCommit, map[string][]string{"added": {"a.js"}}),
		"repository is a URL":           pushPayload("evil.example/x/y", testCommit, map[string][]string{"added": {"a.js"}}),
		"commit is not a SHA":           pushPayload("acme/web", "main; rm -rf /", map[string][]string{"added": {"a.js"}}),
		"commit missing":                pushPayload("acme/web", "", map[string][]string{"added": {"a.js"}}),
		"repository missing altogether": []byte(`{"after":"` + testCommit + `","commits":[{"added":["a.js"]}]}`),
	}
	for name, body := range cases {
		got := h.webhook(t, "push", "", body, "")
		if got.status != 400 {
			t.Errorf("%s: status = %d, want 400 (%s)", name, got.status, got.raw)
		}
	}
	if len(h.store.scans) != 0 || len(h.fetcher.requests) != 0 {
		t.Errorf("a malformed push reached the store or the fetcher")
	}
}

// ---- Fetch and publish failures --------------------------------------------

func TestWebhookSkipsFilesThatCannotBeScanned(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.files["ok.js"] = []byte("const a = 1;\n")
	h.fetcher.files["binary.py"] = []byte{0xff, 0xfe, 0x00, 0x01}
	h.fetcher.errs["huge.go"] = ErrFileTooLarge
	// gone.js is in the push but not at the commit: fakeFetcher returns
	// ErrFileNotFound for anything it does not have.

	body := pushPayload("acme/web", testCommit,
		map[string][]string{"added": {"ok.js", "binary.py", "huge.go", "gone.js"}})
	got := h.webhook(t, "push", "d-skip", body, "")
	if got.status != 202 {
		t.Fatalf("status = %d", got.status)
	}

	if len(h.publisher.messages) != 1 {
		t.Fatalf("published %d job(s), want 1", len(h.publisher.messages))
	}
	var job ScanJob
	_ = json.Unmarshal(h.publisher.messages[0].body, &job)
	if len(job.Files) != 1 || job.Files[0].Path != "ok.js" {
		t.Errorf("job files = %+v, want only ok.js", job.Files)
	}
	if h.store.scans["d-skip"].Status != StatusPending {
		t.Errorf("scan status = %s, want PENDING", h.store.scans["d-skip"].Status)
	}
}

func TestWebhookMarksScanFailedWhenNothingCanBeFetched(t *testing.T) {
	h := newHarness(testSecret)
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"gone.js"}})

	h.webhook(t, "push", "d-none", body, "")

	scan := h.store.scans["d-none"]
	if scan.Status != StatusFailed || !strings.Contains(scan.Error, "none of the changed files") {
		t.Errorf("scan = %+v", scan)
	}
	if len(h.publisher.messages) != 0 {
		t.Errorf("an empty job was published")
	}
}

func TestWebhookMarksScanFailedOnFetchError(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.errs["a.js"] = errors.New("HTTP 500")
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"a.js"}})

	h.webhook(t, "push", "d-fetch", body, "")

	scan := h.store.scans["d-fetch"]
	if scan.Status != StatusFailed || !strings.Contains(scan.Error, "could not fetch a.js") {
		t.Errorf("scan = %+v", scan)
	}
}

func TestWebhookMarksScanFailedWhenBrokerIsDown(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.files["a.js"] = []byte("const a = 1;\n")
	h.publisher.err = errors.New("dial tcp: connection refused")
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"a.js"}})

	got := h.webhook(t, "push", "d-broker", body, "")

	// The delivery itself was valid and was recorded; what failed came after.
	if got.status != 202 {
		t.Errorf("status = %d, want 202", got.status)
	}
	scan := h.store.scans["d-broker"]
	if scan.Status != StatusFailed || !strings.Contains(scan.Error, "could not queue the job") {
		t.Errorf("scan = %+v", scan)
	}
}

func TestWebhookReportsStoreFailure(t *testing.T) {
	h := newHarness(testSecret)
	h.store.failOn = "CreateScan"
	h.fetcher.files["a.js"] = []byte("const a = 1;\n")
	body := pushPayload("acme/web", testCommit, map[string][]string{"added": {"a.js"}})

	got := h.webhook(t, "push", "d-db", body, "")
	if got.status != 500 {
		t.Errorf("status = %d, want 500", got.status)
	}
	if strings.Contains(got.raw, errStoreDown.Error()) {
		t.Errorf("the response leaked the store error: %s", got.raw)
	}
	if len(h.publisher.messages) != 0 {
		t.Errorf("a job was published for a scan that could not be recorded")
	}
}

// ---- Results ---------------------------------------------------------------

// workerResult is a results-queue message as worker/src/job.cpp writes it.
const workerResult = `{
  "job_id": "delivery-123", "repository": "acme/web", "commit": "` + testCommit + `",
  "worker_version": "0.3.0", "status": "COMPLETED", "error": "",
  "summary": {"files_scanned": 2, "files_skipped": 0, "files_with_parse_errors": 0,
              "functions_analyzed": 3, "analysis_ms": 1.9, "findings": 3, "escalated": 1,
              "suppressed": 1, "untriaged": 1, "suppressed_inline": 0},
  "findings": [
    {"file": "src/routes/users.js", "line": 7, "column": 3, "vulnerability": "SQL Injection",
     "class": "sql-injection", "rule_id": "sentinel.javascript.sql-injection", "cwe": "CWE-89",
     "severity": "CRITICAL", "confidence": "HIGH", "message": "Untrusted input ...",
     "snippet": "db.query('SELECT ' + id);", "remediation": "Use parameterised queries.",
     "function": "search", "crosses_function_boundary": false,
     "trace": [{"line": 6, "snippet": "const id = req.query.id;", "description": "attacker input enters"}],
     "verdict": "ESCALATED", "triage_confidence": 0.33, "triage_reason": "nothing similar"},
    {"file": "src/routes/users.js", "line": 9, "column": 3, "vulnerability": "Log Injection",
     "class": "log-injection", "rule_id": "sentinel.javascript.log-injection", "cwe": "CWE-117",
     "severity": "LOW", "confidence": "MEDIUM", "message": "", "snippet": "console.log(q);",
     "remediation": "", "function": "", "crosses_function_boundary": false, "trace": [],
     "verdict": "SUPPRESSED", "triage_confidence": 0.96, "triage_reason": "matches a dismissed finding"},
    {"file": "services/importer.py", "line": 2, "column": 1, "vulnerability": "Command Injection",
     "class": "command-injection", "rule_id": "sentinel.python.command-injection", "cwe": "CWE-78",
     "severity": "CRITICAL", "confidence": "HIGH", "message": "", "snippet": "os.system(c)",
     "remediation": "", "function": "", "crosses_function_boundary": false, "trace": [],
     "verdict": "UNTRIAGED", "triage_confidence": 0, "triage_reason": "triage unavailable: timeout"}
  ]
}`

func TestResultCompletesTheScanAndIsServed(t *testing.T) {
	h := newHarness(testSecret)
	h.fetcher.files["src/routes/users.js"] = []byte("x")
	h.fetcher.files["services/importer.py"] = []byte("y")
	body := pushPayload("acme/web", testCommit,
		map[string][]string{"added": {"src/routes/users.js", "services/importer.py"}})
	h.webhook(t, "push", "delivery-123", body, "")

	if err := handleResult(context.Background(), h.store, []byte(workerResult)); err != nil {
		t.Fatalf("handleResult: %v", err)
	}

	// The scan the webhook created is now complete, with the push's ref kept.
	got := h.get(t, "/api/v1/scans/delivery-123")
	if got.status != 200 {
		t.Fatalf("GET scan: status = %d (%s)", got.status, got.raw)
	}
	scan := got.body["scan"].(map[string]any)
	if scan["status"] != StatusCompleted || scan["ref"] != "refs/heads/main" ||
		scan["findings"] != float64(3) || scan["escalated"] != float64(1) ||
		scan["suppressed"] != float64(1) || scan["untriaged"] != float64(1) ||
		scan["worker_version"] != "0.3.0" {
		t.Errorf("scan = %v", scan)
	}

	findings := got.body["findings"].([]any)
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	verdicts := map[string]string{}
	for _, raw := range findings {
		finding := raw.(map[string]any)
		verdicts[finding["vulnerability"].(string)] = finding["verdict"].(string)
	}
	want := map[string]string{
		"SQL Injection": "ESCALATED", "Log Injection": "SUPPRESSED", "Command Injection": "UNTRIAGED",
	}
	for vulnerability, verdict := range want {
		if verdicts[vulnerability] != verdict {
			t.Errorf("%s: verdict = %q, want %q", vulnerability, verdicts[vulnerability], verdict)
		}
	}
	first := findings[0].(map[string]any)
	if first["triage_reason"] != "nothing similar" || first["cwe"] != "CWE-89" ||
		len(first["trace"].([]any)) != 1 {
		t.Errorf("finding detail lost in storage: %v", first)
	}

	// And it shows up in the list and the totals.
	list := h.get(t, "/api/v1/scans")
	if scans := list.body["scans"].([]any); len(scans) != 1 {
		t.Errorf("list has %d scans, want 1", len(scans))
	}
	stats := h.get(t, "/api/v1/stats")
	if stats.body["scans"] != float64(1) || stats.body["completed"] != float64(1) ||
		stats.body["findings"] != float64(3) || stats.body["suppressed"] != float64(1) {
		t.Errorf("stats = %s", stats.raw)
	}
}

func TestResultForUnknownScanCreatesIt(t *testing.T) {
	// scripts/publish_test_job.py puts a job straight on the queue, so its
	// result arrives with no scan row behind it.
	h := newHarness(testSecret)
	if err := handleResult(context.Background(), h.store, []byte(workerResult)); err != nil {
		t.Fatalf("handleResult: %v", err)
	}
	scan, exists := h.store.scans["delivery-123"]
	if !exists || scan.Status != StatusCompleted || scan.Repository != "acme/web" {
		t.Errorf("scan = %+v (exists=%v)", scan, exists)
	}
}

func TestResultDeliveredTwiceIsStoredOnce(t *testing.T) {
	h := newHarness(testSecret)
	for i := 0; i < 2; i++ {
		if err := handleResult(context.Background(), h.store, []byte(workerResult)); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}
	if got := len(h.store.findings["delivery-123"]); got != 3 {
		t.Errorf("after a redelivery the scan has %d findings, want 3", got)
	}
}

func TestFailedResultMarksTheScanFailed(t *testing.T) {
	h := newHarness(testSecret)
	body := `{"job_id":"j-1","repository":"acme/web","status":"FAILED","error":"boom","findings":[]}`
	if err := handleResult(context.Background(), h.store, []byte(body)); err != nil {
		t.Fatalf("handleResult: %v", err)
	}
	if scan := h.store.scans["j-1"]; scan.Status != StatusFailed || scan.Error != "boom" {
		t.Errorf("scan = %+v", scan)
	}
}

func TestUnusableResultIsDroppedNotRetried(t *testing.T) {
	h := newHarness(testSecret)
	for name, body := range map[string]string{
		"not JSON":  `{"job_id": `,
		"no job id": `{"repository":"acme/web","findings":[]}`,
	} {
		err := handleResult(context.Background(), h.store, []byte(body))
		if !errors.Is(err, errPoisonResult) {
			t.Errorf("%s: err = %v, want errPoisonResult", name, err)
		}
	}
}

func TestStoreOutageIsRetriedNotDropped(t *testing.T) {
	h := newHarness(testSecret)
	h.store.failOn = "SaveResult"
	err := handleResult(context.Background(), h.store, []byte(workerResult))
	if err == nil || errors.Is(err, errPoisonResult) {
		t.Errorf("err = %v, want a retryable error", err)
	}
}

// ---- Read API --------------------------------------------------------------

func TestGetUnknownScanIs404(t *testing.T) {
	h := newHarness(testSecret)
	if got := h.get(t, "/api/v1/scans/nope"); got.status != 404 {
		t.Errorf("status = %d, want 404", got.status)
	}
}

func TestEmptyStoreServesEmptyListNotNull(t *testing.T) {
	h := newHarness(testSecret)
	got := h.get(t, "/api/v1/scans")
	if got.status != 200 || got.raw != `{"scans":[]}` {
		t.Errorf("status = %d body = %s", got.status, got.raw)
	}
}

// ---- Push parsing ----------------------------------------------------------

func TestChangedFiles(t *testing.T) {
	var push pushEvent
	_ = json.Unmarshal(pushPayload("acme/web", testCommit,
		map[string][]string{"added": {"a.js", "b.py", "notes.txt"}, "modified": {"c.go"}},
		map[string][]string{"modified": {"a.js"}, "removed": {"b.py"}},
		map[string][]string{"added": {"d.ts", "b.py"}, "removed": {"c.go"}},
	), &push)

	// a.js: added then modified -> once. b.py: added, removed, re-added -> kept.
	// c.go: modified then removed -> gone. notes.txt: not source.
	want := "a.js b.py d.ts"
	if got := strings.Join(push.changedFiles(), " "); got != want {
		t.Errorf("changedFiles = %q, want %q", got, want)
	}
}

// ---- Fetcher ---------------------------------------------------------------

func TestRawFetcher(t *testing.T) {
	var seenAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/acme/web/" + testCommit + "/src/app.js":
			io.WriteString(w, "eval(x)\n")
		case "/acme/web/" + testCommit + "/dir with space/a b.py":
			io.WriteString(w, "spaced\n")
		case "/acme/web/" + testCommit + "/big.go":
			w.Write(bytes.Repeat([]byte("a"), maxFileBytes+1))
		case "/acme/web/" + testCommit + "/edge.go":
			w.Write(bytes.Repeat([]byte("a"), maxFileBytes))
		case "/acme/web/" + testCommit + "/broken.js":
			http.Error(w, "upstream", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fetcher := NewRawFetcher(server.URL+"/", "tok-123")
	ctx := context.Background()

	content, err := fetcher.Fetch(ctx, "acme/web", testCommit, "src/app.js")
	if err != nil || string(content) != "eval(x)\n" {
		t.Errorf("fetch = %q, %v", content, err)
	}
	if seenAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q", seenAuth)
	}

	if content, err := fetcher.Fetch(ctx, "acme/web", testCommit, "dir with space/a b.py"); err != nil ||
		string(content) != "spaced\n" {
		t.Errorf("path with spaces: %q, %v", content, err)
	}
	if _, err := fetcher.Fetch(ctx, "acme/web", testCommit, "missing.js"); !errors.Is(err, ErrFileNotFound) {
		t.Errorf("missing file: err = %v, want ErrFileNotFound", err)
	}
	if _, err := fetcher.Fetch(ctx, "acme/web", testCommit, "big.go"); !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("oversized file: err = %v, want ErrFileTooLarge", err)
	}
	if content, err := fetcher.Fetch(ctx, "acme/web", testCommit, "edge.go"); err != nil ||
		len(content) != maxFileBytes {
		t.Errorf("file exactly at the limit: len = %d, err = %v", len(content), err)
	}
	if _, err := fetcher.Fetch(ctx, "acme/web", testCommit, "broken.js"); err == nil ||
		errors.Is(err, ErrFileNotFound) {
		t.Errorf("upstream 502: err = %v, want a hard error", err)
	}

	// A pushed path must not be able to leave its repository.
	for _, path := range []string{"../other/secret.js", "a/../../b.js", "/etc/passwd.py", "a//b.js"} {
		if _, err := fetcher.Fetch(ctx, "acme/web", testCommit, path); err == nil ||
			!strings.Contains(err.Error(), "refusing path") {
			t.Errorf("path %q: err = %v, want it refused", path, err)
		}
	}
}
