package main

import (
	"encoding/json"
	"time"
)

// Scan lifecycle. A scan is PENDING from the moment its webhook is accepted
// until the worker reports back, and ends COMPLETED or FAILED.
const (
	StatusPending   = "PENDING"
	StatusCompleted = "COMPLETED"
	StatusFailed    = "FAILED"
)

// Scan is one row of the scans table and one element of GET /api/v1/scans.
type Scan struct {
	ID            string     `json:"id"`
	Repository    string     `json:"repository"`
	Commit        string     `json:"commit"`
	Ref           string     `json:"ref"`
	Status        string     `json:"status"`
	Error         string     `json:"error,omitempty"`
	FilesQueued   int        `json:"files_queued"`
	FilesScanned  int        `json:"files_scanned"`
	Findings      int        `json:"findings"`
	Escalated     int        `json:"escalated"`
	Suppressed    int        `json:"suppressed"`
	Untriaged     int        `json:"untriaged"`
	WorkerVersion string     `json:"worker_version,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at"`
}

// Finding is one row of the findings table. The JSON shape is the one the
// worker publishes, so a result decodes straight into it.
type Finding struct {
	ID               int64           `json:"id,omitempty"`
	File             string          `json:"file"`
	Line             int             `json:"line"`
	Column           int             `json:"column"`
	Vulnerability    string          `json:"vulnerability"`
	Class            string          `json:"class"`
	RuleID           string          `json:"rule_id"`
	CWE              string          `json:"cwe"`
	Severity         string          `json:"severity"`
	Confidence       string          `json:"confidence"`
	Message          string          `json:"message"`
	Snippet          string          `json:"snippet"`
	Remediation      string          `json:"remediation"`
	Function         string          `json:"function"`
	Trace            json.RawMessage `json:"trace"`
	Verdict          string          `json:"verdict"`
	TriageConfidence float64         `json:"triage_confidence"`
	TriageReason     string          `json:"triage_reason"`
}

// JobFile is one source file in a scan job.
type JobFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ScanJob is the message the worker consumes from the scan queue. Its shape is
// fixed by worker/src/job.cpp.
type ScanJob struct {
	JobID      string    `json:"job_id"`
	Repository string    `json:"repository"`
	Commit     string    `json:"commit"`
	Files      []JobFile `json:"files"`
}

// ScanResult is the message the worker publishes to the results queue.
type ScanResult struct {
	JobID         string `json:"job_id"`
	Repository    string `json:"repository"`
	Commit        string `json:"commit"`
	WorkerVersion string `json:"worker_version"`
	Status        string `json:"status"`
	Error         string `json:"error"`
	Summary       struct {
		FilesScanned int `json:"files_scanned"`
		Findings     int `json:"findings"`
		Escalated    int `json:"escalated"`
		Suppressed   int `json:"suppressed"`
		Untriaged    int `json:"untriaged"`
	} `json:"summary"`
	Findings []Finding `json:"findings"`
}

// Stats are the totals shown on the dashboard.
type Stats struct {
	Scans      int `json:"scans"`
	Pending    int `json:"pending"`
	Completed  int `json:"completed"`
	Failed     int `json:"failed"`
	Findings   int `json:"findings"`
	Escalated  int `json:"escalated"`
	Suppressed int `json:"suppressed"`
	Untriaged  int `json:"untriaged"`
}
