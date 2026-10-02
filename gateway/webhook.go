package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// maxJobBytes caps the total source put into one scan job. The job is a single
// queue message; this keeps it well inside the broker's message size limit.
const maxJobBytes = 8 << 20

// verifySignature checks GitHub's X-Hub-Signature-256 header: "sha256=" plus
// the hex HMAC-SHA256 of the raw request body under the shared secret.
//
// The comparison is constant-time. A byte-by-byte compare that returns at the
// first mismatch leaks, through response timing, how much of a forged
// signature was right.
func verifySignature(secret string, body []byte, header string) bool {
	const prefix = "sha256="
	if secret == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	given, err := hex.DecodeString(header[len(prefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(given, mac.Sum(nil))
}

// pushEvent is the part of a GitHub push payload the gateway reads.
type pushEvent struct {
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Deleted    bool   `json:"deleted"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Commits []struct {
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"commits"`
}

// These values become part of a URL the gateway requests, so they are checked
// against what GitHub actually sends rather than passed through.
var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	deliveryPattern   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

func (p pushEvent) validate() error {
	if !repositoryPattern.MatchString(p.Repository.FullName) ||
		strings.Contains(p.Repository.FullName, "..") {
		return fmt.Errorf("repository.full_name %q is not owner/name", p.Repository.FullName)
	}
	if !commitPattern.MatchString(p.After) {
		return fmt.Errorf("after %q is not a commit SHA", p.After)
	}
	return nil
}

// branchDeleted reports a push that removed a ref. Its `after` is all zeros
// and there is nothing at that commit to scan.
func (p pushEvent) branchDeleted() bool {
	return p.Deleted || (p.After != "" && strings.Trim(p.After, "0") == "")
}

// changedFiles lists the files the push left added or modified, in first-seen
// order. Commits are replayed in sequence so a file added in one commit and
// removed in a later one is not fetched.
func (p pushEvent) changedFiles() []string {
	present := map[string]bool{}
	order := []string{}

	touch := func(path string) {
		if _, seen := present[path]; !seen {
			order = append(order, path)
		}
		present[path] = true
	}

	for _, commit := range p.Commits {
		for _, path := range commit.Added {
			touch(path)
		}
		for _, path := range commit.Modified {
			touch(path)
		}
		for _, path := range commit.Removed {
			if _, seen := present[path]; seen {
				present[path] = false
			}
		}
	}

	files := []string{}
	for _, path := range order {
		if present[path] && isScannable(path) {
			files = append(files, path)
		}
	}
	return files
}

// handleWebhook is POST /api/v1/webhook.
//
// It does the cheap, synchronous part -- authenticate, record the scan -- and
// answers. Fetching sources and queueing the job happen afterwards, because
// GitHub gives a webhook ten seconds and a push can touch many files.
func (d Deps) handleWebhook(c *fiber.Ctx) error {
	if d.Secret == "" {
		// Fail closed. Accepting unsigned deliveries because nobody set a
		// secret would let anyone on the network queue scans.
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "GITHUB_WEBHOOK_SECRET is not set; refusing webhooks",
		})
	}

	body := c.Body()
	if !verifySignature(d.Secret, body, c.Get("X-Hub-Signature-256")) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "missing or invalid X-Hub-Signature-256",
		})
	}

	ignored := func(reason string) error {
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"status": "ignored", "reason": reason})
	}

	switch event := c.Get("X-GitHub-Event"); event {
	case "ping":
		return c.JSON(fiber.Map{"status": "pong"})
	case "push":
	default:
		return ignored(fmt.Sprintf("event %q is not scanned", event))
	}

	var push pushEvent
	if err := json.Unmarshal(body, &push); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "body is not valid JSON"})
	}
	if push.branchDeleted() {
		return ignored("the push deleted a ref")
	}
	if err := push.validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	files := push.changedFiles()
	if len(files) == 0 {
		return ignored("no supported source files changed")
	}
	if len(files) > maxFilesPerScan {
		log.Printf("webhook: %s pushed %d scannable files; scanning the first %d",
			push.Repository.FullName, len(files), maxFilesPerScan)
		files = files[:maxFilesPerScan]
	}

	// GitHub's delivery id identifies this event across retries, which makes it
	// the natural scan id: a redelivery collides on the primary key instead of
	// starting a second scan. The header is copied because Fiber reuses the
	// request buffer once the handler returns.
	id := strings.Clone(c.Get("X-GitHub-Delivery"))
	if !deliveryPattern.MatchString(id) {
		id = uuid.NewString()
	}

	scan := Scan{
		ID:          id,
		Repository:  push.Repository.FullName,
		Commit:      push.After,
		Ref:         push.Ref,
		FilesQueued: len(files),
	}
	created, err := d.Store.CreateScan(c.UserContext(), scan)
	if err != nil {
		log.Printf("webhook: could not record scan %s: %v", id, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "could not record the scan",
		})
	}
	if !created {
		return c.JSON(fiber.Map{"status": "duplicate", "scan_id": id})
	}

	d.dispatch(func() { d.fetchAndPublish(scan, files) })

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"status":  "accepted",
		"scan_id": id,
		"files":   len(files),
	})
}

// fetchAndPublish builds the scan job and queues it. Any failure here marks
// the scan FAILED with the reason, since the webhook has already been answered
// and there is nobody left to return an error to.
func (d Deps) fetchAndPublish(scan Scan, files []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fail := func(reason string) {
		log.Printf("scan %s failed: %s", scan.ID, reason)
		if err := d.Store.FailScan(ctx, scan.ID, reason); err != nil {
			log.Printf("scan %s: could not record the failure: %v", scan.ID, err)
		}
	}

	job := ScanJob{JobID: scan.ID, Repository: scan.Repository, Commit: scan.Commit, Files: []JobFile{}}
	total := 0

	for _, path := range files {
		content, err := d.Fetcher.Fetch(ctx, scan.Repository, scan.Commit, path)
		switch {
		case errors.Is(err, ErrFileNotFound), errors.Is(err, ErrFileTooLarge):
			log.Printf("scan %s: skipping %s: %v", scan.ID, path, err)
			continue
		case err != nil:
			fail(fmt.Sprintf("could not fetch %s: %v", path, err))
			return
		}

		// The job is JSON, and the worker parses text. A file that is not
		// UTF-8 is not source in any language it supports.
		if !utf8.Valid(content) {
			log.Printf("scan %s: skipping %s: not UTF-8", scan.ID, path)
			continue
		}
		if total+len(content) > maxJobBytes {
			log.Printf("scan %s: job size limit reached; %s and later files not scanned",
				scan.ID, path)
			break
		}
		total += len(content)
		job.Files = append(job.Files, JobFile{Path: path, Content: string(content)})
	}

	if len(job.Files) == 0 {
		fail("none of the changed files could be fetched")
		return
	}

	body, err := json.Marshal(job)
	if err != nil {
		fail(fmt.Sprintf("could not encode the job: %v", err))
		return
	}
	if err := d.Publisher.Publish(ctx, d.ScanQueue, body); err != nil {
		fail(fmt.Sprintf("could not queue the job: %v", err))
		return
	}
	log.Printf("scan %s queued: %s@%s, %d file(s)", scan.ID, scan.Repository, scan.Commit,
		len(job.Files))
}
