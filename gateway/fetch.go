package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A push webhook names the files that changed but does not carry them, and the
// worker scans contents, not paths. Something has to fetch the bytes; that is
// this file.

// Limits on what one push can put on the queue. A scan job is a single
// RabbitMQ message, so both are about keeping that message a sane size.
const (
	maxFilesPerScan = 200
	maxFileBytes    = 1 << 20 // 1 MiB; larger files are generated or vendored
)

// ErrFileNotFound means the file does not exist at that commit -- typically it
// was added and then removed within the same push. It is skipped, not fatal.
var ErrFileNotFound = errors.New("file not found at commit")

// ErrFileTooLarge means the file exceeds maxFileBytes and was skipped.
var ErrFileTooLarge = errors.New("file exceeds the size limit")

// ContentFetcher retrieves one file at one commit.
type ContentFetcher interface {
	Fetch(ctx context.Context, repository, commit, path string) ([]byte, error)
}

// RawFetcher reads files from a raw-content host laid out as
// {base}/{owner}/{repo}/{commit}/{path}, which is raw.githubusercontent.com's
// layout. The base is configurable so the end-to-end check can point it at a
// local server instead of at GitHub.
type RawFetcher struct {
	BaseURL string
	Token   string // optional; needed for private repositories
	Client  *http.Client
}

func NewRawFetcher(baseURL, token string) *RawFetcher {
	return &RawFetcher{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (f *RawFetcher) Fetch(ctx context.Context, repository, commit, path string) ([]byte, error) {
	// Escape per segment: a path is attacker-influenced (it is whatever was
	// pushed), and must not be able to climb out of its repository or smuggle
	// a query string.
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == ".." || segment == "." || segment == "" {
			return nil, fmt.Errorf("refusing path %q", path)
		}
		segments[i] = url.PathEscape(segment)
	}
	target := fmt.Sprintf("%s/%s/%s/%s", f.BaseURL, repository, url.PathEscape(commit),
		strings.Join(segments, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrFileNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("fetch %s: HTTP %d", path, resp.StatusCode)
	}

	// Read one byte past the limit so "exactly at the limit" and "over it" are
	// distinguishable without trusting Content-Length.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxFileBytes {
		return nil, ErrFileTooLarge
	}
	return body, nil
}

// scannableExtensions mirrors language_for_path in worker/src/languages.cpp.
// Fetching a file the worker would skip is wasted work, so the two lists
// should agree; the worker remains the authority and ignores anything else.
var scannableExtensions = []string{
	".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyi", ".go",
}

func isScannable(path string) bool {
	for _, extension := range scannableExtensions {
		if strings.HasSuffix(path, extension) {
			return true
		}
	}
	return false
}
