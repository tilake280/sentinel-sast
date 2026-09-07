// HTTP handlers for the demo service.
//
// Demo corpus for Sentinel SAST -- Go half. The Go file is where the
// source/sink name collision matters: r.URL.Query() and db.Query() share a
// final segment, so a name-only matcher reports the source as a sink.

package api

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

var db *sql.DB

// ---------------------------------------------------------------------------
// REAL VULNERABILITIES
// ---------------------------------------------------------------------------

// SQL injection: the query parameter is spliced into the statement.
func SearchUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}

// Command injection: a form value reaches exec.Command.
func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

// Path traversal: the filename comes from the request.
func Download(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	data, err := os.ReadFile("/var/data/" + name)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Write(data)
}

// SSRF: the destination is attacker-chosen.
func FetchAvatar(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "bad url", 400)
		return
	}
	defer resp.Body.Close()
}

// Interprocedural: the sink is in runQuery, the source is in the caller.
func runQuery(q string) (*sql.Rows, error) {
	return db.Query(q)
}

func Report(w http.ResponseWriter, r *http.Request) {
	runQuery("SELECT * FROM reports WHERE owner = " + r.FormValue("owner"))
}

// Weak cryptography: MD5 is collision-broken.
func Checksum(data []byte) string {
	return fmt.Sprintf("%x", md5.Sum(data))
}

// ---------------------------------------------------------------------------
// SAFE CODE THAT NAIVE SCANNERS FLAG ANYWAY
// ---------------------------------------------------------------------------

// Parameterised query -- the driver binds the value.
func UserByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return
	}
	defer rows.Close()
}

// Numeric coercion: an int cannot carry a SQL payload.
func UserByIntID(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}

// filepath.Base strips traversal sequences.
func SafeDownload(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.FormValue("file"))
	data, err := os.ReadFile("/var/data/" + name)
	if err != nil {
		return
	}
	w.Write(data)
}

// A constant query with no request data anywhere near it.
func UserCount(w http.ResponseWriter, r *http.Request) {
	row := db.QueryRow("SELECT COUNT(*) FROM users")
	_ = row
}

// Reading a query parameter is not itself a finding -- r.URL.Query() shares a
// final segment with the db.Query() sink, which is the collision the analyzer
// resolves by checking sources before sinks.
func ReadParam(r *http.Request) string {
	return r.URL.Query().Get("name")
}
