#!/usr/bin/env python3
"""Run the analyzer over the benchmark corpus and summarise what it reports.

    python3 scripts/fetch_corpus.py        # once: fetch the pinned repositories
    python3 scripts/run_benchmark.py       # scan them and print the summary

The corpus is the set of public repositories in benchmark/corpus.json, each at a
pinned commit, so two runs of the same worker give the same numbers.

What this measures, and what it does not
----------------------------------------
It measures what the analyzer reports on real code: how many files it scanned,
what it found by class and language, and how the triage layer ruled on each
finding. It does NOT measure recall -- there is no list of every vulnerability
in these repositories to compare against -- and a finding count says nothing by
itself about whether the findings are right.

Precision is estimated separately, from benchmark/labels.csv: a fixed random
sample of findings, each labelled true or false positive by a person who read
the code. The summary reports precision on that sample and how many labels
still apply to the current run.

    --write-sample   draw the sample and add unlabelled rows to labels.csv
    --no-triage      do not call the triage layer (findings are UNTRIAGED)
    --sample-size N  number of findings to sample (default 50)

Triage verdicts need the triage layer running (see ai-layer/). If it is not
reachable the run continues with triage off and says so; findings are then
reported as untriaged, never counted as escalated.

Output: the summary is printed and saved to benchmark/results/summary.txt, and
every finding is saved to benchmark/results/results.json.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "benchmark" / "corpus.json"
CORPUS = ROOT / "benchmark" / "corpus"
RESULTS = ROOT / "benchmark" / "results"
LABELS = ROOT / "benchmark" / "labels.csv"
WORKER = ROOT / "worker" / "build" / "sentinel-worker"

# Fixed, so the sample is the same findings every time it is drawn.
SAMPLE_SEED = 20261002

LANGUAGES = ["javascript", "python", "go"]
VERDICTS = ["ESCALATED", "SUPPRESSED", "UNTRIAGED"]
LABEL_FIELDS = ["key", "label", "reason", "repository", "file", "line", "class", "snippet"]


def git_head(path: Path) -> str | None:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def triage_reachable(triage_url: str) -> bool:
    # The health endpoint sits at the service root, beside the triage route.
    base = triage_url.split("/api/")[0]
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=3) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def worker_version() -> str:
    result = subprocess.run([str(WORKER), "--version"], capture_output=True, text=True)
    return result.stdout.strip().removeprefix("sentinel-worker ").strip() or "unknown"


def scan(repository: dict, exclude: dict, use_triage: bool) -> dict:
    """Runs the worker over one repository and returns its report."""
    argv = [str(WORKER), "--scan", str(CORPUS / repository["name"]), "--format", "report", "--quiet"]
    if not use_triage:
        argv.append("--no-triage")
    for name in exclude.get("directories", []):
        argv += ["--exclude", name]
    for suffix in exclude.get("suffixes", []):
        argv += ["--exclude", f"*{suffix}"]

    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"worker failed on {repository['name']}:\n{result.stderr}")
    return json.loads(result.stdout)


def finding_key(repository: str, finding: dict) -> str:
    """Identifies a finding across runs: where it is and what it claims."""
    return f"{repository}:{finding['file']}:{finding['line']}:{finding['class']}"


def read_labels() -> dict[str, dict]:
    if not LABELS.exists():
        return {}
    with LABELS.open(newline="") as handle:
        return {row["key"]: row for row in csv.DictReader(handle)}


def write_labels(rows: list[dict]) -> None:
    with LABELS.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LABEL_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: row["key"]))


def table(headers: list[str], rows: list[list], align: str | None = None) -> list[str]:
    """Plain-text table. `align` is one 'l' or 'r' per column."""
    cells = [[str(cell) for cell in row] for row in rows]
    widths = [max(len(headers[i]), *(len(row[i]) for row in cells)) if cells else len(headers[i])
              for i in range(len(headers))]
    align = align or "l" + "r" * (len(headers) - 1)

    def render(row):
        return "  ".join(cell.ljust(width) if side == "l" else cell.rjust(width)
                         for cell, width, side in zip(row, widths, align)).rstrip()

    return [render(headers), render(["-" * width for width in widths]), *(render(row) for row in cells)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--no-triage", action="store_true")
    parser.add_argument("--write-sample", action="store_true")
    parser.add_argument("--sample-size", type=int, default=50)
    args = parser.parse_args()

    if not WORKER.exists():
        raise SystemExit(f"{WORKER} not found. Build it: cd worker && make")

    manifest = json.loads(MANIFEST.read_text())
    repositories = manifest["repositories"]
    exclude = manifest.get("exclude", {})

    for repository in repositories:
        head = git_head(CORPUS / repository["name"]) if (CORPUS / repository["name"]).is_dir() else None
        if head != repository["commit"]:
            raise SystemExit(f"{repository['name']} is not at its pinned commit "
                             f"({head or 'missing'}). Run: python3 scripts/fetch_corpus.py")

    triage_url = os.getenv("TRIAGE_URL", "http://localhost:8000/api/v1/triage")
    use_triage = not args.no_triage
    triage_note = ""
    if use_triage and not triage_reachable(triage_url):
        use_triage = False
        triage_note = (f"The triage layer at {triage_url} was not reachable, so this run made no "
                       "triage calls. Every finding is UNTRIAGED.")
    elif not use_triage:
        triage_note = "Run with --no-triage. Every finding is UNTRIAGED."

    # ---- Scan --------------------------------------------------------------
    started = time.monotonic()
    findings: list[dict] = []
    files_by_language: Counter = Counter()
    per_repository: list[dict] = []
    totals = Counter()
    analysis_ms = 0.0

    for repository in repositories:
        report = scan(repository, exclude, use_triage)
        summary = report["summary"]

        scanned = [f for f in report["files"] if not f["skipped_minified"]]
        for file in scanned:
            files_by_language[file["language"]] += 1

        totals["files"] += summary["files_scanned"]
        totals["minified"] += summary["files_minified"]
        totals["parse_errors"] += summary["files_with_parse_errors"]
        totals["functions"] += summary["functions_analyzed"]
        totals["suppressed_inline"] += summary["suppressed_inline"]
        analysis_ms += summary["analysis_ms"]

        for finding in report["findings"]:
            language = finding["rule_id"].split(".")[1]
            findings.append({**finding, "repository": repository["name"], "kind": repository["kind"],
                             "language": language, "key": finding_key(repository["name"], finding)})

        per_repository.append({
            "name": repository["name"], "kind": repository["kind"], "language": repository["language"],
            "commit": repository["commit"], "files": summary["files_scanned"],
            "findings": summary["findings"], "escalated": summary["escalated"],
            "suppressed": summary["suppressed"], "untriaged": summary["untriaged"],
        })

    elapsed = time.monotonic() - started
    findings.sort(key=lambda finding: finding["key"])

    # ---- Sample and labels -------------------------------------------------
    keys = sorted({finding["key"] for finding in findings})
    sample_size = min(args.sample_size, len(keys))
    sample = sorted(random.Random(SAMPLE_SEED).sample(keys, sample_size))
    by_key = {finding["key"]: finding for finding in findings}

    labels = read_labels()
    if args.write_sample:
        rows = list(labels.values())
        added = 0
        for key in sample:
            if key in labels:
                continue
            finding = by_key[key]
            rows.append({"key": key, "label": "", "reason": "", "repository": finding["repository"],
                         "file": finding["file"], "line": finding["line"], "class": finding["class"],
                         "snippet": finding["snippet"]})
            added += 1
        write_labels(rows)
        labels = read_labels()
        print(f"labels.csv: {added} unlabelled row(s) added for the {sample_size}-finding sample\n")

    sampled_labels = [labels[key] for key in sample if key in labels and labels[key]["label"].strip()]
    verdict_counts = Counter(row["label"].strip().upper() for row in sampled_labels)
    stale = sorted(key for key in labels if key not in by_key)

    # ---- Summary -----------------------------------------------------------
    out: list[str] = []
    say = out.append

    say("Sentinel SAST benchmark")
    say("=======================")
    say(f"worker {worker_version()}  |  corpus: {len(repositories)} repositories at pinned commits "
        "(benchmark/corpus.json)")
    say("")

    say("Files")
    say("-----")
    say(f"{totals['files']} source files scanned, {totals['functions']} functions")
    for line in table(["language", "files"],
                      [[language, files_by_language[language]] for language in LANGUAGES]):
        say("  " + line)
    say(f"  {totals['minified']} minified file(s) skipped; "
        f"{totals['parse_errors']} file(s) had parse errors and were analysed anyway")
    say(f"  analysis time {analysis_ms / 1000:.1f}s (wall {elapsed:.1f}s including triage calls)")
    say("")

    say("Findings by class and language")
    say("------------------------------")
    by_class: dict[str, Counter] = defaultdict(Counter)
    for finding in findings:
        by_class[finding["vulnerability"]][finding["language"]] += 1
    class_rows = sorted(by_class.items(), key=lambda item: (-sum(item[1].values()), item[0]))
    rows = [[name, *(count[language] for language in LANGUAGES), sum(count.values())]
            for name, count in class_rows]
    rows.append(["total", *(sum(count[language] for _, count in class_rows) for language in LANGUAGES),
                 len(findings)])
    for line in table(["class", *LANGUAGES, "total"], rows):
        say("  " + line)
    say(f"  {len(by_class)} classes reported; {totals['suppressed_inline']} finding(s) "
        "silenced by inline directives in the scanned code")
    say("")

    say("Triage verdicts")
    say("---------------")
    verdicts = Counter(finding["verdict"] for finding in findings)
    for line in table(["verdict", "findings"], [[verdict, verdicts[verdict]] for verdict in VERDICTS]):
        say("  " + line)
    if triage_note:
        say(f"  {triage_note}")
    else:
        triaged = verdicts["ESCALATED"] + verdicts["SUPPRESSED"]
        say(f"  {triaged} of {len(findings)} findings received a verdict from the triage layer.")
    say("")

    say("By repository")
    say("-------------")
    rows = []
    for repository in per_repository:
        density = f"{100 * repository['findings'] / repository['files']:.1f}" if repository["files"] else "-"
        rows.append([repository["name"], repository["kind"], repository["language"], repository["files"],
                     repository["findings"], density, repository["escalated"], repository["suppressed"],
                     repository["untriaged"]])
    for line in table(["repository", "kind", "language", "files", "findings", "per 100 files",
                       "escalated", "suppressed", "untriaged"], rows, "lllrrrrrr"):
        say("  " + line)
    for kind in ("vulnerable-app", "ordinary"):
        subset = [repository for repository in per_repository if repository["kind"] == kind]
        files = sum(repository["files"] for repository in subset)
        count = sum(repository["findings"] for repository in subset)
        say(f"  {kind}: {count} findings in {files} files"
            + (f" ({100 * count / files:.1f} per 100 files)" if files else ""))
    say("")

    say("Precision on the labelled sample")
    say("--------------------------------")
    say(f"Sample: {sample_size} of {len(keys)} findings, drawn with fixed seed {SAMPLE_SEED}.")
    if not sampled_labels:
        say("  No labels yet. Run with --write-sample, then fill in the label column of")
        say("  benchmark/labels.csv with TP or FP for each row.")
    else:
        true_positive, false_positive = verdict_counts["TP"], verdict_counts["FP"]
        unsure = len(sampled_labels) - true_positive - false_positive
        decided = true_positive + false_positive
        say(f"  labelled {len(sampled_labels)} of {sample_size}: {true_positive} true positive, "
            f"{false_positive} false positive, {unsure} undecided")
        if decided:
            say(f"  precision {100 * true_positive / decided:.0f}% "
                f"({true_positive}/{decided} of the decided labels)")
        if len(sampled_labels) < sample_size:
            say(f"  {sample_size - len(sampled_labels)} sampled finding(s) are not labelled yet")

        # The engine attaches a confidence to every finding. If that number
        # means anything, precision should fall as confidence does.
        rows = []
        for confidence in ("HIGH", "MEDIUM", "LOW"):
            in_bucket = [row for row in sampled_labels
                         if by_key[row["key"]]["confidence"] == confidence]
            hits = sum(1 for row in in_bucket if row["label"].strip().upper() == "TP")
            misses = sum(1 for row in in_bucket if row["label"].strip().upper() == "FP")
            rate = f"{100 * hits / (hits + misses):.0f}%" if hits + misses else "-"
            rows.append([confidence, hits, misses, rate])
        say("")
        for line in table(["engine confidence", "true positive", "false positive", "precision"], rows):
            say("  " + line)
        say("")
        say("  Labels are one reviewer's reading of the code; see the reason column in")
        say("  benchmark/labels.csv. This is precision only -- recall is not measured.")
    if stale:
        say(f"  {len(stale)} label(s) refer to findings this run did not produce and were ignored.")
    say("")

    summary_text = "\n".join(out)
    print(summary_text)

    # ---- Save --------------------------------------------------------------
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "summary.txt").write_text(summary_text + "\n")
    (RESULTS / "results.json").write_text(json.dumps({
        "worker_version": worker_version(),
        "triage_used": use_triage,
        "sample_seed": SAMPLE_SEED,
        "sample": sample,
        "totals": {
            "files_scanned": totals["files"], "files_minified": totals["minified"],
            "files_with_parse_errors": totals["parse_errors"], "functions": totals["functions"],
            "findings": len(findings),
            "files_by_language": {language: files_by_language[language] for language in LANGUAGES},
            "verdicts": {verdict: verdicts[verdict] for verdict in VERDICTS},
        },
        "repositories": per_repository,
        "findings": [{key: finding[key] for key in (
            "key", "repository", "kind", "language", "file", "line", "vulnerability", "class", "cwe",
            "severity", "confidence", "snippet", "verdict", "triage_confidence", "triage_reason")}
            for finding in findings],
    }, indent=2) + "\n")
    print(f"saved: {(RESULTS / 'summary.txt').relative_to(ROOT)}, "
          f"{(RESULTS / 'results.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
