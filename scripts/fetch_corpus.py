#!/usr/bin/env python3
"""Fetch the benchmark corpus: each repository in benchmark/corpus.json, at its pinned commit.

    python3 scripts/fetch_corpus.py

The repositories are cloned into benchmark/corpus/, which is gitignored: the
corpus is third-party code and is reproduced from the manifest, not stored in
this repository. Needs git and network access. Safe to re-run; a repository
already at its pinned commit is left alone.

Each checkout is shallow (the one pinned commit, no history).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "benchmark" / "corpus.json"
CORPUS = ROOT / "benchmark" / "corpus"


def git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def current_commit(path: Path) -> str | None:
    if not (path / ".git").is_dir():
        return None
    result = git(["rev-parse", "HEAD"], path)
    return result.stdout.strip() if result.returncode == 0 else None


def fetch(repository: dict) -> bool:
    name, url, commit = repository["name"], repository["url"], repository["commit"]
    path = CORPUS / name

    if current_commit(path) == commit:
        print(f"  ok       {name} @ {commit[:12]} (already present)")
        return True

    path.mkdir(parents=True, exist_ok=True)
    steps = [
        ["init", "--quiet"],
        ["remote", "remove", "origin"],          # tolerated to fail on a fresh directory
        ["remote", "add", "origin", url],
        # Fetching by SHA pins the content exactly; a branch name would drift.
        ["fetch", "--quiet", "--depth", "1", "origin", commit],
        ["-c", "advice.detachedHead=false", "checkout", "--quiet", "--force", "FETCH_HEAD"],
    ]
    for step in steps:
        result = git(step, path)
        if result.returncode != 0 and step[:2] != ["remote", "remove"]:
            print(f"  FAILED   {name}: git {' '.join(step)}\n{result.stderr.strip()}")
            return False

    if current_commit(path) != commit:
        print(f"  FAILED   {name}: checked out {current_commit(path)}, expected {commit}")
        return False

    print(f"  fetched  {name} @ {commit[:12]}")
    return True


def main() -> int:
    repositories = json.loads(MANIFEST.read_text())["repositories"]
    CORPUS.mkdir(parents=True, exist_ok=True)
    print(f"fetching {len(repositories)} repositories into {CORPUS.relative_to(ROOT)}/")

    results = [fetch(repository) for repository in repositories]
    failed = results.count(False)
    if failed:
        print(f"\n{failed} of {len(results)} repositories could not be fetched")
        return 1
    print(f"\nall {len(results)} repositories are at their pinned commits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
