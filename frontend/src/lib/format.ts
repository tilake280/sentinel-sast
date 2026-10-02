// Rendered on the server, so times are formatted in one fixed zone rather than
// whatever the server's locale happens to be.
export function formatTime(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function shortCommit(commit: string): string {
  return commit ? commit.slice(0, 7) : "—";
}

export function shortRef(ref: string): string {
  return ref.replace(/^refs\/(heads|tags)\//, "");
}

// Similarity to the nearest previously dismissed finding, as the triage layer
// reported it.
export function formatSimilarity(value: number): string {
  return value.toFixed(3);
}
