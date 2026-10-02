# Sentinel frontend

Lists scans and shows each finding with its triage verdict (escalated,
suppressed or untriaged). Built with Next.js; every page is rendered on the
server per request from the gateway's read API, so nothing here is cached or
mocked.

```bash
pnpm install
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

The gateway address is read from `GATEWAY_URL` on the server (default
`http://localhost:3001`). If the gateway is unreachable the page says so rather
than showing placeholder numbers.

| Path | Shows |
|---|---|
| `/` | Totals and recent scans; refreshes while a scan is pending |
| `/scans/[id]` | One scan's findings, filterable by verdict, with the triage reason and taint path |
