"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// Re-requests the current route on an interval while `active` is true. The
// page is a Server Component, so refreshing it re-fetches from the gateway;
// this is what moves a scan from PENDING to COMPLETED on screen without a
// reload. It renders nothing.
export function AutoRefresh({ active, intervalMs = 3000 }: { active: boolean; intervalMs?: number }) {
  const router = useRouter();

  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => router.refresh(), intervalMs);
    return () => clearInterval(timer);
  }, [active, intervalMs, router]);

  return null;
}
