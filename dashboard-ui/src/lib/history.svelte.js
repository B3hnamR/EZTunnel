// History from /api/history, cached per range and series for a minute (rows are per minute).
import { getHistory } from "./api.js";

const FRESH_MS = 60_000;
export const history = $state({});
const inflight = {};

export function key(range, series) {
  return `${range}:${series}`;
}

/** Loads (or refreshes) one history; the result appears in `history[key]`. */
export async function load(range, series, force = false) {
  const k = key(range, series);
  const have = history[k];
  if (!force && have?.data && Date.now() - have.loadedAt < FRESH_MS) return;
  if (inflight[k]) return;
  inflight[k] = true;
  history[k] = { ...(have ?? {}), loading: true, error: false };
  try {
    const { status, data } = await getHistory(range, series);
    history[k] = status === 200 ? { data, loadedAt: Date.now(), loading: false, error: false } : { ...(have ?? {}), loading: false, error: true };
  } catch {
    history[k] = { ...(have ?? {}), loading: false, error: true };
  } finally {
    inflight[k] = false;
  }
}

export function clear() {
  for (const k of Object.keys(history)) delete history[k];
}

/** Points from the first one with data on; empty buckets after that count as zero. The bucket
 *  still filling is marked `partial`; `dropPartial` leaves it out (line charts, where a half
 *  bucket would look like a sudden drop). */
export function trimmed(points, bucketSec, dropPartial = false) {
  const first = points.findIndex((p) => p.down != null);
  if (first < 0) return [];
  const now = Date.now();
  return points
    .slice(first)
    .map((p) => ({ ...p, down: p.down ?? 0, up: p.up ?? 0, empty: p.down == null, partial: bucketSec != null && p.at + bucketSec * 1000 > now }))
    .filter((p) => !(dropPartial && p.partial));
}

/** Summary figures for a line range (bytes per second) or the daily range (bytes). */
export function summary(points, bucketSec, daily) {
  const filled = points.filter((p) => !p.empty);
  if (!filled.length) return null;
  const totals = filled.map((p) => p.down + p.up);
  if (daily) {
    // Today counts toward the total, not toward the busiest day or the average.
    const whole = filled.filter((p) => !p.partial).map((p) => p.down + p.up);
    const sum = totals.reduce((a, b) => a + b, 0);
    const days = whole.length ? whole : totals;
    return { total: sum, busiest: Math.max(...days), average: days.reduce((a, b) => a + b, 0) / days.length };
  }
  const rates = totals.map((t) => t / bucketSec);
  return {
    peak: Math.max(...filled.map((p) => p.peak ?? 0), ...rates),
    low: Math.min(...rates),
    average: rates.reduce((a, b) => a + b, 0) / rates.length,
  };
}

/** Bytes moved since the viewer's local midnight, from the 24-hour history. */
export function today(points) {
  const midnight = new Date();
  midnight.setHours(0, 0, 0, 0);
  return points.filter((p) => p.at >= midnight.getTime() && p.down != null).reduce((sum, p) => sum + p.down + p.up, 0);
}
