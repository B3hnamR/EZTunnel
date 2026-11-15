// The live connection: the newest snapshot, the recent history for the charts, and whether the
// stream is up. One EventSource per signed-in page.
import { getSnapshot, getSession } from "./api.js";
import { clear as clearHistory } from "./history.svelte.js";

const KEEP = 150;

export const live = $state({
  snapshot: null,
  history: [],
  /** "loading", "up" or "lost" */
  link: "loading",
  /** When the newest snapshot was taken (ms). */
  lastAt: 0,
});

let source = null;
let onSignedOut = () => {};
let connectionGeneration = 0;

function take(snapshot) {
  live.snapshot = snapshot;
  live.lastAt = snapshot.at;
  const t = {};
  let down = 0;
  let up = 0;
  for (const x of snapshot.tunnels) {
    const d = x.down_bps ?? 0;
    const u = x.up_bps ?? 0;
    t[x.name] = [d, u];
    down += d;
    up += u;
  }
  const next = [...live.history, { at: snapshot.at, down, up, t }];
  live.history = next.length > KEEP ? next.slice(next.length - KEEP) : next;
}

export async function connect(signedOut) {
  onSignedOut = signedOut;
  disconnect();
  const generation = ++connectionGeneration;
  live.link = "loading";
  let snapshot = { status: 0, data: null };
  try {
    snapshot = await getSnapshot();
  } catch {
    if (generation === connectionGeneration) live.link = "lost";
    // The event stream can recover even when the initial HTTP request failed.
  }
  if (generation !== connectionGeneration) return;
  const { status, data } = snapshot;
  if (status === 401) return onSignedOut();
  if (status !== 200) live.link = "lost";
  if (status === 200 && data) {
    live.history = data.history ?? [];
    if (data.snapshot) {
      live.snapshot = data.snapshot;
      live.lastAt = data.snapshot.at;
      live.link = "up";
    }
  }
  const stream = new EventSource("/api/events");
  source = stream;
  stream.addEventListener("snapshot", (event) => {
    if (generation !== connectionGeneration || source !== stream) return;
    try {
      take(JSON.parse(event.data));
      live.link = "up";
    } catch {
      // a broken event is skipped; the next one replaces it
    }
  });
  stream.addEventListener("error", async () => {
    if (generation !== connectionGeneration || source !== stream) return;
    live.link = "lost";
    // EventSource retries by itself, but not after the session ended.
    try {
      const { data } = await getSession();
      if (generation !== connectionGeneration || source !== stream) return;
      if (data && !data.signed_in) {
        disconnect();
        onSignedOut();
      }
    } catch {
      // the server is unreachable; keep retrying
    }
  });
}

export function disconnect() {
  connectionGeneration++;
  if (source) source.close();
  source = null;
}

export function reset() {
  disconnect();
  clearHistory();
  live.snapshot = null;
  live.history = [];
  live.link = "loading";
  live.lastAt = 0;
}
