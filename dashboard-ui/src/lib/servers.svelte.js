// The other servers (agents) this dashboard manages: polled while signed in, with a short live
// series per tunnel so their cards can draw a spark line like local ones.
import { getServers } from "./api.js";

const POINTS = 150;
export const LOCAL = "local";

export const fleet = $state({ list: [], loaded: false, error: false, offlineAfter: 20, localName: null });

/** The name this server is shown under: the one set on the dashboard, else its hostname. */
export const localName = (hostname) => fleet.localName || hostname || "";
/** id -> tunnel name -> recent download rates. */
export const fleetSeries = $state({});

let timer = null;
let active = false;
let inflight = null;
let controller = null;

function poll() {
  if (!active) return Promise.resolve();
  if (inflight) return inflight;
  const request = new AbortController();
  controller = request;
  inflight = pollOnce(request);
  return inflight;
}

async function pollOnce(request) {
  try {
    const { status, data } = await getServers(request.signal);
    if (!active || request.signal.aborted || controller !== request) return;
    if (status !== 200) throw new Error(String(status));
    fleet.list = data.servers;
    fleet.offlineAfter = data.offline_after ?? 20;
    fleet.localName = data.local_name ?? null;
    fleet.loaded = true;
    fleet.error = false;
    for (const server of data.servers) {
      const tunnels = server.snapshot?.tunnels ?? [];
      const per = (fleetSeries[server.id] ??= {});
      for (const x of tunnels) {
        const list = Object.hasOwn(per, x.name) ? per[x.name] : (per[x.name] = []);
        list.push(server.online ? x.down_bps ?? 0 : 0);
        if (list.length > POINTS) list.splice(0, list.length - POINTS);
      }
    }
  } catch {
    if (active && !request.signal.aborted && controller === request) fleet.error = true;
  } finally {
    if (controller === request) {
      controller = null;
      inflight = null;
    }
  }
}

export function startFleet() {
  if (active) return;
  active = true;
  poll();
  timer = setInterval(poll, 3000);
}

export function stopFleet() {
  active = false;
  controller?.abort();
  controller = null;
  inflight = null;
  clearInterval(timer);
  timer = null;
  fleet.list = [];
  fleet.loaded = false;
  fleet.error = false;
  fleet.offlineAfter = 20;
  fleet.localName = null;
  for (const id of Object.keys(fleetSeries)) delete fleetSeries[id];
}

export function refreshFleet() {
  return poll();
}

export function serverById(id) {
  return fleet.list.find((s) => s.id === id);
}
