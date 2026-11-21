// Small helpers shared by the screens.

/**
 * `obj[key]` only when `obj` has it itself. Tunnel names are keys of plain objects, and a name
 * such as `constructor` or `toString` would otherwise find what every object inherits.
 */
export function own(obj, key) {
  return obj != null && Object.hasOwn(obj, key) ? obj[key] : undefined;
}

/** Text typed on a Persian or Arabic keyboard with plain digits and separators. */
export function plainDigits(text) {
  return String(text ?? "")
    .replace(/[۰-۹]/g, (d) => d.charCodeAt(0) - 0x06f0)
    .replace(/[٠-٩]/g, (d) => d.charCodeAt(0) - 0x0660)
    .replace(/[،؛]/g, ",")
    .replace(/\u2212/g, "-");
}

/** The status mark class and label key for a tunnel. */
export function tunnelState(x) {
  if (x.state === "failed") return ["bad", "failed"];
  if (x.state === "running") {
    // A tunnel that has only just started is still dialing its other end.
    if (x.link_state === "not_connected" && (x.uptime_sec ?? Infinity) < 30) return ["warn", "connecting"];
    if (["not_connected"].includes(x.link_state)) return ["bad", "unstable"];
    // Heartbeats lost while the link came up count as loss for a while; that is not a fault.
    const settled = (x.uptime_sec ?? Infinity) >= 90;
    if (["no_traffic", "silent", "quota"].includes(x.link_state) || (settled && (x.loss_pct ?? 0) >= 1)) return ["warn", "unstable"];
    return ["ok", "running"];
  }
  if (x.state === "starting") return ["warn", "starting"];
  return ["off", x.state === "none" ? "none" : "stopped"];
}

export function transportLabel(id) {
  return (id || "?").toUpperCase();
}

/** The transport a tunnel uses now: for a running failover tunnel, the carrier in use. */
export function shownTransport(x) {
  return x?.failover?.carrier?.split(" ")[0] || x?.transport;
}

export function isUp(x) {
  return x.state === "running" || x.state === "starting";
}

/** How a tunnel's link line is drawn: solid when working, moving while connecting, broken when down. */
export function linkState(x) {
  const [mark, label] = tunnelState(x);
  if (x.state === "starting" || label === "connecting") return "live";
  if (mark === "ok") return "ok";
  if (mark === "warn") return "warn";
  return "down";
}

/** Ports the tunnels on every known server already use (their forwarded ports and tunnel ports). */
export function usedPorts(snapshots) {
  const used = new Set();
  for (const snap of snapshots) {
    for (const x of snap?.tunnels ?? []) {
      for (const p of x.carry?.ports ?? []) {
        // "7373" or a range "9000-9100": every port in it.
        const [a, b = a] = (String(p).match(/\d+/g) ?? []).map(Number);
        if (a) for (let n = a; n <= Math.min(b, a + 5000); n++) used.add(n);
      }
      // "listen :7000" or "203.0.113.10:2083": the tunnel port.
      for (const n of String(x.link ?? "").match(/:(\d+)/)?.slice(1) ?? []) used.add(+n);
      // A failover tunnel's other carriers ("wss 0.0.0.0:8443").
      for (const c of x.failover?.carriers ?? []) for (const n of String(c.carrier ?? "").match(/:(\d+)$/)?.slice(1) ?? []) used.add(+n);
    }
  }
  return used;
}

/** A random free-looking port for a new tunnel: 10000-32767 (below the range Linux hands out for
 *  outgoing connections, which could hold it for a moment), not one already in use or listed. */
export function randomPort(avoid = new Set()) {
  const pick = new Uint32Array(1);
  for (let i = 0; i < 200; i++) {
    crypto.getRandomValues(pick);
    const port = 10000 + (pick[0] % 22768);
    if (!avoid.has(port)) return port;
  }
  return 10000 + Math.floor(Math.random() * 22768);
}
