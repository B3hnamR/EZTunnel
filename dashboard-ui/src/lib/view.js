// Small helpers shared by the screens.

/** The status mark class and label key for a tunnel. */
export function tunnelState(x) {
  if (x.state === "failed") return ["bad", "failed"];
  if (x.state === "running") {
    if (["not_connected"].includes(x.link_state)) return ["bad", "unstable"];
    if (["no_traffic", "silent", "quota"].includes(x.link_state) || (x.loss_pct ?? 0) >= 1) return ["warn", "unstable"];
    return ["ok", "running"];
  }
  if (x.state === "starting") return ["warn", "starting"];
  return ["off", x.state === "none" ? "none" : "stopped"];
}

export function transportLabel(id) {
  return (id || "?").toUpperCase();
}

export function isUp(x) {
  return x.state === "running" || x.state === "starting";
}
