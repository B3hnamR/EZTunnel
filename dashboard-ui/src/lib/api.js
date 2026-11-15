// Calls to the dashboard's JSON API. Every request carries the x-eztunnel header; the server
// refuses state-changing requests without it.

async function call(method, path, body, timeout = 10_000, signal) {
  const headers = { "x-eztunnel": "1" };
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    // A server that stops answering must end in an error the screen can show, not a spinner.
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeout)]) : AbortSignal.timeout(timeout),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try {
    data = await response.json();
  } catch {
    // empty body
  }
  return { status: response.status, data };
}

export const getSession = () => call("GET", "/api/session");
export const getSnapshot = () => call("GET", "/api/snapshot");
export const getHistory = (range, series, server = "local", signal) =>
  call("GET", `/api/history?range=${encodeURIComponent(range)}&series=${encodeURIComponent(series)}&tz=${-new Date().getTimezoneOffset()}&server=${encodeURIComponent(server)}`, undefined, 10_000, signal);
export const login = (password) => call("POST", "/api/login", { password });
export const logout = () => call("POST", "/api/logout", {});
const base = (server) => (server && server !== "local" ? `/api/servers/${encodeURIComponent(server)}` : "/api");
// An action answers once it is done; after a start it watches the tunnel come up (about 15 s).
export const act = (name, action, server) =>
  call("POST", `${base(server)}/tunnels/${encodeURIComponent(name)}/${action}`, {}, 45_000);
export const restartAll = (server) => call("POST", server && server !== "local" ? `${base(server)}/restart-all` : "/api/restart-all", {}, 310_000);
export const getLogs = (name, lines, server, signal) =>
  call("GET", `${base(server)}/tunnels/${encodeURIComponent(name)}/logs?lines=${lines}`, undefined, 25_000, signal);
export const getServers = (signal) => call("GET", "/api/servers", undefined, 10_000, signal);
export const createJoinCode = () => call("POST", "/api/join-codes", {});
export const removeServer = (id) => call("DELETE", `/api/servers/${encodeURIComponent(id)}`);
export const getActivity = (limit) => call("GET", `/api/activity?limit=${limit}`);
export const followUrl = (name, server) => `${base(server)}/tunnels/${encodeURIComponent(name)}/logs/follow`;
// What the edit screen offers for a tunnel, and saving (or going back one version). Saving restarts
// the tunnel and watches it come up, and may put the old settings back, so it gets a long timeout.
export const getEditable = (name, server, signal) => call("GET", `${base(server)}/tunnels/${encodeURIComponent(name)}/settings`, undefined, 25_000, signal);
export const saveEdit = (name, changes, server) => call("POST", `${base(server)}/tunnels/${encodeURIComponent(name)}/settings`, changes, 90_000);
export const undoEdit = (name, server) => call("POST", `${base(server)}/tunnels/${encodeURIComponent(name)}/undo`, {}, 90_000);
// Deleting stops the tunnel's service first, so it gets the action timeout.
export const deleteTunnel = (name, server) => call("DELETE", `${base(server)}/tunnels/${encodeURIComponent(name)}`, undefined, 45_000);
// A new tunnel on two servers: the form's options, and creating it (both ends start and are
// watched, so it gets a long timeout).
export const getNewTunnel = () => call("GET", "/api/new-tunnel");
export const createTunnel = (form) => call("POST", "/api/new-tunnel", form, 120_000);
// A tunnel's own figures, and its tools: speedtest, pairing, quota_reset.
export const getStatus = (name, server) => call("GET", `${base(server)}/tunnels/${encodeURIComponent(name)}/status`, undefined, 15_000);
export const runTool = (name, tool, body, server) =>
  call("POST", `${base(server)}/tunnels/${encodeURIComponent(name)}/tools/${tool}`, body ?? {}, tool === "speedtest" ? 160_000 : 60_000);
// Server tools (health, fix, optimize_plan, optimize_apply, optimize_undo, files) and the
// transport check between two servers.
export const serverTool = (server, tool, body) =>
  call("POST", `/api/servers/${encodeURIComponent(server || "local")}/tools/${tool}`, body ?? {}, 100_000);
export const startCheck = (form) => call("POST", "/api/conntest", form, 40_000);
export const getCheck = () => call("GET", "/api/conntest", undefined, 25_000);
export const stopCheck = () => call("POST", "/api/conntest/stop", {}, 40_000);
// Maintenance: kept program files, the newest release, installing, backups.
export const getReleases = () => call("GET", "/api/releases");
export const checkRelease = () => call("POST", "/api/releases/check", {}, 40_000);
export const fetchRelease = (version, arch) => call("POST", "/api/releases/fetch", { version, arch }, 330_000);
export async function uploadProgram(file) {
  const response = await fetch("/api/releases/upload", {
    method: "POST", credentials: "same-origin", headers: { "x-eztunnel": "1", "content-type": "application/octet-stream" },
    body: file, signal: AbortSignal.timeout(300_000),
  });
  let data = null;
  try { data = await response.json(); } catch { /* empty */ }
  return { status: response.status, data };
}
export const installOn = (server, file, allowDowngrade) =>
  call("POST", `/api/servers/${encodeURIComponent(server || "local")}/install`, { file, allow_downgrade: Boolean(allowDowngrade) }, 600_000);
export const getBackups = () => call("GET", "/api/backups");
export const backupNow = () => call("POST", "/api/backups", {}, 120_000);
export const deleteBackup = (file) => call("DELETE", `/api/backups/${encodeURIComponent(file)}`);
export const restoreBackup = (server, body) => call("POST", `/api/servers/${encodeURIComponent(server || "local")}/restore`, body, 150_000);
// Alerts and settings.
export const getAlerts = () => call("GET", "/api/alerts");
export const getSettings = () => call("GET", "/api/settings");
export const saveSettings = (body) => call("POST", "/api/settings", body);
export const setPassword = (current, next) => call("POST", "/api/password", { current, new: next }, 30_000);
export const getSessions = () => call("GET", "/api/sessions");
export const revokeSession = (id) => call("POST", "/api/sessions/revoke", { id });
// Each chat may take up to 20 s when Telegram cannot be reached.
export const testTelegram = (body = {}) => call("POST", "/api/alerts/test", body, 240_000);
// Adding a server over SSH, and Mirage source tests.
export const getSshKey = () => call("GET", "/api/ssh-key", undefined, 30_000);
export const addOverSsh = (host, port, user) => call("POST", "/api/servers/ssh", { host, port, user }, 330_000);
export const startMirage = (form) => call("POST", "/api/mirage-test", form, 40_000);
export const getMirage = () => call("GET", "/api/mirage-test", undefined, 25_000);
export const stopMirage = () => call("POST", "/api/mirage-test/stop", {}, 40_000);
// Is there a path between two servers, and which server could relay.
export const findPath = (form) => call("POST", "/api/pathfinder", form, 300_000);
