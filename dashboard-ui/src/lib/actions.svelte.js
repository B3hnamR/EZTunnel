// Tunnel actions shared by the screens: the confirm step, what is under way, and the message
// that reports the result.
import { act, restartAll } from "./api.js";
import { t } from "./i18n.svelte.js";
import { live } from "./live.svelte.js";
import { fleet } from "./servers.svelte.js";

/** The other ends of a tunnel: the same pair fingerprint, on this server or a joined one. */
export function otherEnds(name, server, pair) {
  if (!pair) return [];
  const places = [{ id: "local", name: t("thisServer"), online: true, tunnels: live.snapshot?.tunnels ?? [] }];
  for (const s of fleet.list) places.push({ id: s.id, name: s.name, online: s.online, tunnels: s.snapshot?.tunnels ?? [] });
  const found = [];
  for (const place of places) {
    for (const x of place.tunnels) {
      if (x.pair === pair && !(place.id === (server ?? "local") && x.name === name)) {
        found.push({ server: place.id, serverName: place.name, name: x.name, online: place.online });
      }
    }
  }
  return found;
}

/** The message at the bottom of the screen. `bad` messages stay longer and are announced. */
export const toast = $state({ text: "", bad: false, shown: false });
let hideTimer;

export function say(text, bad = false) {
  toast.text = text;
  toast.bad = bad;
  toast.shown = true;
  clearTimeout(hideTimer);
  hideTimer = setTimeout(() => (toast.shown = false), bad ? 8000 : 3000);
}

/** Tunnels with an action under way ("*" while every tunnel restarts), and the action. */
export const pending = $state({});

/** The question waiting for an answer: { title, text, confirm, danger, run }. */
export const asking = $state({ open: false, title: "", text: "", confirm: "", run: null, option: null, safe: false });

/** `option` ({ label, checked }) adds a checkbox; `run` then receives whether it is ticked. */
export function ask(title, text, confirm, run, option = null, safe = false) {
  asking.safe = safe;
  asking.title = title;
  asking.text = text;
  asking.confirm = confirm;
  asking.run = run;
  asking.option = option ? { label: option.label, checked: option.checked ?? true } : null;
  asking.open = true;
}

function failure(name, status, data) {
  if (status === 401) return t("signedOutNow");
  if (status === 409) return t("busyT");
  if (status === 504) return t("slowT", name);
  return `${t("failedT", name)}${data?.detail ? ` ${data.detail}` : ""}`;
}

/** The key `pending` uses for a tunnel: its name here, "server/name" on another server. */
export const pendingKey = (name, server) => (server && server !== "local" ? `${server}/${name}` : name);

/** Runs one action and reports it; `quiet` returns the report ([text, bad]) instead. */
export async function runAction(name, action, server, quiet = false) {
  const key = pendingKey(name, server);
  if (pending[key] || pending["*"]) return quiet ? [t("busyT"), true] : undefined;
  pending[key] = action;
  let report;
  try {
    const { status, data } = await act(name, action, server);
    if (status !== 200) report = [failure(name, status, data), true];
    else if (!data.changed) report = [t("sameT", name), false];
    else if (data.came_up === false) report = [t("notUpT", name), true];
    else report = [t(action === "stop" ? "stoppedT" : action === "start" ? "startedT" : "restartedT", name), false];
  } catch {
    report = [t("slowT", name), true];
  } finally {
    delete pending[key];
  }
  if (quiet) return report;
  say(...report);
}

/** Stop, start or restart a tunnel; with its other end on a managed server, both ends by default. */
export function confirmAction(name, action, server, pair = null) {
  const others = otherEnds(name, server, pair).filter((o) => o.online);
  // Both ends together; one message for all, problems first, so a failure is never hidden.
  const runAll = async (both) => {
    if (!both || !others.length) return runAction(name, action, server);
    const reports = await Promise.all([runAction(name, action, server, true), ...others.map((o) => runAction(o.name, action, o.server, true))]);
    const bad = reports.filter((r) => r[1]);
    say((bad.length ? bad : reports).map((r) => r[0]).join(" "), bad.length > 0);
  };
  const option = others.length ? { label: t("alsoOther", t(action), others.map((o) => `${o.name} · ${o.serverName}`).join(", ")), checked: true } : null;
  if (action === "start") {
    if (!others.length) return runAction(name, action, server);
    return ask(t("startQ", name), t("startText"), t("start"), runAll, option, true);
  }
  const stop = action === "stop";
  ask(t(stop ? "stopQ" : "restartQ", name), t(stop ? "stopText" : "restartText"), t(action), runAll, option);
}

export function confirmRestartAll(count, server = "local") {
  const all = server === "local" ? "*" : `${server}/*`;
  ask(t("allQ", count), t("allText"), t("restartAll"), async () => {
    if (pending[all] || (server === "local" && Object.keys(pending).length)) return say(t("busyT"), true);
    pending[all] = "restart";
    try {
      const { status, data } = await restartAll(server);
      if (status !== 200) return say(failure("", status, data), true);
      const bad = data.results.filter((r) => !r.ok || r.came_up === false).map((r) => r.name);
      if (bad.length) say(t("allSomeT", bad), true);
      else say(t("allDoneT", data.results.length));
    } catch {
      say(t("slowAllT"), true);
    } finally {
      delete pending[all];
    }
  });
}
