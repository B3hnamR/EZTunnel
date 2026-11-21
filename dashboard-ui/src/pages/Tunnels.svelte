<script>
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import Blocks from "../lib/Blocks.svelte";
  import Spark from "../lib/Spark.svelte";
  import RangeTabs from "../lib/RangeTabs.svelte";
  import { history, load, key, trimmed } from "../lib/history.svelte.js";
  import Empty from "./Empty.svelte";
  import State from "./State.svelte";
  import { live } from "../lib/live.svelte.js";
  import { t, num, pct, amount, duration, rate } from "../lib/i18n.svelte.js";
  import { tunnelState, transportLabel, shownTransport, isUp, linkState, own } from "../lib/view.js";
  import LinkLine from "../lib/LinkLine.svelte";
  import { pending, pendingKey, confirmAction, confirmRestartAll } from "../lib/actions.svelte.js";
  import LogPanel from "../lib/LogPanel.svelte";
  import EditPanel from "../lib/EditPanel.svelte";
  import DeletePanel from "../lib/DeletePanel.svelte";
  import NewTunnelPanel from "../lib/NewTunnelPanel.svelte";
  import ServerPicker from "../lib/ServerPicker.svelte";
  import { fleet, fleetSeries, serverById, LOCAL } from "../lib/servers.svelte.js";

  /** Which server's tunnels: this one, or a joined server's id. */
  let { server = LOCAL } = $props();
  const remote = $derived(server !== LOCAL);
  const remoteServer = $derived(remote ? serverById(server) : null);

  /** The tunnel whose log is open over this page. */
  let logFor = $state("");
  /** The tunnel whose settings are open for changing. */
  let editFor = $state("");
  /** The tunnel being deleted: { name, pair }. */
  let deleteFor = $state(null);
  let creating = $state(false);

  // Cards or a compact list; remembered per browser.
  let view = $state((() => { try { return localStorage.getItem("ezv") === "list" ? "list" : "cards"; } catch { return "cards"; } })());
  function setView(v) {
    view = v;
    try { localStorage.setItem("ezv", v); } catch { /* private window */ }
  }

  /** The label of a button whose action is under way. */
  const allKey = $derived(remote ? `${server}/*` : "*");
  const doing = (name, action) => pending[pendingKey(name, server)] === action || (pending[allKey] && action === "restart");
  const locked = (name) => Boolean(pending[pendingKey(name, server)] || pending[allKey]);

  const tunnels = $derived(remote ? remoteServer?.snapshot?.tunnels ?? [] : live.snapshot?.tunnels ?? []);

  function size(bytes) {
    const [value, unit] = amount(bytes ?? 0);
    return `${value} ${unit}`;
  }

  // Each card has its own range; every non-live range is one request for all tunnels.
  let ranges = $state({});
  const rangeOf = (name) => own(ranges, name) ?? "live";
  const day = $derived(history[key("24h", "tunnels", server)]?.data);

  $effect(() => {
    const wanted = new Set(["24h", ...Object.values(ranges).filter((r) => r !== "live")]);
    untrack(() => wanted.forEach((r) => load(r, "tunnels", false, server)));
    const timer = setInterval(() => wanted.forEach((r) => load(r, "tunnels", true, server)), 60_000);
    return () => clearInterval(timer);
  });

  function series(name) {
    const range = rangeOf(name);
    if (range === "live") return remote ? own(fleetSeries[server], name) ?? [] : live.history.map((p) => own(p.t, name)?.[0] ?? 0);
    const data = history[key(range, "tunnels", server)]?.data;
    const points = own(data?.tunnels, name)?.points;
    return points ? trimmed(points, data.bucket_sec, range !== "30d").map((p) => p.down / data.bucket_sec) : [];
  }

  function uptime(name) {
    const value = own(day?.tunnels, name)?.uptime_24h_pct;
    return value == null ? null : t("upLine", pct(value));
  }

  /** The note under a card for a link that is not working well. */
  function linkNote(x) {
    if (x.state === "failed") return ["bad", t("note").failed];
    if (x.state !== "running") return null;
    const issue = t("note")[x.link_state];
    if (x.link_state === "not_connected") return ["bad", issue];
    if (["no_traffic", "silent", "quota"].includes(x.link_state)) return ["warn", issue];
    return null;
  }

  function carried(x) {
    // [label, technical value shown left to right]
    const parts = [];
    if (x.carry?.ports?.length) parts.push([t("ports"), x.carry.ports.join(", ")]);
    if (x.carry?.socks) parts.push([t("socks"), ""]);
    if (x.carry?.tun) parts.push([t("tun"), ""]);
    if (x.carry?.exits?.length) parts.push([t("exits"), x.carry.exits.join(", ")]);
    return parts;
  }
</script>

{#if fleet.list.length}<ServerPicker value={server} route="tunnels" />{/if}
{#if remote && !remoteServer}
  <div class="panel act-empty">{fleet.loaded ? t("noSuchServer") : t("loadingT")}</div>
{:else if remote && !remoteServer.online}
  <div class="note warn mb16" role="note"><Icon name="warn" /><span>{t("srvOfflineNote", remoteServer.name)}</span></div>
{/if}
{#if remote ? remoteServer?.online : live.snapshot}
  {#if tunnels.length === 0}
    {#if remote}<div class="panel act-empty"><b>{t("noTunnelLogsT")}</b></div>{:else}<Empty />{/if}
    <div class="row-flex mt12"><button class="btn primary" onclick={() => (creating = true)} aria-haspopup="dialog"><Icon name="plus" />{t("newTunnel")}</button></div>
  {:else}
    <div class="row-flex mb16 tbar">
      <p class="muted small grow m0">{remote ? t("tunCountOn", tunnels.length, remoteServer.name) : t("tunCount", tunnels.length)}</p>
      <div class="seg tview" role="group" aria-label={t("viewAs")}>
        <button type="button" aria-pressed={view === "cards"} onclick={() => setView("cards")} title={t("viewCards")} aria-label={t("viewCards")}><Icon name="grid" /></button>
        <button type="button" aria-pressed={view === "list"} onclick={() => setView("list")} title={t("viewList")} aria-label={t("viewList")}><Icon name="rows" /></button>
      </div>
      <button class="btn primary" onclick={() => (creating = true)} aria-haspopup="dialog"><Icon name="plus" />{t("newTunnel")}</button>
      <button class="btn" onclick={() => confirmRestartAll(tunnels.length, server)} disabled={remote ? Boolean(pending[allKey]) : Object.keys(pending).length > 0} aria-busy={Boolean(pending[allKey])}>
        <Icon name="restart" />{pending[allKey] ? t("restartingAll") : t("restartAll")}
      </button>
    </div>
    {#if view === "list"}
      {@render list()}
    {:else}
    <div class="tgrid">
      {#each tunnels as x, i (x.name)}
        {@const [mark, label] = tunnelState(x)}
        {@const note = linkNote(x)}
        <article class="panel tcard" aria-labelledby="t{i}">
          <div class="hd">
            <div class="grow">
              <div class="title"><h2 id="t{i}" class="ltr"><a class="tlink" href="#/tunnel?t={encodeURIComponent(x.name)}{remote ? `&s=${encodeURIComponent(server)}` : ''}">{x.name}</a></h2>{#if x.transport}<span class="code-chip">{transportLabel(shownTransport(x))}</span>{/if}{#if x.failover}<span class="code-chip" title={t("foH")}>{t("foH")}</span>{/if}{#if x.game}<span class="code-chip" title={t("gameF")}>{t("gameF")}</span>{/if}</div>
              <div class="meta">
                {#if x.direction}<span>{t(x.direction)}</span>{/if}
                {#each carried(x) as [label, value], ci}{#if ci || x.direction}<span aria-hidden="true">·</span>{/if}<span>{label}{#if value}{" "}<span class="ltr">{value}</span>{/if}</span>{/each}
              </div>
            </div>
            <State {mark} {label} />
          </div>
          <LinkLine from={t(x.side || "iran")} to={x.link} state={linkState(x)} label={isUp(x) && x.rtt_ms != null ? `${num(x.rtt_ms)} ms` : ""} />
          {#if x.error}
            <div class="note bad" role="note"><Icon name="warn" /><span>{t("unreadable")} <span class="ltr">{x.error}</span></span></div>
          {:else}
            <div class="kv">
              <div><b>{isUp(x) && x.rtt_ms != null ? `${num(x.rtt_ms)} ms` : "-"}</b><span>{t("ping")}</span></div>
              <div><b>{isUp(x) && x.loss_pct != null ? pct(x.loss_pct) : "-"}</b><span>{t("loss")}</span></div>
              <div><b>{isUp(x) && x.uptime_sec != null ? duration(x.uptime_sec) : "-"}</b><span>{t("uptime")}</span></div>
              <div><b>{x.sessions != null ? num(x.sessions) : "-"}</b><span>{t("sessions")}</span></div>
            </div>
            <div class="row-flex">
              <span class="muted small grow">{t("recv")} {size(x.down_total)} · {t("sent")} {size(x.up_total)}</span>
              <RangeTabs value={rangeOf(x.name)} onchange={(r) => (ranges[x.name] = r)} label="{t('rangeLabel')}: {x.name}" />
            </div>
            <div class="spark">
              <Spark values={series(x.name)} active={rangeOf(x.name) !== "live" || x.state === "running"} warn={mark === "warn"} id={i} />
            </div>
            {#if uptime(x.name)}<div class="muted small">{uptime(x.name)}</div>{/if}
            {#if x.quota}
              <div class="limit">
                <div class="q">
                  <span>{t("limit")}</span>
                  <span>{size(x.quota.used)} {t("of")} {size(x.quota.limit)} · {size(Math.max(0, x.quota.limit - x.quota.used))} {t("left")}</span>
                </div>
                <Blocks value={(x.quota.used / x.quota.limit) * 100} cls={x.quota.used >= x.quota.limit * 0.9 ? "big warn" : "big"} />
              </div>
            {/if}
            {#if note}
              <div class="note {note[0]}" role="note"><Icon name="warn" /><span>{note[1]}</span></div>
            {/if}
            {#if x.last_drop && isUp(x)}
              <div class="muted small">{t("lastDrop")} <span class="ltr">{x.last_drop}</span></div>
            {/if}
            {#if isUp(x) && x.udp_dropped}
              {#if (x.udp_dropped_recent ?? 0) >= 20}
                <div class="note warn" role="note"><Icon name="warn" /><span>{t("udpDropped", num(x.udp_dropped), num(x.udp_dropped_recent))}</span></div>
              {:else}
                <div class="muted small">{t("udpDropped", num(x.udp_dropped), num(x.udp_dropped_recent ?? 0))}</div>
              {/if}
            {/if}
          {/if}
          <div class="actions" role="group" aria-label="{t('actionsOf')} {x.name}">
            {#if isUp(x)}
              <button class="btn" onclick={() => confirmAction(x.name, "stop", server, x.pair ?? null)} disabled={locked(x.name)} aria-busy={doing(x.name, "stop")}>
                <Icon name="stop" />{doing(x.name, "stop") ? t("stopping") : t("stop")}<span class="sr"> {x.name}</span>
              </button>
              <button class="btn" onclick={() => confirmAction(x.name, "restart", server, x.pair ?? null)} disabled={locked(x.name)} aria-busy={doing(x.name, "restart")}>
                <Icon name="restart" />{doing(x.name, "restart") ? t("restarting") : t("restart")}<span class="sr"> {x.name}</span>
              </button>
            {:else}
              <button class="btn" onclick={() => confirmAction(x.name, "start", server, x.pair ?? null)} disabled={locked(x.name) || Boolean(x.error)} aria-busy={doing(x.name, "start")}>
                <Icon name="play" />{doing(x.name, "start") ? t("starting") : t("start")}<span class="sr"> {x.name}</span>
              </button>
            {/if}
            <button class="btn" onclick={() => (editFor = x.name)} disabled={locked(x.name) || Boolean(x.error)} aria-haspopup="dialog" aria-busy={doing(x.name, "edit") || doing(x.name, "undo")}>
              <Icon name="edit" />{doing(x.name, "edit") || doing(x.name, "undo") ? t("saving") : t("edit")}<span class="sr"> {x.name}</span>
            </button>
            <button class="btn" onclick={() => (logFor = x.name)} aria-haspopup="dialog"><Icon name="logs" />{t("logs")}<span class="sr"> {x.name}</span></button>
            <button class="btn danger del-btn" onclick={() => (deleteFor = { name: x.name, pair: x.pair ?? null })} disabled={locked(x.name)} aria-haspopup="dialog" aria-busy={doing(x.name, "delete")}>
              <Icon name="trash" />{doing(x.name, "delete") ? t("deleting") : t("delete")}<span class="sr"> {x.name}</span>
            </button>
          </div>
        </article>
      {/each}
    </div>
    {/if}
  {/if}
{/if}

{#snippet list()}
  {@const top = Math.max(1, ...tunnels.map((x) => (x.down_bps ?? 0) + (x.up_bps ?? 0)))}
  <div class="panel tlist" role="table" aria-label={t("tunnels")}>
    <div class="tl-row tl-head" role="row">
      <span role="columnheader">{t("name")}</span>
      <span role="columnheader">{t("tlLink")}</span>
      <span role="columnheader">{t("tlNow")}</span>
      <span role="columnheader" class="tl-num">{t("sessions")}</span>
      <span role="columnheader" class="tl-num">{t("total")}</span>
      <span role="columnheader">{t("state")}</span>
      <span role="columnheader"><span class="sr">{t("actionsOf")}</span></span>
    </div>
    {#each tunnels as x, i (x.name)}
      {@const [mark, label] = tunnelState(x)}
      {@const up = isUp(x)}
      {@const now = (x.down_bps ?? 0) + (x.up_bps ?? 0)}
      <div class="tl-row tl-{mark}" role="row">
        <span role="cell" class="tl-name">
          <a class="tlink ltr" href="#/tunnel?t={encodeURIComponent(x.name)}{remote ? `&s=${encodeURIComponent(server)}` : ''}">{x.name}</a>
          <small>{#each carried(x) as [lbl, value], ci}{#if ci}<span aria-hidden="true"> · </span>{/if}{lbl}{#if value}{" "}<span class="ltr">{value}</span>{/if}{/each}</small>
        </span>
        <span role="cell" class="tl-link">
          <span class="tl-tags">{#if x.transport}<span class="code-chip">{transportLabel(shownTransport(x))}</span>{/if}{#if x.failover}<span class="code-chip" title={t("foH")}>{t("foH")}</span>{/if}{#if x.game}<span class="code-chip">{t("gameF")}</span>{/if}{#if x.direction}<span class="tl-dir">{t(x.direction)}</span>{/if}</span>
          <small class="ltr">{up && x.rtt_ms != null ? `${num(x.rtt_ms)} ms` : "-"}{#if up && x.loss_pct != null}{" · "}{pct(x.loss_pct)}{/if}</small>
        </span>
        <span role="cell" class="tl-now">
          <span class="tl-spark spark mini"><Spark values={series(x.name).slice(-40)} active={x.state === "running"} warn={mark === "warn"} id={`l${i}`} /></span>
          <span class="tl-rate"><b class="ltr">{up ? rate(now) : "-"}</b>{#if up}<small>Mb/s</small>{/if}<svg class="tl-bar" viewBox="0 0 100 3" preserveAspectRatio="none" aria-hidden="true"><rect class="t" width="100" height="3" rx="1.5" /><rect class="f" width={up && now ? Math.max(2, (now / top) * 100) : 0} height="3" rx="1.5" /></svg></span>
        </span>
        <span role="cell" class="tl-num tl-ses">{x.sessions != null ? num(x.sessions) : "-"}</span>
        <span role="cell" class="tl-num tl-total"><b>{size((x.down_total ?? 0) + (x.up_total ?? 0))}</b>{#if up && x.uptime_sec != null}<small>{duration(x.uptime_sec)}</small>{/if}</span>
        <span role="cell" class="tl-state"><State {mark} {label} /></span>
        <span role="cell" class="tl-act">
          <label class="switch tl-switch" title={up ? t("stop") : t("start")}>
            <input type="checkbox" role="switch" checked={up} disabled={locked(x.name) || Boolean(x.error)} aria-label="{up ? t('stop') : t('start')} {x.name}"
              onclick={(e) => { e.preventDefault(); confirmAction(x.name, up ? "stop" : "start", server, x.pair ?? null); }} />
          </label>
          <button class="btn ghost icon" onclick={() => (logFor = x.name)} title={t("logs")} aria-label="{t('logs')} {x.name}" aria-haspopup="dialog"><Icon name="logs" /></button>
          <button class="btn ghost icon" onclick={() => (editFor = x.name)} disabled={locked(x.name) || Boolean(x.error)} title={t("edit")} aria-label="{t('edit')} {x.name}" aria-haspopup="dialog"><Icon name="edit" /></button>
        </span>
      </div>
    {/each}
  </div>
{/snippet}

<LogPanel name={logFor} {server} onclose={() => (logFor = "")} />
<EditPanel name={editFor} {server} onclose={() => (editFor = "")} />
<NewTunnelPanel open={creating} onclose={() => (creating = false)} />
<DeletePanel name={deleteFor?.name ?? ""} pair={deleteFor?.pair ?? null} {server} onclose={() => (deleteFor = null)} />
