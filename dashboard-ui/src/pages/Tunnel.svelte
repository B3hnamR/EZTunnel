<script>
  // One tunnel: its figures now, its history, a speed test, its traffic limit and the pairing code
  // for setting up the other end by hand.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import Blocks from "../lib/Blocks.svelte";
  import AreaChart from "../lib/AreaChart.svelte";
  import BarChart from "../lib/BarChart.svelte";
  import RangeTabs from "../lib/RangeTabs.svelte";
  import State from "./State.svelte";
  import EditPanel from "../lib/EditPanel.svelte";
  import { history, load, key, trimmed, summary } from "../lib/history.svelte.js";
  import { live } from "../lib/live.svelte.js";
  import { fleet, fleetSeries, LOCAL } from "../lib/servers.svelte.js";
  import { getStatus, runTool } from "../lib/api.js";
  import { pending, pendingKey, ask, say } from "../lib/actions.svelte.js";
  import { t, num, pct, amount, duration, rate as mbit } from "../lib/i18n.svelte.js";
  import { tunnelState, transportLabel, shownTransport, isUp, linkState, own } from "../lib/view.js";
  import LinkLine from "../lib/LinkLine.svelte";

  let { name, server = LOCAL } = $props();
  const remote = $derived(server !== LOCAL);
  const place = $derived(remote ? fleet.list.find((s) => s.id === server) : null);
  const x = $derived((remote ? place?.snapshot?.tunnels : live.snapshot?.tunnels)?.find((t) => t.name === name));
  const base = $derived(remote ? `&s=${encodeURIComponent(server)}` : "");

  const size = (bytes) => amount(bytes ?? 0).join(" ");
  const rate = (bps) => `${mbit(bps ?? 0)} Mbit/s`;

  // The control socket's figures, read every 5 seconds while the page is open.
  let status = $state(null);
  let statusError = $state("");
  // One read at a time; an answer for a page or tunnel left meanwhile is thrown away.
  let statusRead = null;
  async function readStatus() {
    if (statusRead) return;
    const request = new AbortController();
    statusRead = request;
    try {
      const { status: code, data } = await getStatus(name, server, request.signal);
      if (request.signal.aborted) return;
      if (code === 200) {
        status = data;
        statusError = "";
      } else {
        status = null;
        statusError = data?.detail ?? "";
      }
    } catch {
      // The figures shown stay, marked as old (below), rather than looking current.
      if (!request.signal.aborted) statusError = t("slowShort");
    } finally {
      if (statusRead === request) statusRead = null;
    }
  }
  $effect(() => {
    name;
    server;
    untrack(() => {
      status = null;
      statusError = "";
      readStatus();
    });
    const timer = setInterval(readStatus, 5000);
    return () => {
      clearInterval(timer);
      statusRead?.abort();
      statusRead = null;
    };
  });

  const rtt = $derived.by(() => {
    const samples = status?.rtt_ms;
    if (!Array.isArray(samples) || !samples.length) return null;
    const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
    const jitter = samples.length > 1 ? samples.slice(1).reduce((s, v, i) => s + Math.abs(v - samples[i]), 0) / (samples.length - 1) : 0;
    return { min: Math.min(...samples), avg, max: Math.max(...samples), jitter };
  });
  const lossOf = (s) => (s?.pings ? Math.max(0, (s.pings_lost ?? 0) / s.pings) * 100 : null);
  /** Extra figures the transport reports (FEC recovery, pool, certificate...), flattened. */
  const extra = $derived.by(() => {
    const out = [];
    const walk = (value, prefix) => {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        for (const [k, v] of Object.entries(value)) walk(v, prefix ? `${prefix}.${k}` : k);
      } else if (value != null && !Array.isArray(value)) out.push([prefix, String(value)]);
    };
    walk(status?.transport_extensions, "");
    return out;
  });

  /** The rows of the figures panel: [label, parts, technical]. */
  const facts = $derived.by(() => {
    if (!status) return [];
    const rows = [
      [t("connectsF"), [num(status.connects ?? 0)]],
      [t("streamsF"), [num(status.streams ?? 0), t("ofTotal", num(status.streams_total ?? 0))]],
      [t("refusedF"), [num(status.refused ?? 0), num(status.rejected ?? 0)]],
      [t("heartbeatsF"), [t("answeredOf", num(status.pongs ?? 0), num(status.pings ?? 0)), ...(lossOf(status) != null ? [pct(lossOf(status))] : [])]],
    ];
    if (rtt) rows.push([t("rttF"), [`${num(rtt.min)} ms`, `${num(rtt.avg)} ms`, `${num(rtt.max)} ms`, `± ${num(rtt.jitter)} ms`]]);
    rows.push([t("udpDropF"), [num(status.udp_dropped ?? 0), ...(status.udp_oversize ? [t("oversizeF", num(status.udp_oversize))] : [])]]);
    // Game mode: whether its datagram path is up and how the copies race.
    if (x?.game) {
      const g = x.game;
      rows.push([t("gameF"), [g.ready == null ? t("gameUnknown") : g.ready ? t("gameReady") : t("gameWaiting"), t("gameCopiesPort", num(g.copies), num(g.port)),
        t("gamePackets", num(g.packets_out), num(g.packets_in)), t("gameAbsorbed", num(g.copies_absorbed))]]);
    }
    rows.push([t("totalF"), [`${t("recv")} ${size(status.bytes_from_peer)}`, `${t("sent")} ${size(status.bytes_to_peer)}`]]);
    // Flow-control windows in use, in 16 KiB frames, against the memory budget.
    if (status.window_frames_used != null)
      rows.push([t("windowF"), [size(status.window_frames_used * 16384), ...(status.window_frames_limit ? [t("ofTotal", size(status.window_frames_limit * 16384))] : [])]]);
    rows.push([t("versionF"), [String(status.version ?? ""), String(status.role ?? "")]]);
    for (const [k, v] of extra) rows.push([k, [v], true]);
    return rows;
  });

  // History.
  let range = $state("24h");
  const histKey = $derived(key(range, "tunnels", server));
  const data = $derived(history[histKey]?.data);
  const points = $derived(own(data?.tunnels, name)?.points ? trimmed(own(data.tunnels, name).points, data.bucket_sec, range !== "30d") : []);
  const sum = $derived(points.length ? summary(points, data.bucket_sec, range === "30d") : null);
  $effect(() => {
    const r = range === "live" ? "24h" : range;
    const at = server;
    untrack(() => load(r, "tunnels", false, at));
    // Kept current while the page is open, like the other history pages.
    const timer = setInterval(() => load(r, "tunnels", true, at), 60_000);
    return () => clearInterval(timer);
  });
  const liveSeries = $derived(remote ? own(fleetSeries[server], name) ?? [] : live.history.map((p) => own(p.t, name)?.[0] ?? 0));

  // Speed test: download and upload, one connection and four.
  const SIZES = [10, 50, 100];
  let testSize = $state(10);
  let results = $state([]);
  let testing = $state(false);
  const busyKey = $derived(pendingKey(name, server));
  async function speedTest() {
    if (pending[busyKey]) return say(t("busyT"), true);
    testing = true;
    pending[busyKey] = "speedtest";
    results = [];
    try {
      for (const [direction, streams] of [["down", 1], ["up", 1], ["down", 4], ["up", 4]]) {
        const row = { direction, streams, state: "running" };
        results.push(row);
        const i = results.length - 1;
        try {
          const { status: code, data } = await runTool(name, "speedtest", { direction, streams, bytes: testSize << 20 }, server);
          results[i] = code === 200 ? { ...row, state: "done", bps: data.bytes_per_second, seconds: data.seconds } : { ...row, state: "failed", detail: data?.detail ?? "" };
          if (code !== 200) break;
        } catch {
          results[i] = { ...row, state: "failed", detail: t("slowShort") };
          break;
        }
      }
    } finally {
      delete pending[busyKey];
      testing = false;
    }
  }

  // Pairing code.
  let pairing = $state(null);
  let pairAddress = $state("");
  let pairBusy = $state(false);
  let pairError = $state("");
  async function getPairing(address) {
    pairBusy = true;
    pairError = "";
    try {
      const { status: code, data } = await runTool(name, "pairing", address ? { address } : {}, server);
      if (code !== 200) {
        pairError = data?.detail ?? t("failedShort");
        return;
      }
      pairing = data;
      if (data.needs_address && !data.code && !pairAddress) pairAddress = data.suggested ?? "";
    } catch {
      pairError = t("slowShort");
    } finally {
      pairBusy = false;
    }
  }
  async function copyCode() {
    try {
      await navigator.clipboard.writeText(pairing.code);
      say(t("copied"));
    } catch {
      say(t("copyFail"), true);
    }
  }

  // Traffic count reset.
  function resetCount() {
    ask(t("resetQ", name), t("resetText"), t("resetGo"), async () => {
      if (pending[busyKey]) return say(t("busyT"), true);
      pending[busyKey] = "restart";
      try {
        const { status: code, data } = await runTool(name, "quota_reset", {}, server);
        if (code !== 200) return say(`${t("failedT", name)} ${data?.detail ?? ""}`, true);
        say(data.came_up === false ? t("notUpT", name) : t("resetDone", name), data.came_up === false);
      } catch {
        say(t("slowT", name), true);
      } finally {
        delete pending[busyKey];
      }
    });
  }

  let editing = $state("");
</script>

<div class="row-flex mb16 tbar">
  <a class="btn ghost" href="#/tunnels{remote ? `?s=${encodeURIComponent(server)}` : ''}"><Icon name="route" />{t("allTunnels")}</a>
  <span class="grow"></span>
  <a class="btn" href="#/logs?t={encodeURIComponent(name)}{base}"><Icon name="logs" />{t("logs")}</a>
  <button class="btn" onclick={() => (editing = name)} disabled={!x || Boolean(x?.error) || Boolean(pending[busyKey])}><Icon name="edit" />{t("edit")}</button>
</div>

{#if !x}
  <div class="panel act-empty">{(remote ? fleet.loaded : live.snapshot) ? t("noSuchTunnel", name) : t("loadingT")}</div>
{:else}
  {@const [mark, label] = tunnelState(x)}
  <section class="panel tcard mb16" aria-labelledby="tp-h">
    <div class="hd">
      <div class="grow">
        <div class="title"><h2 id="tp-h" class="ltr">{x.name}</h2>{#if x.transport}<span class="code-chip">{transportLabel(shownTransport(x))}</span>{/if}{#if x.failover}<span class="code-chip" title={t("foH")}>{t("foH")}</span>{/if}</div>
        <div class="meta">
          {#if x.direction}<span>{t(x.direction)}</span>{/if}
          {#if remote}{#if x.direction}<span aria-hidden="true">·</span>{/if}<span>{place?.name}</span>{/if}
        </div>
      </div>
      <State {mark} {label} />
    </div>
    <LinkLine from={t(x.side || "iran")} to={x.link} state={linkState(x)} label={isUp(x) && x.rtt_ms != null ? `${num(x.rtt_ms)} ms` : ""} />
    <div class="kv kv6">
      <div><b>{isUp(x) && x.rtt_ms != null ? `${num(x.rtt_ms)} ms` : "-"}</b><span>{t("ping")}</span></div>
      <div><b>{isUp(x) && x.loss_pct != null ? pct(x.loss_pct) : "-"}</b><span>{t("loss")}</span></div>
      <div><b>{isUp(x) && x.uptime_sec != null ? duration(x.uptime_sec) : "-"}</b><span>{t("uptime")}</span></div>
      <div><b>{x.sessions != null ? num(x.sessions) : "-"}</b><span>{t("sessions")}</span></div>
      <div><b>{isUp(x) ? rate(x.down_bps) : "-"}</b><span>{t("down")}</span></div>
      <div><b>{isUp(x) ? rate(x.up_bps) : "-"}</b><span>{t("up")}</span></div>
    </div>
  </section>

  {@const fo = status?.failover ?? x.failover}
  {#if fo}
    <section class="panel mb16" aria-labelledby="tp-fo">
      <div class="row-flex mb12">
        <h3 id="tp-fo" class="sec-h grow m0">{t("foH")}</h3>
        {#if fo.switches != null}<span class="muted small">{t("foSwitches", num(fo.switches))}</span>{/if}
      </div>
      <ol class="fo-list">
        {#each fo.carriers ?? [] as c (c.order)}
          {@const word = c.state === "healthy" ? "ok" : c.state === "down" ? "bad" : c.state ? "warn" : ""}
          <li class="fo-row fo-live" class:fo-on={c.active}>
            <span class="fo-n" aria-hidden="true">{num(c.order)}</span>
            <div class="grow">
              <b class="ltr">{c.carrier}</b>
              {#if c.active}<span class="code-chip">{t("foActive")}</span>{/if}
              {#if c.state}
                <div class="muted small">
                  <span class="mark {word}" aria-hidden="true"></span>
                  {t("foState")[c.state] ?? c.state}{#if c.why}{" · "}{t("foWhy")[c.why] ?? c.why}{/if}{#if c.for_sec != null}{" · "}{t("foFor", duration(Math.max(1, c.for_sec)))}{/if}{#if c.sessions != null}{" · "}{t("foSessions", num(c.sessions))}{/if}
                </div>
              {/if}
            </div>
          </li>
        {/each}
      </ol>
      {#if fo.active == null}<p class="muted small m0 mt8">{t("foNotLive")}</p>{/if}
      {#if fo.return_after_sec}<p class="muted small m0 mt8">{t("foReturn", duration(fo.return_after_sec))}</p>{/if}
    </section>
  {/if}

  <div class="tp-grid">
    <section class="panel" aria-labelledby="tp-now">
      <h3 id="tp-now" class="sec-h">{t("figuresNow")}</h3>
      {#if status}
        {#if statusError}<p class="note warn small m0" role="status">{t("figuresOld", statusError)}</p>{/if}
        <dl class="facts" class:stale={Boolean(statusError)}>
          {#each facts as [label, parts, ltr]}
            <div>
              <dt class:ltr class:mono={ltr}>{label}</dt>
              <dd>{#each parts as part, i}{#if i}<span class="sep" aria-hidden="true">·</span>{/if}<span class:ltr>{part}</span>{/each}</dd>
            </div>
          {/each}
        </dl>
      {:else}
        <p class="muted m0">{isUp(x) ? (statusError || t("loadingT")) : t("notRunningFigures")}</p>
      {/if}
      {#if x.last_drop && isUp(x)}<p class="muted small">{t("lastDrop")} <span class="ltr">{x.last_drop}</span></p>{/if}
    </section>

    <section class="panel" aria-labelledby="tp-limit">
      <h3 id="tp-limit" class="sec-h">{t("limitH")}</h3>
      {#if x.quota}
        <div class="limit">
          <div class="q"><span>{size(x.quota.used)} {t("of")} {size(x.quota.limit)}</span><span>{size(Math.max(0, x.quota.limit - x.quota.used))} {t("left")}</span></div>
          <Blocks value={(x.quota.used / x.quota.limit) * 100} cls={x.quota.used >= x.quota.limit * 0.9 ? "big warn" : "big"} />
        </div>
        <div class="row-flex mt12">
          <button class="btn" onclick={() => (editing = name)} disabled={Boolean(pending[busyKey])}>{t("changeLimit")}</button>
          <button class="btn" onclick={resetCount} disabled={Boolean(pending[busyKey]) || !isUp(x)}><Icon name="restart" />{t("resetCount")}</button>
        </div>
      {:else}
        <p class="muted m0">{t("noLimit")}</p>
        <div class="row-flex mt12"><button class="btn" onclick={() => (editing = name)} disabled={Boolean(pending[busyKey])}>{t("setLimit")}</button></div>
      {/if}
    </section>
  </div>

  <section class="panel mt16" aria-labelledby="tp-hist">
    <div class="row-flex mb16">
      <h3 id="tp-hist" class="sec-h grow m0">{t("historyH")}</h3>
      <RangeTabs value={range} onchange={(r) => (range = r)} label="{t('rangeLabel')}: {name}" />
    </div>
    {#if range === "live"}
      <div class="chart"><AreaChart recv={liveSeries} sent={[]} label="{t('traffic')}, {t('live')}" id="tpl" /></div>
    {:else if !data}
      <div class="chart-empty" role="status">{history[histKey]?.error ? t("historyError") : t("loadingT")}</div>
    {:else if !points.length}
      <div class="chart-empty">{t("noHistory")}</div>
    {:else}
      <div class="chart">
        {#if range === "30d"}
          <BarChart values={points.map((p) => p.down + p.up)} label="{t('traffic')}, {t('d30')}" />
        {:else}
          <AreaChart recv={points.map((p) => p.down / data.bucket_sec)} sent={points.map((p) => p.up / data.bucket_sec)} label="{t('traffic')}, {t(range === '24h' ? 'h24' : 'd7')}" id="tph" />
        {/if}
      </div>
      {#if sum}
        <div class="kv mt12">
          {#if range === "30d"}
            <div><b>{size(sum.total)}</b><span>{t("totalR")}</span></div>
            <div><b>{size(sum.busiest)}</b><span>{t("busiest")}</span></div>
            <div><b>{size(sum.average)}</b><span>{t("dailyAvg")}</span></div>
          {:else}
            <div><b>{rate(sum.peak)}</b><span>{t("peak")}</span></div>
            <div><b>{rate(sum.average)}</b><span>{t("avg")}</span></div>
            <div><b>{rate(sum.low)}</b><span>{t("low")}</span></div>
          {/if}
          {#if own(data.tunnels, name)?.uptime_pct != null}<div><b>{pct(own(data.tunnels, name).uptime_pct)}</b><span>{t("uptimeRange")}</span></div>{/if}
        </div>
      {/if}
    {/if}
  </section>

  <div class="tp-grid mt16">
    <section class="panel" aria-labelledby="tp-speed">
      <h3 id="tp-speed" class="sec-h">{t("speedH")}</h3>
      {#if x.side === "foreign"}
        <p class="muted m0">{t("speedFromIran")}</p>
      {:else if !isUp(x)}
        <p class="muted m0">{t("notRunningFigures")}</p>
      {:else}
        <p class="muted small">{t("speedText")}</p>
        <div class="row-flex">
          <label class="sr" for="tp-size">{t("testSize")}</label>
          <select id="tp-size" class="input sel-auto" bind:value={testSize} disabled={testing}>
            {#each SIZES as mb}<option value={mb}>{t("eachWay", num(mb))}</option>{/each}
          </select>
          <button class="btn primary" onclick={speedTest} disabled={testing || Boolean(pending[busyKey])} aria-busy={testing}>{testing ? t("testing") : t("runTest")}</button>
        </div>
        {#if results.length}
          <table class="speed mt12">
            <tbody>
              {#each results as r}
                <tr>
                  <th scope="row">{t(r.direction === "down" ? "downTest" : "upTest")} · {t(r.streams === 1 ? "oneConn" : "fourConn")}</th>
                  <td>
                    {#if r.state === "running"}<span class="muted">{t("testing")}</span>
                    {:else if r.state === "failed"}<span class="bad-t">{r.detail || t("failedShort")}</span>
                    {:else}<b class="ltr">{num((r.bps * 8) / 1e6)} Mbit/s</b>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
          <p class="muted small m0 mt12">{t("speedNote")}</p>
        {/if}
      {/if}
    </section>

    <section class="panel" aria-labelledby="tp-pair">
      <h3 id="tp-pair" class="sec-h">{t("pairH")}</h3>
      <p class="muted small">{t("pairText")}</p>
      {#if pairing?.code}
        <div class="code-box ltr mono" aria-label={t("pairH")}>{pairing.code}</div>
        <div class="row-flex mt12">
          <button class="btn" onclick={copyCode}><Icon name="copy" />{t("copy")}</button>
          <button class="btn ghost" onclick={() => (pairing = null)}>{t("hide")}</button>
        </div>
        <div class="note warn mt12" role="note"><Icon name="lock" /><span>{t("pairSecret")}</span></div>
      {:else if pairing?.needs_address}
        <label class="flabel" for="tp-addr">{t("pairAddress")}</label>
        <div class="row-flex">
          <input id="tp-addr" class="input ltr grow" bind:value={pairAddress} autocomplete="off" spellcheck="false" />
          <button class="btn primary" onclick={() => getPairing(pairAddress.trim())} disabled={pairBusy || !pairAddress.trim()}>{t("showCode")}</button>
        </div>
      {:else}
        <button class="btn" onclick={() => getPairing("")} disabled={pairBusy}><Icon name="lock" />{t("showCode")}</button>
      {/if}
      {#if pairError}<p class="small bad-t">{pairError}</p>{/if}
    </section>
  </div>
{/if}

<EditPanel name={editing} {server} onclose={() => (editing = "")} />
