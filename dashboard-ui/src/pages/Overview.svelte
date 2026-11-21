<script>
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import AreaChart from "../lib/AreaChart.svelte";
  import BarChart from "../lib/BarChart.svelte";
  import RangeTabs from "../lib/RangeTabs.svelte";
  import { history, load, key, trimmed, summary, today } from "../lib/history.svelte.js";
  import Strip from "./Strip.svelte";
  import Empty from "./Empty.svelte";
  import State from "./State.svelte";
  import { live } from "../lib/live.svelte.js";
  import { t, ui, num, pct, rate, amount, dateText } from "../lib/i18n.svelte.js";
  import { tunnelState, transportLabel, shownTransport, isUp, linkState } from "../lib/view.js";
  import LinkLine from "../lib/LinkLine.svelte";
  import { fleet } from "../lib/servers.svelte.js";

  const reduced = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  // Under reduced motion the chart starts still; Resume makes it follow the data.
  let paused = $state(reduced);
  let frozen = $state([]);

  const snap = $derived(live.snapshot);
  const tunnels = $derived(snap?.tunnels ?? []);
  // Trouble on every server: this one's, each joined server's, and joined servers that went quiet.
  const issues = $derived([
    ...(snap?.issues ?? []),
    ...fleet.list.flatMap((s) =>
      s.online
        ? (s.snapshot?.issues ?? []).map((i) => ({ ...i, server: s.name, serverId: s.id }))
        : [{ level: "bad", kind: "server_offline", server: s.name, serverId: s.id }],
    ),
    // Drift: a joined server running another program version than this one.
    ...fleet.list
      .filter((s) => s.online && s.snapshot?.version && snap?.version && s.snapshot.version !== snap.version)
      .map((s) => ({ level: "warn", kind: "server_version", server: s.name, serverId: s.id, value: s.snapshot.version })),
  ]);
  const level = $derived(issues.some((i) => i.level === "bad") ? "bad" : issues.length ? "warn" : "ok");
  const remoteTunnels = $derived(fleet.list.flatMap((s) => (s.online ? s.snapshot?.tunnels ?? [] : [])));
  const allTunnels = $derived([...tunnels, ...remoteTunnels]);
  const running = $derived(tunnels.filter((x) => x.state === "running"));
  const runningAll = $derived(allTunnels.filter((x) => x.state === "running"));
  const pings = $derived(runningAll.map((x) => x.rtt_ms).filter((v) => v != null));
  const serversOnline = $derived(fleet.list.filter((s) => s.online).length);
  const shown = $derived(paused ? frozen : live.history);

  // Ranges other than Live come from the stored history (all tunnels summed).
  let range = $state("live");
  const entry = $derived(range === "live" ? null : history[key(range, "all")]);
  const data = $derived(entry?.data);
  const daily = $derived(range === "30d");
  const points = $derived(data ? trimmed(data.points, data.bucket_sec, !daily) : []);
  const stats = $derived(data ? summary(points, data.bucket_sec, daily) : null);
  const startsLate = $derived(data && data.first_at != null && data.first_at > data.from);
  // "Traffic today" always comes from the 24-hour history.
  const day = $derived(history[key("24h", "all")]?.data);
  const todayBytes = $derived(day ? today(day.points) : null);

  // Only the chosen range drives this effect; loading reads the history state, which must not
  // re-run it (that would retry a failed request in a loop).
  $effect(() => {
    const chosen = range;
    untrack(() => {
      load("24h", "all");
      if (chosen !== "live") load(chosen, "all");
    });
    // Rows are written once a minute; refresh while this screen is open.
    const timer = setInterval(() => {
      load("24h", "all", true);
      if (chosen !== "live") load(chosen, "all", true);
    }, 60_000);
    return () => clearInterval(timer);
  });

  function size(bytes) {
    const [value, unit] = amount(bytes);
    return [value, unit];
  }

  function togglePause() {
    if (!paused) frozen = live.history;
    paused = !paused;
  }

  function issueText(issue) {
    const text = t("issue")[issue.kind];
    if (typeof text !== "function") return text;
    const counted = ["udp_drops", "failover_backup", "carrier_down"].includes(issue.kind);
    return text(counted ? num(issue.value ?? 0) : pct(issue.value ?? 0));
  }

  function total(x) {
    if (x.down_total == null) return "-";
    const [value, unit] = amount(x.down_total + (x.up_total ?? 0));
    return `${value} ${unit}`;
  }
</script>

{#if snap}
  <Strip host={snap.host} />
  {#if allTunnels.length === 0 && fleet.list.length === 0}
    <Empty />
  {:else}
    <div class="ov-grid">
    <section class="panel" aria-labelledby="tr-h">
      <div class="row-flex">
        <div class="grow"><h2 id="tr-h">{t("traffic")}</h2><div class="muted small">{t("trafficSub")}</div></div>
        <div class="legend"><span><i class="sw-recv"></i>{t("recv")}</span><span><i class="sw-sent"></i>{t("sent")}</span></div>
        <RangeTabs value={range} onchange={(r) => (range = r)} label={t("rangeLabel")} />
        {#if range === "live"}
          <button class="btn icon" onclick={togglePause} aria-label={paused ? t("resume") : t("pause")} title={paused ? t("resume") : t("pause")}>
            <Icon name={paused ? "play" : "pause"} />
          </button>
        {/if}
      </div>
      <div class="chart">
        {#if range === "live"}
          {#if shown.length < 2}
            <div class="chart-empty">{t("chartWait")}</div>
          {:else}
            <AreaChart recv={shown.map((p) => p.down)} sent={shown.map((p) => p.up)} label={t("traffic")} id="ov" />
          {/if}
        {:else if !data && entry?.error}
          <div class="chart-empty" role="alert">
            <div class="row-flex">{t("historyError")}<button class="btn" onclick={() => load(range, "all", true)}>{t("retry")}</button></div>
          </div>
        {:else if !data}
          <div class="chart-empty" role="status">{t("historyLoading")}</div>
        {:else if points.length < (daily ? 1 : 2)}
          <div class="chart-empty">{t("noHistory")}</div>
        {:else if daily}
          <BarChart values={points.map((p) => p.down + p.up)} label="{t('traffic')}, {t('d30')}" />
        {:else}
          <AreaChart
            recv={points.map((p) => p.down / data.bucket_sec)}
            sent={points.map((p) => p.up / data.bucket_sec)}
            label="{t('traffic')}, {t(range === '24h' ? 'h24' : 'd7')}"
            id="ovh" />
        {/if}
      </div>
      {#if range !== "live" && stats}
        <div class="chart-stats">
          {#if daily}
            {@const a = size(stats.total)}{@const b = size(stats.busiest)}{@const c = size(stats.average)}
            <span>{t("totalR")}<b>{a[0]} {a[1]}</b></span>
            <span>{t("busiest")}<b>{b[0]} {b[1]}</b></span>
            <span>{t("dailyAvg")}<b>{c[0]} {c[1]}</b></span>
          {:else}
            <span>{t("peak")}<b>{rate(stats.peak)} Mb/s</b></span>
            <span>{t("low")}<b>{rate(stats.low)} Mb/s</b></span>
            <span>{t("avg")}<b>{rate(stats.average)} Mb/s</b></span>
          {/if}
        </div>
      {/if}
      {#if range !== "live" && startsLate}
        <div class="chart-note">{t("historyFrom", dateText(data.first_at))}</div>
      {/if}
    </section>

    <section class="panel" aria-labelledby="hero-h">
      <div class="ov-status"><span class="mark {level}"></span><h2 id="hero-h">{issues.length ? t("attn", issues.length) : t("healthy")}</h2></div>
      {#if issues.length}
        <ul class="issues">
          {#each issues as issue}
            <li>
              <span class="mark {issue.level}"></span>
              {#if issue.kind === "server_offline"}
                <span>{ui.lang === "fa" ? "سرور " : ""}<b class="ltr">{issue.server}</b> {t("issue").server_offline}</span>
              {:else if issue.kind === "server_version"}
                <span>{ui.lang === "fa" ? "سرور " : ""}<b class="ltr">{issue.server}</b> {t("versionDrift", issue.value, snap.version)}</span>
              {:else}
                <span>{ui.lang === "fa" ? "تونل " : ""}<b class="ltr">{issue.tunnel}</b>{#if issue.server}<span class="issue-on">{t("issueOn")} <b class="ltr">{issue.server}</b></span>{/if} {issueText(issue)}</span>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
      <div class="figures">
        <div><span class="label">{fleet.list.length ? t("kTunnelsAll") : t("kTunnels")}</span><span class="num">{num(runningAll.length)}<small>{t("of")} {num(allTunnels.length)}</small></span></div>
        {#if fleet.list.length}
          <div><span class="label">{t("kServers")}</span><span class="num">{num(serversOnline + 1)}<small>{t("of")} {num(fleet.list.length + 1)}</small></span></div>
        {/if}
        <div>
          <span class="label">{t("kToday")}</span>
          {#if todayBytes == null}<span class="num">-</span>{:else}{@const [v, u] = size(todayBytes)}<span class="num">{v}<small>{u}</small></span>{/if}
        </div>
        <div>
          <span class="label">{t("kPing")}</span>
          <span class="num">{pings.length ? num(pings.reduce((a, b) => a + b, 0) / pings.length) : "-"}<small>ms</small></span>
        </div>
      </div>
      <div class="row-flex ov-quick mt16">
        <a class="btn" href={fleet.list.length ? "#/servers" : "#/tunnels"}>{fleet.list.length ? t("openServers") : t("openTunnels")}</a>
        <a class="btn ghost" href="#/health"><Icon name="health" />{t("health")}</a>
        <a class="btn ghost" href="#/alerts"><Icon name="alerts" />{t("alerts")}</a>
      </div>
    </section>
    </div>

    {#if tunnels.length}
    <div class="sec-head"><h2>{t("tunnelsList")}</h2><div class="grow"></div><a class="btn" href="#/tunnels">{t("viewAll")}</a></div>
    <div class="panel tablewrap">
      <table class="table">
        <thead>
          <tr>
            <th scope="col">{t("name")}</th>
            <th scope="col">{t("route")}</th>
            <th scope="col" class="hide-m">{t("loss")}</th>
            <th scope="col" class="hide-m">{t("total")}</th>
            <th scope="col">{t("state")}</th>
          </tr>
        </thead>
        <tbody>
          {#each tunnels as x (x.name)}
            {@const [mark, label] = tunnelState(x)}
            <tr>
              <td class="tname"><span class="ltr">{x.name}</span><small><span class="ltr">{transportLabel(shownTransport(x))}</span>{#if x.failover} · {t("foH")}{/if} · {t(x.direction || "reverse")}</small></td>
              <td><LinkLine from={t(x.side || "iran")} to={x.link} state={linkState(x)} label={isUp(x) && x.rtt_ms != null ? `${num(x.rtt_ms)} ms` : ""} /></td>
              <td class="num hide-m">{isUp(x) && x.loss_pct != null ? pct(x.loss_pct) : "-"}</td>
              <td class="num hide-m">{total(x)}</td>
              <td><State {mark} {label} /></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {/if}
  {/if}
{/if}
