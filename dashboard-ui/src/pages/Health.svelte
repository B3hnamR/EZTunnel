<script>
  // The health check of one server: what is fine, what needs attention and the fix for each, then
  // the kernel optimization and where the files are.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { serverTool } from "../lib/api.js";
  import { say, ask } from "../lib/actions.svelte.js";
  import { fleet, LOCAL } from "../lib/servers.svelte.js";
  import { t, num, pct, amount, clock } from "../lib/i18n.svelte.js";
  import Ring from "../lib/Ring.svelte";

  let { server = LOCAL } = $props();
  const remote = $derived(server !== LOCAL);
  const place = $derived(remote ? fleet.list.find((s) => s.id === server) : null);

  let checks = $state(null);
  let checking = $state(false);
  let problem = $state("");
  let fixing = $state("");
  let plan = $state(null);
  let files = $state(null);
  let optimizing = $state(false);
  let checkedAt = $state(0);

  async function run() {
    checking = true;
    problem = "";
    try {
      const { status, data } = await serverTool(server, "health");
      if (status === 200) {
        checks = data.checks;
        checkedAt = Date.now();
      }
      else problem = data?.detail ?? t("failedShort");
    } catch {
      problem = t("slowShort");
    } finally {
      checking = false;
    }
    loadPlan();
    loadFiles();
  }

  async function loadPlan() {
    try {
      const { status, data } = await serverTool(server, "optimize_plan");
      if (status === 200) plan = data;
    } catch {}
  }

  async function loadFiles() {
    try {
      const { status, data } = await serverTool(server, "files");
      if (status === 200) files = data.files;
    } catch {}
  }

  // Runs when the page opens and when the server comes online, not on every server-list refresh.
  const ready = $derived(!remote || Boolean(place?.online));
  $effect(() => {
    if (ready) untrack(run);
  });

  const order = { bad: 0, warn: 1, ok: 2 };
  const system = $derived((checks ?? []).filter((c) => !c.subject).sort((a, b) => order[a.level] - order[b.level]));
  const tunnels = $derived.by(() => {
    const groups = {};
    for (const c of checks ?? []) if (c.subject) (groups[c.subject] ??= []).push(c);
    return Object.entries(groups).sort(([, a], [, b]) => Math.min(...a.map((c) => order[c.level])) - Math.min(...b.map((c) => order[c.level])));
  });
  // Everything that is not fine, worst first, across the server and its tunnels.
  const attention = $derived((checks ?? []).filter((c) => c.level !== "ok").sort((a, b) => order[a.level] - order[b.level]));
  const passing = $derived(system.filter((c) => c.level === "ok"));
  const okCount = $derived((checks ?? []).filter((c) => c.level === "ok").length);
  const counts = $derived({
    bad: (checks ?? []).filter((c) => c.level === "bad").length,
    warn: (checks ?? []).filter((c) => c.level === "warn").length,
  });

  /** What a finding says, in words. */
  function describe(c) {
    const v = c.value;
    switch (c.id) {
      case "time_sync": return t(v ? "hcTimeOk" : "hcTimeBad");
      case "congestion": return t(c.level === "ok" ? "hcBbrOk" : "hcBbrBad", v);
      case "optimize": return c.level === "ok" ? t("hcOptOk") : t("hcOptBad", num(v));
      case "disk": return t("hcDisk", pct(v));
      case "memory": return t("hcMemory", pct(v));
      case "udp_buffers": return t(c.level === "ok" ? "hcUdpOk" : "hcUdpBad", amount(v.have).join(" "), amount(v.want).join(" "));
      case "ip_forward": return t(v ? "hcFwdOk" : "hcFwdBad");
      case "config": return `${t("hcConfig")} ${v}`;
      case "service": return t("hcService")[v] ?? v;
      case "link": return `${t("note")[v.state] ?? t("hcLinkOk")}${v.last_drop ? ` ${t("lastDrop")} ${v.last_drop}` : ""}`;
      case "program": return t("hcProgram", v);
      case "debug_logging": return t("hcDebug");
      case "firewall": return t(c.level === "ok" ? "hcFwOpen" : "hcFwClosed", v);
      default: return String(v ?? "");
    }
  }

  const FIX_ICONS = { restart: "restart", start: "play", debug_off: "stop", optimize: "settings", udp_buffers: "plus", ufw: "lock" };
  const fixIcon = (fix) => FIX_ICONS[fix.split(":")[0]] ?? "check";

  function fixLabel(fix) {
    const kind = fix.split(":")[0];
    return t("fixes")[kind] ?? fix;
  }

  async function doFix(fix) {
    if (fixing) return;
    fixing = fix;
    try {
      const { status, data } = await serverTool(server, "fix", { fix });
      if (status !== 200) say(`${t("fixFailed")} ${data?.detail ?? ""}`, true);
      else say(data.came_up === false ? t("fixNotUp") : t("fixDone"), data.came_up === false);
    } catch {
      say(t("slowShort"), true);
    } finally {
      fixing = "";
    }
    run();
  }

  function optimize(apply) {
    ask(t(apply ? "optQ" : "optUndoQ"), t(apply ? "optText" : "optUndoText"), t(apply ? "optApply" : "optUndo"), async () => {
      optimizing = true;
      try {
        const { status, data } = await serverTool(server, apply ? "optimize_apply" : "optimize_undo");
        if (status !== 200) say(`${t("fixFailed")} ${data?.detail ?? ""}`, true);
        else if (data.failed?.length) say(t("optSome", data.failed.join(", ")), true);
        else say(t(apply ? "optDone" : "optUndone"));
      } catch {
        say(t("slowShort"), true);
      } finally {
        optimizing = false;
      }
      run();
    });
  }

  // Every server at a glance: its score and counts; a card opens that server's details below.
  const all = $derived([
    { id: LOCAL, name: t("thisServer"), online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, online: s.online })),
  ]);
  let overview = $state({});
  async function survey() {
    for (const p of all.filter((p) => p.online)) {
      if (p.id === server) continue;
      overview[p.id] = { ...(overview[p.id] ?? {}), loading: true };
      serverTool(p.id, "health").then(({ status, data }) => {
        overview[p.id] = status === 200 ? { checks: data.checks, at: Date.now() } : { error: data?.detail ?? t("failedShort") };
      }).catch(() => (overview[p.id] = { error: t("slowShort") }));
    }
  }
  const onlineAll = $derived(all.filter((p) => p.online).map((p) => p.id).join(","));
  $effect(() => {
    onlineAll;
    untrack(survey);
  });
  // The open server's own run keeps its card current.
  $effect(() => {
    if (checks) untrack(() => (overview[server] = { checks, at: checkedAt }));
  });
  const tally = (list) => ({
    bad: list.filter((c) => c.level === "bad").length,
    warn: list.filter((c) => c.level === "warn").length,
    ok: list.filter((c) => c.level === "ok").length,
  });
  function open(id) {
    location.hash = id === LOCAL ? "#/health" : `#/health?s=${encodeURIComponent(id)}`;
  }

  const when = (secs) => (secs ? new Date(secs * 1000).toLocaleString(document.documentElement.lang === "fa" ? "fa-IR" : "en-GB") : "-");
</script>

{#if fleet.list.length}
  <section class="hc-fleet mb16" aria-label={t("hcFleet")}>
    {#each all as p (p.id)}
      {@const o = overview[p.id]}
      {@const n = o?.checks ? tally(o.checks) : null}
      <button type="button" class="panel hc-srv" class:on={p.id === server} aria-pressed={p.id === server} onclick={() => open(p.id)} disabled={!p.online && p.id !== server}>
        <Ring value={n ? (n.ok / Math.max(1, o.checks.length)) * 100 : null} label={t("hcNOk")} id="hcs-{p.id}" tone={n ? (n.bad ? "bad" : n.warn ? "warn" : "ok") : null} />
        <span class="hc-srv-t">
          <b>{p.name}</b>
          {#if !p.online}<span class="muted small">{t("offline")}</span>
          {:else if o?.error}<span class="bad-t small">{t("failedShort")}</span>
          {:else if !n}<span class="muted small">{t("hcRunning")}</span>
          {:else if n.bad}<span class="bad-t small">{t("hcBadCount", num(n.bad))}</span>
          {:else if n.warn}<span class="warn-t small">{t("hcWarnCount", num(n.warn))}</span>
          {:else}<span class="ok-t small">{t("hcAllOk")}</span>{/if}
          {#if n}<span class="muted small">{t("hcScore", num(n.ok), num(o.checks.length))}</span>{/if}
        </span>
      </button>
    {/each}
  </section>
{/if}

{#if remote && !place}
  <div class="panel act-empty">{fleet.loaded ? t("noSuchServer") : t("loadingT")}</div>
{:else if remote && !place.online}
  <div class="note warn" role="note"><Icon name="warn" /><span>{t("srvOfflineNote", place.name)}</span></div>
{:else}
  <section class="panel hc-top" aria-label={t("health")}>
    <div class="hc-score">
      <Ring value={checks ? (okCount / Math.max(1, checks.length)) * 100 : null} label={t("hcNOk")} id="hc" tone={counts.bad ? "bad" : counts.warn ? "warn" : "ok"} />
      <div>
        <h2 role="status">
          {#if checks}
            {#if counts.bad}<span class="bad-t">{t("hcBadCount", num(counts.bad))}</span>{:else if counts.warn}<span class="warn-t">{t("hcWarnCount", num(counts.warn))}</span>{:else}<span class="ok-t">{t("hcAllOk")}</span>{/if}
          {:else if checking}<span class="muted">{t("hcRunning")}</span>{:else}-{/if}
        </h2>
        <p class="muted small m0">{checks ? t("hcScore", num(okCount), num(checks.length)) : ""}{#if checkedAt}<span class="act-sep">·</span>{t("hcChecked", clock(checkedAt))}{/if}</p>
      </div>
    </div>
    <div class="hc-counts">
      <div class:zero={!counts.bad}><span class="mark bad"></span><b class="num">{checks ? num(counts.bad) : "-"}</b><span>{t("hcNProblems")}</span></div>
      <div class:zero={!counts.warn}><span class="mark warn"></span><b class="num">{checks ? num(counts.warn) : "-"}</b><span>{t("hcNWarn")}</span></div>
      <div><span class="mark ok"></span><b class="num">{checks ? num(okCount) : "-"}</b><span>{t("hcNOk")}</span></div>
    </div>
    <button class="btn" onclick={run} disabled={checking} aria-busy={checking}><Icon name="restart" />{checking ? t("hcRunning") : t("hcAgain")}</button>
  </section>
  {#if problem}<div class="note bad mb16" role="alert"><Icon name="warn" /><span>{problem}</span></div>{/if}

  {#if checks}
    <div class="hc-grid">
      <section class="panel" aria-labelledby="hc-need">
        <h3 id="hc-need" class="sec-h">{t("hcNeeds")}</h3>
        {#if attention.length}
          <ul class="hc-list">
            {#each attention as c, i (c.id + (c.subject ?? "") + i)}
              <li class="hc {c.level}">
                <span class="mark {c.level}" aria-hidden="true"></span>
                <div class="grow">
                  <b>{t("hc")[c.id] ?? c.id}{#if c.subject}<a class="code-chip ltr hc-sub" href="#/tunnel?t={encodeURIComponent(c.subject)}{remote ? `&s=${encodeURIComponent(server)}` : ''}">{c.subject}</a>{/if}</b>
                  <span class="muted small">{describe(c)}</span>
                </div>
                {#if c.fix}<button class="btn {c.level === 'bad' ? 'primary' : ''}" onclick={() => doFix(c.fix)} disabled={Boolean(fixing)} aria-busy={fixing === c.fix}><Icon name={fixIcon(c.fix)} />{fixing === c.fix ? t("fixing") : fixLabel(c.fix)}</button>{/if}
                <span class="sr">{t("lvl")[c.level]}</span>
              </li>
            {/each}
          </ul>
        {:else}
          <div class="hc-clear"><span class="hc-clear-i"><Icon name="check" /></span><div><b>{t("hcNothing")}</b><p class="muted small m0">{t("hcNothingSub")}</p></div></div>
        {/if}
      </section>

      <section class="panel" aria-labelledby="hc-sys">
        <h3 id="hc-sys" class="sec-h">{t("hcSystem")}<span class="muted small hc-h-n">{num(passing.length)} {t("hcPassing")}</span></h3>
        <ul class="hc-tiles">
          {#each passing as c (c.id)}
            <li><span class="mark ok" aria-hidden="true"></span><div><b>{t("hc")[c.id] ?? c.id}</b><span class="muted small">{describe(c)}</span></div></li>
          {/each}
        </ul>
      </section>
    </div>

    {#if tunnels.length}
      <div class="sec-head"><h2>{t("hcTunnelsH")}</h2></div>
      <div class="hc-tgrid">
        {#each tunnels as [name, list] (name)}
          {@const worst = list.some((c) => c.level === "bad") ? "bad" : list.some((c) => c.level === "warn") ? "warn" : "ok"}
          <section class="panel hc-t {worst}" aria-labelledby="hc-t-{name}">
            <header><span class="mark {worst}"></span><h3 id="hc-t-{name}"><a class="tlink ltr" href="#/tunnel?t={encodeURIComponent(name)}{remote ? `&s=${encodeURIComponent(server)}` : ''}">{name}</a></h3><span class="muted small">{num(list.filter((c) => c.level === "ok").length)}/{num(list.length)}</span></header>
            <ul>
              {#each list as c, i (c.id + i)}
                <li class={c.level}><span class="mark {c.level}" aria-hidden="true"></span><span class="grow"><b>{t("hc")[c.id] ?? c.id}</b> <span class="muted">{describe(c)}</span></span></li>
              {/each}
            </ul>
          </section>
        {/each}
      </div>
    {/if}
  {/if}

  <div class="tp-grid mt16">
    <section class="panel" aria-labelledby="hc-opt">
      <h3 id="hc-opt" class="sec-h">{t("optH")}</h3>
      <p class="muted small">{t("optAbout")}</p>
      {#if plan}
        {#if plan.changes.length}
          <ul class="opt-list">
            {#each plan.changes as c (c.key)}
              <li>
                <div class="grow"><span class="ltr mono">{c.key}</span><div class="muted small ltr edesc">{c.why}</div></div>
                <span class="opt-v ltr"><span class="from mono">{c.current}</span><span aria-hidden="true">→</span><b class="mono">{c.wanted}</b></span>
              </li>
            {/each}
          </ul>
        {:else}
          <div class="hc-clear"><span class="hc-clear-i"><Icon name="check" /></span><b>{t("optNothing")}</b></div>
        {/if}
        <div class="row-flex mt16">
          {#if plan.changes.length}<button class="btn primary" onclick={() => optimize(true)} disabled={optimizing} aria-busy={optimizing}><Icon name="check" />{t("optApply")}</button>{/if}
          {#if plan.applied}<button class="btn" onclick={() => optimize(false)} disabled={optimizing}><Icon name="undo" />{t("optUndo")}</button>{/if}
        </div>
      {:else}
        <div class="loading"><div class="blocks"></div><span class="muted">{t("loadingT")}</span></div>
      {/if}
    </section>

    <section class="panel" aria-labelledby="hc-files">
      <h3 id="hc-files" class="sec-h">{t("filesH")}</h3>
      {#if files}
        <ul class="file-list">
          {#each files as f (f.path)}
            <li class:missing={!f.exists}>
              <div class="grow"><b>{t("fileLabel")[f.label] ?? f.label}</b><span class="ltr mono">{#each f.path.split(/(?<=\/)/) as part}{part}<wbr />{/each}</span>{#if !f.exists && t("fileWhy")[f.label]}<small class="file-why">{t("fileWhy")[f.label]}</small>{/if}</div>
              <div class="file-meta"><span>{f.exists ? amount(f.size ?? 0).join(" ") : (t("fileNone")[f.label] ?? t("missing"))}</span>{#if f.exists}<span class="muted">{when(f.modified)}</span>{/if}</div>
            </li>
          {/each}
        </ul>
      {:else}
        <div class="loading"><div class="blocks"></div><span class="muted">{t("loadingT")}</span></div>
      {/if}
    </section>
  </div>
{/if}
