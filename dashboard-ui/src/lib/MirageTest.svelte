<script>
  // Mirage source tests between two managed servers: which permitted spoof source addresses
  // get through, with which packet types, in each direction.
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import { startMirage, getMirage, stopMirage } from "./api.js";
  import { say } from "./actions.svelte.js";
  import { live } from "./live.svelte.js";
  import { fleet, LOCAL, localName } from "./servers.svelte.js";
  import { t, num, pct } from "./i18n.svelte.js";
  import { copyText, saveFile, csvLine, stamp } from "./share.js";

  // The backend's list (it arrives with the status); this one matches it until then.
  const FALLBACK_PROFILES = ["udp", "icmp", "tcp", "icmpv6", "gre", "ipip", "bip"];
  const PROFILES = $derived(Array.isArray(state?.profiles) && state.profiles.length ? state.profiles : FALLBACK_PROFILES);
  const places = $derived([
    { id: LOCAL, name: t("thisServerIs", localName(live.snapshot?.host?.hostname)), address: live.snapshot?.host?.address ?? "", address6: live.snapshot?.host?.address6 ?? "", online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, address: s.snapshot?.host?.address ?? "", address6: s.snapshot?.host?.address6 ?? "", online: s.online })),
  ]);
  const placeOf = (id) => places.find((p) => p.id === id);
  let f = $state({ iran: LOCAL, foreign: "", sources: "", reverse: "real", profiles: ["udp", "icmp"], depth: "quick" });
  $effect(() => {
    if (!f.foreign) {
      const first = places.find((p) => p.id !== LOCAL && p.online);
      if (first) untrack(() => (f.foreign = first.id));
    }
  });

  let state = $state(null);
  let starting = $state(false);
  let stopping = $state(false);
  let problem = $state("");
  async function poll() {
    try {
      const { status, data } = await getMirage();
      if (status === 200) state = data;
    } catch {}
  }
  $effect(() => {
    untrack(poll);
    const timer = setInterval(poll, 3000);
    return () => clearInterval(timer);
  });

  async function start() {
    starting = true;
    problem = "";
    try {
      const { status, data } = await startMirage({
        iran: f.iran, foreign: f.foreign, iran_ip: placeOf(f.iran)?.address, foreign_ip: placeOf(f.foreign)?.address,
        foreign_sources: f.sources, iran_sources: f.reverse.trim(), profiles: f.profiles, depth: f.depth,
      });
      if (status !== 200) problem = data?.detail ?? t("failedShort");
      else poll();
    } catch {
      problem = t("slowShort");
    } finally {
      starting = false;
    }
  }

  async function stop() {
    if (stopping) return;
    stopping = true;
    try {
      const { status, data } = await stopMirage();
      if (status === 200) say(t("ctStopping"));
      else say(data?.detail ?? t("failedShort"), true);
    } catch {
      say(t("slowShort"), true);
    } finally {
      stopping = false;
    }
  }

  const running = $derived(state?.state === "running");
  const result = (r) => (r.error ? t("mgError") : r.received === 0 ? t("mgNone") : r.received < r.sent ? t("mgLossy") : t("mgPassed"));
  const level = (r) => (r.error || r.received === 0 ? "bad" : r.received < r.sent ? "warn" : "ok");
  // Results: filters, copying and export.
  let view = $state({ result: "all", toward: "all", type: "all", q: "", sort: "source" });
  const rows = $derived(state?.rows ?? []);
  const outcome = (r) => (r.error || r.received === 0 ? "failed" : r.received < r.sent ? "lossy" : "passed");
  const types = $derived([...new Set(rows.map((r) => String(r.profile)))]);
  const counts = $derived({
    passed: rows.filter((r) => outcome(r) === "passed").length,
    lossy: rows.filter((r) => outcome(r) === "lossy").length,
    failed: rows.filter((r) => outcome(r) === "failed").length,
  });
  const ipKey = (ip) => String(ip).split(/[.:]/).map((n) => n.padStart(5, "0")).join(".");
  const shown = $derived.by(() => {
    const q = view.q.trim();
    const list = rows.filter((r) =>
      (view.result === "all" || outcome(r) === view.result) &&
      (view.toward === "all" || r.toward === view.toward) &&
      (view.type === "all" || String(r.profile) === view.type) &&
      (!q || String(r.source).includes(q)));
    if (view.sort === "ping") return [...list].sort((a, b) => (a.rtt_ms ?? 1e9) - (b.rtt_ms ?? 1e9));
    if (view.sort === "loss") return [...list].sort((a, b) => (a.loss ?? 100) - (b.loss ?? 100));
    return [...list].sort((a, b) => ipKey(a.source).localeCompare(ipKey(b.source)));
  });
  const filtered = $derived(view.result !== "all" || view.toward !== "all" || view.type !== "all" || view.q.trim() !== "");
  const shownIps = $derived([...new Set(shown.map((r) => r.source))]);
  // Sources that passed with every type tried in their direction: ready to paste into a tunnel.
  const cleanIps = $derived.by(() => {
    const bad = new Set(rows.filter((r) => outcome(r) !== "passed").map((r) => `${r.toward} ${r.source}`));
    return [...new Set(rows.filter((r) => outcome(r) === "passed" && !bad.has(`${r.toward} ${r.source}`)).map((r) => r.source))];
  });
  function exportCsv() {
    const head = csvLine(["source", "type", "toward", "sent", "received", "loss_pct", "ping_ms", "result", "error"]);
    const body = shown.map((r) => csvLine([r.source, r.profile, r.toward, r.sent, r.received, r.loss ?? "", r.rtt_ms ?? "", outcome(r), r.error ?? ""]));
    saveFile(`mirage-${stamp()}.csv`, [head, ...body].join("\n") + "\n", "text/csv");
  }
  function exportJson() {
    saveFile(`mirage-${stamp()}.json`, JSON.stringify(shown.map((r) => ({ ...r, result: outcome(r) })), null, 2), "application/json");
  }

  const toggle = (p) => (f.profiles = f.profiles.includes(p) ? f.profiles.filter((x) => x !== p) : [...f.profiles, p]);
</script>

<section class="panel mt16 ct-sec" aria-labelledby="mg-h">
  <div class="sec-row">
    <span class="ct-ico"><Icon name="lock" /></span>
    <h3 id="mg-h" class="sec-h grow m0">{t("mgH")}</h3>
    {#if running}<button class="btn danger" onclick={stop} disabled={stopping} aria-busy={stopping}><Icon name="stop" />{t("stop")}</button>{/if}
  </div>
  <p class="muted small">{t("mgAbout")}</p>
  {#if !running}
    <div class="ct-route">
      <div class="ct-end">
        <span class="eyebrow"><span class="mark ok"></span>{t("iranEnd")}</span>
        <label class="sr" for="mg-iran">{t("iranEnd")}</label>
        <select id="mg-iran" class="input" bind:value={f.iran}>{#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}</select>
        <label class="flabel m0" for="mg-rev">{t("mgReverse")}</label>
        <input id="mg-rev" class="input ltr" bind:value={f.reverse} spellcheck="false" />
        <p class="muted small m0">{t("mgReverseHelp")}</p>
      </div>
      <div class="ct-wire link warn" aria-hidden="true"><span class="wire"><i></i></span></div>
      <div class="ct-end">
        <span class="eyebrow"><span class="mark ok"></span>{t("foreignEnd")}</span>
        <label class="sr" for="mg-foreign">{t("foreignEnd")}</label>
        <select id="mg-foreign" class="input" bind:value={f.foreign}>{#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}</select>
        <label class="flabel m0" for="mg-src">{t("mgSources")}</label>
        <textarea id="mg-src" class="input ltr mg-area" bind:value={f.sources} placeholder="198.51.100.10, 198.51.100.11" spellcheck="false"></textarea>
        <p class="muted small m0">{t("mgSourcesHelp")}</p>
      </div>
    </div>
    <div class="mg-opts">
      <fieldset class="mg-types">
        <legend class="flabel">{t("mgTypes")}</legend>
        {#each PROFILES as p}<label class="chk"><input type="checkbox" checked={f.profiles.includes(p)} onchange={() => toggle(p)} /><span class="ltr">{p.toUpperCase()}</span></label>{/each}
      </fieldset>
      <div>
        <span class="flabel" id="mg-depth-l">{t("ctPreset")}</span>
        <div class="ct-list" role="group" aria-labelledby="mg-depth-l">
          {#each [["quick", "mgQuick"], ["extended", "mgExtended"]] as [v, k]}<button type="button" aria-pressed={f.depth === v} onclick={() => (f.depth = v)}>{t(k)}</button>{/each}
        </div>
      </div>
    </div>
    <div class="note warn mt16" role="note"><Icon name="warn" /><span>{t("mgPermitted")}</span></div>
    {#if problem}<div class="note bad mt12" role="alert"><Icon name="warn" /><span class="ltr">{problem}</span></div>{/if}
    <div class="row-flex mt16">
      <button class="btn primary ct-go" onclick={start} disabled={starting || !f.foreign || f.iran === f.foreign || !f.sources.trim() || !f.profiles.length} aria-busy={starting}><Icon name="play" />{starting ? t("ctStarting") : t("mgStart")}</button>
    </div>
  {/if}
  {#if state && state.state !== "idle"}
    <p class="small mt16 mg-status" role="status">
      <span class="pill {running ? 'live' : state.state === 'failed' ? 'bad' : 'ok'}">{running ? t("mgRunning", num(state.rows?.length ?? 0)) : state.state === "failed" ? t("ctEndedBad") : t("ctResults")}</span>
      {#if state.state === "failed" && state.error}<span class="muted ltr">{state.error}</span>{/if}
    </p>
    {#if rows.length}
      <div class="mg-sum" role="group" aria-label={t("ctVerdict")}>
        <button type="button" class="mg-count" aria-pressed={view.result === "all"} onclick={() => (view.result = "all")}><b class="num">{num(rows.length)}</b><span>{t("mgAll")}</span></button>
        <button type="button" class="mg-count" aria-pressed={view.result === "passed"} onclick={() => (view.result = "passed")}><span class="mark ok"></span><b class="num">{num(counts.passed)}</b><span>{t("mgPassed")}</span></button>
        <button type="button" class="mg-count" aria-pressed={view.result === "lossy"} onclick={() => (view.result = "lossy")}><span class="mark warn"></span><b class="num">{num(counts.lossy)}</b><span>{t("mgLossy")}</span></button>
        <button type="button" class="mg-count" aria-pressed={view.result === "failed"} onclick={() => (view.result = "failed")}><span class="mark bad"></span><b class="num">{num(counts.failed)}</b><span>{t("mgFailedN")}</span></button>
      </div>
      <div class="mg-tools">
        <label class="mg-search"><Icon name="search" /><span class="sr">{t("mgSearch")}</span><input dir={view.q ? "ltr" : null} bind:value={view.q} placeholder={t("mgSearch")} spellcheck="false" autocomplete="off" /></label>
        <label class="picker"><span>{t("mgType")}</span><select bind:value={view.type}><option value="all">{t("mgAll")}</option>{#each types as ty}<option value={ty}>{ty.toUpperCase()}</option>{/each}</select></label>
        <label class="picker"><span>{t("mgToward")}</span><select bind:value={view.toward}><option value="all">{t("mgAll")}</option><option value="iran">{t("iranEnd")}</option><option value="foreign">{t("foreignEnd")}</option></select></label>
        <label class="picker"><span>{t("mgSort")}</span><select bind:value={view.sort}><option value="source">{t("mgSource")}</option><option value="ping">{t("ping")}</option><option value="loss">{t("loss")}</option></select></label>
        {#if filtered}<button type="button" class="btn ghost" onclick={() => (view = { ...view, result: "all", toward: "all", type: "all", q: "" })}><Icon name="x" />{t("mgClear")}</button>{/if}
      </div>
      <div class="mg-actions">
        <span class="muted small grow">{t("mgShowing", num(shown.length), num(rows.length))}</span>
        <button type="button" class="btn" onclick={() => copyText(cleanIps.join("\n"), t("mgIpsN", num(cleanIps.length)))} disabled={!cleanIps.length} title={t("mgCleanHelp")}><Icon name="check" />{t("mgCopyClean", num(cleanIps.length))}</button>
        <button type="button" class="btn" onclick={() => copyText(shownIps.join("\n"), t("mgIpsN", num(shownIps.length)))} disabled={!shownIps.length}><Icon name="copy" />{t("mgCopyShown", num(shownIps.length))}</button>
        <button type="button" class="btn" onclick={exportCsv} disabled={!shown.length}><Icon name="download" />CSV</button>
        <button type="button" class="btn" onclick={exportJson} disabled={!shown.length}><Icon name="download" />JSON</button>
      </div>
      <div class="table-wrap">
        <table class="speed ct-table">
          <thead><tr><th scope="col">{t("mgSource")}</th><th scope="col">{t("mgType")}</th><th scope="col">{t("mgToward")}</th><th scope="col">{t("mgGot")}</th><th scope="col">{t("ping")}</th><th scope="col">{t("ctVerdict")}</th></tr></thead>
          <tbody>
            {#each shown as r, i (r.toward + r.source + r.profile + i)}
              <tr>
                <th scope="row" class="mono"><span class="mg-ip"><span class="ltr">{r.source}</span><button type="button" class="btn ghost icon mg-copy" onclick={() => copyText(r.source, r.source)} title={t("copy")} aria-label="{t('copy')} {r.source}"><Icon name="copy" /></button></span></th>
                <td><span class="code-chip ltr">{String(r.profile).toUpperCase()}</span></td>
                <td>{r.toward === "iran" ? t("iranEnd") : t("foreignEnd")}</td>
                <td>
                  <div class="ct-speed"><span class="num">{num(r.received)} / {num(r.sent)} <span class="muted">· {pct(r.loss ?? 0)} {t("loss")}</span></span><svg viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true"><rect class="t" width="100" height="4" rx="2" /><rect class="f" width={r.sent ? Math.max(2, (r.received / r.sent) * 100) : 0} height="4" rx="2" /></svg></div>
                </td>
                <td>{r.rtt_ms != null ? `${num(r.rtt_ms)} ms` : "-"}</td>
                <td><span class="pill {level(r)}">{result(r)}</span>{#if r.error}<div class="muted small ltr edesc">{r.error}</div>{/if}</td>
              </tr>
            {:else}
              <tr><td colspan="6" class="muted">{t("mgNoMatch")}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</section>
