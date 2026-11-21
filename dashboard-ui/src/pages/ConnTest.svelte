<script>
  // The transport check between two managed servers: which transports work in which direction,
  // how fast and how steady, with the best one recommended and a tunnel one click away.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import Blocks from "../lib/Blocks.svelte";
  import NewTunnelPanel from "../lib/NewTunnelPanel.svelte";
  import MirageTest from "../lib/MirageTest.svelte";
  import PathFinder from "../lib/PathFinder.svelte";
  import CheckCustom, { presetOptions, transportsFor, tuneVariants, tuneCount } from "../lib/CheckCustom.svelte";
  import { startCheck, getCheck, stopCheck, getNewTunnel } from "../lib/api.js";
  import { say } from "../lib/actions.svelte.js";
  import { live } from "../lib/live.svelte.js";
  import { fleet, LOCAL, localName } from "../lib/servers.svelte.js";
  import { t, num, duration, list } from "../lib/i18n.svelte.js";
  import { transportLabel } from "../lib/view.js";

  const places = $derived([
    { id: LOCAL, name: t("thisServerIs", localName(live.snapshot?.host?.hostname)), address: live.snapshot?.host?.address ?? "", address6: live.snapshot?.host?.address6 ?? "", online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, address: s.snapshot?.host?.address ?? "", address6: s.snapshot?.host?.address6 ?? "", online: s.online })),
  ]);
  const placeOf = (id) => places.find((p) => p.id === id);

  let f = $state({ iran: LOCAL, foreign: "", iranIp: "", foreignIp: "", iranIpTouched: false, foreignIpTouched: false, preset: "quick", directions: "both", priority: "stability", mode: "find", tune: [], family: null });
  // Both servers' IPv6 addresses, when both have one.
  const ipv6Pair = $derived.by(() => {
    const a = placeOf(f.iran)?.address6;
    const b = placeOf(f.foreign)?.address6;
    return a && b && a !== b ? [a, b] : null;
  });
  const family = $derived(f.family ?? (ipv6Pair ? "both" : "ipv4"));
  const eligible = $derived(transportsFor(family));
  const findIpv6Picker = $derived(f.mode === "find" && family === "ipv6" && f.preset !== "custom");
  let findIpv6 = $state(presetOptions("quick").transports);
  const tuneTransports = $derived(f.tune.filter((x) => eligible.some(([n]) => n === x)));
  function toggleTransport(x) {
    const current = f.mode === "tune" ? f.tune : findIpv6;
    const next = transportsFor("ipv4").map(([n]) => n).filter((n) => n === x ? !current.includes(n) : current.includes(n));
    if (f.mode === "tune") f.tune = next;
    else findIpv6 = next;
  }
  const tuneBad = $derived(f.mode === "tune" && !tuneTransports.length);
  // Customize starts from the preset chosen last, and keeps its changes while it stays open.
  let base = $state("quick");
  let custom = $state(presetOptions("quick"));
  function pickPreset(v) {
    if (v === "custom" && f.preset !== "custom") {
      base = f.preset;
      custom = presetOptions(base);
      if (f.mode === "tune") custom.rounds = 2;
      else if (family === "ipv6") custom.transports = [...findIpv6];
    }
    f.preset = v;
  }
  function pickMode(v) {
    f.mode = v;
    if (f.preset === "custom") custom.rounds = v === "tune" ? 2 : 1;
  }
  // The transports the check would run: Find takes them from the custom panel, Tune from the page.
  const activeTransports = $derived(f.mode === "tune" ? tuneTransports : custom.transports.filter((x) => eligible.some(([n]) => n === x)));
  const customBad = $derived(f.preset === "custom" && (!activeTransports.length || (activeTransports.includes("tun") && !custom.tun_profiles.length) || (custom.pings === 0 && !custom.download && !custom.upload && !custom.parallel && custom.hold_sec === 0 && !custom.udp)));
  const routeBad = $derived(!f.foreign || f.iran === f.foreign
    || (family !== "ipv6" && (!f.iranIp.trim() || !f.foreignIp.trim()))
    || (family !== "ipv4" && !ipv6Pair));
  // Pick the first joined server once the list arrives, and follow each server's address.
  $effect(() => {
    if (!f.foreign) {
      const first = places.find((p) => p.id !== LOCAL && p.online);
      if (first) untrack(() => (f.foreign = first.id));
    }
  });
  $effect(() => {
    const iran = placeOf(f.iran)?.address ?? "";
    const foreign = placeOf(f.foreign)?.address ?? "";
    untrack(() => {
      if (!f.iranIpTouched) f.iranIp = iran;
      if (!f.foreignIpTouched) f.foreignIp = foreign;
    });
  });

  function pickEnd(field, value) {
    f[field] = value;
    const ipField = field === "iran" ? "iranIp" : "foreignIp";
    const touchedField = `${ipField}Touched`;
    f[touchedField] = false;
    f[ipField] = placeOf(value)?.address ?? "";
  }

  let state = $state(null);
  let starting = $state(false);
  let stopping = $state(false);
  let problem = $state("");
  let creatable = $state([]);

  async function poll() {
    try {
      const { status, data } = await getCheck();
      if (status === 200) state = data;
    } catch {}
  }
  $effect(() => {
    untrack(poll);
    getNewTunnel().then(({ status, data }) => {
      if (status === 200) creatable = data.transports.map((x) => x.name);
    });
    const timer = setInterval(poll, 2000);
    return () => clearInterval(timer);
  });

  const running = $derived(state?.state === "running");
  const rows = $derived(state?.view?.rows ?? state?.report?.cases ?? []);
  const done = $derived(rows.filter((r) => r.verdict).length);
  const best = $derived((state?.best ?? []).map((id) => rows.find((r) => r.spec.id === id)).filter(Boolean));
  const tuneGroups = $derived(state?.tune ?? []);
  const isTune = $derived(state?.mode === "tune");
  const caseOf = (id) => rows.find((r) => r.spec.id === id);

  async function start(addresses = null) {
    const checkFamily = addresses?.family ?? family;
    const pair6 = addresses?.ipv6Pair ?? ipv6Pair;
    if (checkFamily !== "ipv4" && !pair6) {
      problem = t("ctNeedIpv6");
      return;
    }
    starting = true;
    problem = "";
    const iranIp = (addresses?.iran ?? f.iranIp).trim();
    const foreignIp = (addresses?.foreign ?? f.foreignIp).trim();
    try {
      // A tune check takes its transports from the page; the custom panel adds measurements and rounds.
      let extra = null;
      if (f.preset === "custom") {
        extra = { ...custom };
        if (f.mode === "tune") delete extra.transports;
        else extra.transports = activeTransports;
      } else if (f.mode === "find" && checkFamily === "ipv6") {
        extra = { transports: findIpv6 };
      }
      const { status, data } = await startCheck({
        iran: f.iran, foreign: f.foreign,
        iran_ip: checkFamily === "ipv6" ? undefined : iranIp,
        foreign_ip: checkFamily === "ipv6" ? undefined : foreignIp,
        family: checkFamily,
        iran_ip6: checkFamily === "ipv4" ? undefined : pair6[0],
        foreign_ip6: checkFamily === "ipv4" ? undefined : pair6[1],
        preset: f.preset === "custom" ? base : f.preset, directions: f.directions, priority: f.priority,
        mode: f.mode, tune_transports: f.mode === "tune" ? tuneTransports : undefined, custom: extra,
      });
      if (status !== 200) problem = data?.detail ?? t("failedShort");
      else poll();
    } catch {
      problem = t("slowShort");
    } finally {
      starting = false;
    }
  }

  /** "Tune the best": the same two servers, the transports a find check ranked best, every option. */
  function tuneBest() {
    // The same pair and the same addresses the finished check used, whatever the form shows now.
    const iranIp = state?.report?.iran_ip ?? state?.view?.iran_ip ?? null;
    const foreignIp = state?.report?.foreign_ip ?? state?.view?.foreign_ip ?? null;
    const iran6 = state?.report?.iran_ip6 ?? state?.view?.iran_ip6;
    const foreign6 = state?.report?.foreign_ip6 ?? state?.view?.foreign_ip6;
    const pair6 = iran6 && foreign6 ? [iran6, foreign6] : null;
    const checkFamily = state?.report?.options?.ipv6_only ? "ipv6" : pair6 ? "both" : "ipv4";
    if (state?.iran) f.iran = state.iran;
    if (state?.foreign) f.foreign = state.foreign;
    if (checkFamily !== "ipv6") {
      if (iranIp) { f.iranIp = iranIp; f.iranIpTouched = true; }
      if (foreignIp) { f.foreignIp = foreignIp; f.foreignIpTouched = true; }
    } else {
      f.iranIpTouched = false;
      f.foreignIpTouched = false;
    }
    f.family = checkFamily;
    f.mode = "tune";
    f.tune = [...(state?.tune_best ?? [])];
    if (f.preset === "custom") custom.rounds = 2;
    start({ iran: iranIp ?? f.iranIp, foreign: foreignIp ?? f.foreignIp, family: checkFamily, ipv6Pair: pair6 });
  }

  async function stop() {
    if (stopping) return;
    stopping = true;
    try {
      const { status, data } = await stopCheck();
      if (status === 200) say(t("ctStopping"));
      else say(data?.detail ?? t("failedShort"), true);
    } catch {
      say(t("slowShort"), true);
    } finally {
      stopping = false;
    }
  }

  const VERDICT_LEVEL = { works: "ok", reachable: "ok", unstable: "warn", slow: "warn", "download-only": "warn", "upload-only": "warn" };
  const level = (v) => (v ? VERDICT_LEVEL[v] ?? (v === "skipped" || v === "stopped" ? "off" : "bad") : "off");
  const name = (r) => `${transportLabel(r.spec.transport)}${r.spec.profile ? ` ${String(r.spec.profile).toUpperCase()}` : ""}${r.spec.variant && r.spec.variant !== "plain" ? ` · ${t("variant")[r.spec.variant] ?? r.spec.variant}` : ""}${r.spec.ipv6 ? " · IPv6" : ""}${r.spec.round ? ` #${r.spec.round + 1}` : ""}`;
  // Which address family and direction worked at all ("IPv4 direct: blocked, IPv6 direct: works").
  const paths = $derived(state?.paths ?? []);
  const pathLabel = (p) => `${p.ipv6 ? "IPv6" : "IPv4"} ${p.dialer === "iran" ? t("dirDirect") : t("dirReverse")}`;
  const dialer = (r) => (r.spec.dialer === "foreign" ? t("dialForeign") : r.spec.dialer === "iran" ? t("dialIran") : t("dialBoth"));
  const topSpeed = $derived(Math.max(1, ...rows.flatMap((r) => [r.download?.mbps ?? 0, r.upload?.mbps ?? 0])));
  // Sorting and filtering of the result table: click a column to sort (again to reverse, a third
  // time to go back to the check's own order). Rows without a value always come last.
  const SORTS = [["name", "transport", ""], ["who", "ctWho", ""], ["result", "ctVerdict", ""], ["ping", "ping", ""], ["down", "downTest", "Mbit/s"], ["up", "upTest", "Mbit/s"]];
  const RANK = { ok: 0, warn: 1, bad: 2, off: 3 };
  const pingOf = (r) => r.rtt_ms ?? r.ping?.median_ms ?? null;
  const speedOf = (x) => (x?.mbps != null && !x.error ? x.mbps : null);
  const KEYS = {
    name: (r) => name(r).toLowerCase(),
    who: (r) => dialer(r),
    result: (r) => (r.verdict ? RANK[level(r.verdict)] ?? 2 : null),
    ping: pingOf,
    down: (r) => speedOf(r.download),
    up: (r) => speedOf(r.upload),
  };
  // Speeds read best-first on the first click; the rest low-first.
  const HIGH_FIRST = new Set(["down", "up"]);
  let view = $state({ sort: null, desc: false, q: "", result: "all", who: "all", transport: "" });
  function sortBy(key) {
    if (view.sort !== key) {
      view.sort = key;
      view.desc = HIGH_FIRST.has(key);
    } else if (view.desc === HIGH_FIRST.has(key)) view.desc = !view.desc;
    else view.sort = null;
  }
  function resetView() {
    view.sort = null;
    view.desc = false;
    view.q = "";
    view.result = "all";
    view.who = "all";
    view.transport = "";
  }
  const transportsShown = $derived([...new Set(rows.map((r) => r.spec.transport))]);
  const filtered = $derived(Boolean(view.q.trim() || view.result !== "all" || view.who !== "all" || view.transport));
  const shownRows = $derived.by(() => {
    const words = view.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    let found = rows.filter((r) => {
      if (view.who !== "all" && r.spec.dialer !== view.who) return false;
      if (view.transport && r.spec.transport !== view.transport) return false;
      if (view.result !== "all" && (!r.verdict || level(r.verdict) !== view.result)) return false;
      if (words.length) {
        const text = `${name(r)} ${dialer(r)} ${r.verdict ? t("verdicts")[r.verdict] ?? r.verdict : ""} ${r.note ?? ""}`.toLowerCase();
        if (!words.every((w) => text.includes(w))) return false;
      }
      return true;
    });
    if (view.sort) {
      const key = KEYS[view.sort];
      const sign = view.desc ? -1 : 1;
      found = found
        .map((r, i) => [r, key(r), i])
        .sort(([, a, i], [, b, j]) => {
          if (a == null || b == null) return a == null && b == null ? i - j : a == null ? 1 : -1;
          const c = typeof a === "string" ? a.localeCompare(b) : a - b;
          return c ? c * sign : i - j;
        })
        .map(([r]) => r);
    }
    return found;
  });
  const mbps = (x) => (x?.mbps != null && !x.error ? `${num(x.mbps)} Mbit/s` : "-");

  // A tunnel from a result: the transport, the direction and the port that worked.
  let creating = $state(false);
  let prefill = $state(null);
  function createFrom(r) {
    const direction = r.spec.dialer === "iran" ? "direct" : "reverse";
    const iranId = state?.iran ?? f.iran;
    const foreignId = state?.foreign ?? f.foreign;
    // The option the case tested goes with it.
    const variant = r.spec.variant ?? "plain";
    prefill = {
      iran: iranId, foreign: foreignId, transport: r.spec.transport, direction,
      port: r.port ? String(r.port) : undefined,
      // The address of the family the case used: an IPv6 result makes an IPv6 tunnel.
      address: r.spec.ipv6
        ? (direction === "reverse" ? state?.report?.iran_ip6 ?? state?.view?.iran_ip6 : state?.report?.foreign_ip6 ?? state?.view?.foreign_ip6)
        : (direction === "reverse" ? state?.report?.iran_ip ?? state?.view?.iran_ip : state?.report?.foreign_ip ?? state?.view?.foreign_ip),
      tls_profile: variant === "browser-tls" ? "chrome" : undefined,
      tls_fragment: variant === "tls-fragment" ? true : undefined,
      tcp_congestion: variant === "congestion" ? "cubic" : undefined,
      fec_pacer: variant === "pacer" ? true : undefined,
      parallax_mode: variant === "packet" ? "packet" : undefined,
      fromCheck: variant !== "plain" ? true : undefined,
    };
    if (variant === "game") {
      // FEC-UDP with Game mode is the GAME entry; other carriers get Game mode switched on. Game
      // UDP must reach the tunnel, and a direct tunnel needs the Iran address it was tested with.
      if (r.spec.transport === "fec-udp" && creatable.includes("game")) prefill.transport = "game";
      prefill.game = true;
      prefill.protocol = "both";
      prefill.iran_address = r.spec.ipv6
        ? state?.report?.iran_ip6 ?? state?.view?.iran_ip6
        : state?.report?.iran_ip ?? state?.view?.iran_ip;
    }
    creating = true;
  }
  // A failover tunnel from the results: the best transports that worked in the same direction,
  // each once and on the port it was tested with, best first (2 to 3 of them).
  const failoverPick = $derived.by(() => {
    const first = best[0];
    if (!first || first.spec.ipv6 || running) return [];
    const candidates = [...best, ...rows.filter(usable).sort((a, b) => (speedOf(b.download) ?? 0) - (speedOf(a.download) ?? 0))];
    const picked = [];
    for (const r of candidates) {
      if (picked.length === 3) break;
      if (!canCreate(r) || r.spec.ipv6 || r.spec.dialer !== first.spec.dialer || (r.spec.variant ?? "plain") === "game") continue;
      if (picked.some((p) => p.spec.transport === r.spec.transport || (r.port && p.port === r.port))) continue;
      picked.push(r);
    }
    return picked.length >= 2 ? picked : [];
  });
  function createFailover() {
    const first = failoverPick[0];
    createFrom(first);
    prefill = {
      iran: prefill.iran, foreign: prefill.foreign, direction: prefill.direction, address: prefill.address,
      mode: "failover",
      carriers: failoverPick.map((r) => ({ transport: r.spec.transport, port: r.port ? String(r.port) : "", touched: Boolean(r.port) })),
    };
  }
  const usable = (r) => ["works", "reachable", "slow", "unstable"].includes(r.verdict);
  // Every option a case tests can be set from the dashboard, except the raw TUN fragmentation.
  const canCreate = (r) => creatable.includes(r.spec.transport) && r.spec.variant !== "fragment" && usable(r);
  // Raw-socket, TUN and Mirage tunnels need choices on the machine itself.
  const terminalOnly = (r) => usable(r) && !canCreate(r);
</script>

<PathFinder />

{#if !running}
  <section class="panel mb16 ct-sec" aria-labelledby="ct-form">
    <div class="sec-row"><span class="ct-ico"><Icon name="conntest" /></span><h3 id="ct-form" class="sec-h grow m0">{t("ctNew")}</h3></div>
    <p class="muted small">{t("ctAbout")}</p>
    <div class="ct-route">
      <div class="ct-end">
        <span class="eyebrow"><span class="mark ok"></span>{t("iranEnd")}</span>
        <label class="sr" for="ct-iran">{t("iranEnd")}</label>
        <select id="ct-iran" class="input" value={f.iran} onchange={(e) => pickEnd("iran", e.currentTarget.value)}>{#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}</select>
        {#if family !== "ipv6"}
          <label class="flabel m0" for="ct-iip">{t("ctIranIp")}</label>
          <input id="ct-iip" class="input ltr" bind:value={f.iranIp} oninput={() => (f.iranIpTouched = true)} autocomplete="off" spellcheck="false" />
        {/if}
        {#if family !== "ipv4" && placeOf(f.iran)?.address6}<span class="muted small ltr">{placeOf(f.iran).address6}</span>{/if}
      </div>
      <div class="ct-wire link live" aria-hidden="true"><span class="wire"><i></i></span></div>
      <div class="ct-end">
        <span class="eyebrow"><span class="mark ok"></span>{t("foreignEnd")}</span>
        <label class="sr" for="ct-foreign">{t("foreignEnd")}</label>
        <select id="ct-foreign" class="input" value={f.foreign} onchange={(e) => pickEnd("foreign", e.currentTarget.value)}>{#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}</select>
        {#if family !== "ipv6"}
          <label class="flabel m0" for="ct-fip">{t("ctForeignIp")}</label>
          <input id="ct-fip" class="input ltr" bind:value={f.foreignIp} oninput={() => (f.foreignIpTouched = true)} autocomplete="off" spellcheck="false" />
        {/if}
        {#if family !== "ipv4" && placeOf(f.foreign)?.address6}<span class="muted small ltr">{placeOf(f.foreign).address6}</span>{/if}
      </div>
    </div>
    <div class="ct-form-group">
      <span class="ct-form-label" id="ct-mode-l">{t("ctMode")}</span>
      <div class="ct-list" role="group" aria-labelledby="ct-mode-l">
        {#each [["find", "ctFind"], ["tune", "ctTune"]] as [v, k]}<button type="button" aria-pressed={f.mode === v} onclick={() => pickMode(v)}>{t(k)}</button>{/each}
      </div>
      <p class="ct-mode-help muted m0 mt8">{t(f.mode === "tune" ? "ctTuneHelp" : "ctFindHelp")}</p>
    </div>
    <div class="ct-form-group">
      <label class="ct-form-label" for="ct-family">{t("ctFamily")}</label>
      <select id="ct-family" class="input ct-family" value={family} onchange={(e) => (f.family = e.currentTarget.value)}>
        <option value="ipv4">IPv4</option>
        <option value="ipv6">IPv6</option>
        <option value="both">IPv4 + IPv6</option>
      </select>
      {#if family !== "ipv4" && !ipv6Pair}<p class="small bad-t m0 mt8" role="status">{t("ctNeedIpv6")}</p>{/if}
    </div>
    {#if f.mode === "tune" || findIpv6Picker}
      {@const selected = f.mode === "tune" ? tuneTransports : findIpv6}
      <div class="ct-form-group">
        <span class="ct-form-label" id="ct-tune-l">{t(family === "ipv6" ? "ntOverIpv6" : "ctTuneWhich")}</span>
        <div class="cc-grid ct-tune" role="group" aria-labelledby="ct-tune-l">
          {#each eligible as [x, note] (x)}
            <label class="chk cc-chk" class:on={selected.includes(x)} title={note ? t(note) : ""}>
              <input type="checkbox" checked={selected.includes(x)} onchange={() => toggleTransport(x)} />
              <span class="ltr">{transportLabel(x)}</span>
              {#if f.mode === "tune"}<span class="muted small ct-tune-v">{tuneVariants(x).length ? `+${tuneVariants(x).length}` : ""}</span>{/if}
            </label>
          {/each}
        </div>
        {#if f.mode === "tune" && tuneTransports.length}
          <p class="muted small m0 mt8 ltr edesc">{tuneTransports.map((x) => `${transportLabel(x)}: ${[t("ctDefaultOpt"), ...tuneVariants(x).map((v) => t("variant")[v] ?? v)].join(", ")}`).join(" · ")}</p>
          <p class="muted small m0">{t("ccCases", num(tuneCount(tuneTransports, f.preset === "custom" ? custom : { tun_profiles: custom.tun_profiles, rounds: 2 }, f.directions === "both" ? 2 : 1, family)))}</p>
        {:else if !selected.length}<p class="small bad-t m0 mt8">{t(f.mode === "tune" ? "ctTuneNone" : "ccNoTransport")}</p>{/if}
      </div>
    {/if}
    <div class="ct-form-group ct-opts">
      {#each [["ct-preset", "ctPreset", "preset", [["quick", "ctQuick"], ["standard", "ctStandard"], ["thorough", "ctThorough"], ["custom", "ctCustom"]]], ["ct-dir", "ctDirections", "directions", [["both", "ctBoth"], ["foreign", "dirReverse"], ["iran", "dirDirect"]]], ["ct-pri", "ctPriority", "priority", [["stability", "ctStability"], ["speed", "ctSpeed"], ["hiding", "ctHiding"], ["lossy", "ctLossy"]]]] as [id, label, field, opts] (id)}
        <div>
          <span class="ct-form-label" id="{id}-l">{t(label)}</span>
          <div class="ct-list" role="group" aria-labelledby="{id}-l">
            {#each opts as [v, k]}<button type="button" aria-pressed={f[field] === v} onclick={() => (field === "preset" ? pickPreset(v) : (f[field] = v))}>{t(k)}</button>{/each}
          </div>
        </div>
      {/each}
    </div>
    {#if f.preset === "custom"}
      <div class="ct-custom mt16">
        <CheckCustom bind:value={custom} dirs={f.directions === "both" ? 2 : 1} tune={f.mode === "tune"} tuned={tuneTransports} {family} />
      </div>
    {/if}
    <p class="muted small mt12 m0">{t("ctPortsNote")}</p>
    {#if places.length < 2}<div class="note warn mt12" role="note"><Icon name="warn" /><span>{t("needAgent")}</span></div>{/if}
    {#if problem}<div class="note bad mt12" role="alert"><Icon name="warn" /><span>{t("ctFailed")} <span class="ltr">{problem}</span></span></div>{/if}
    <div class="row-flex mt16">
      <button class="btn primary ct-go" onclick={() => start()} disabled={starting || routeBad || customBad || tuneBad || (findIpv6Picker && !findIpv6.length)} aria-busy={starting}>
        <Icon name="conntest" />{starting ? t("ctStarting") : t("ctStart")}
      </button>
    </div>
  </section>
{/if}

{#if state && state.state !== "idle"}
  <section class="panel" aria-labelledby="ct-res">
    <div class="row-flex mb16">
      <h3 id="ct-res" class="sec-h grow m0">{running ? t("ctRunning") : state.state === "failed" ? t("ctEndedBad") : t("ctResults")}</h3>
      {#if running}<button class="btn danger" onclick={stop} disabled={stopping} aria-busy={stopping}><Icon name="stop" />{t("stop")}</button>{/if}
    </div>
    {#if running}
      <div class="ct-progress" role="status">
        <Blocks value={rows.length ? (done / rows.length) * 100 : 0} cls="big" />
        <span class="muted small">{state.view?.step} · {t("ctDone", num(done), num(rows.length))}{state.view?.remaining_sec ? ` · ${t("ctLeft", duration(state.view.remaining_sec))}` : ""}</span>
      </div>
    {/if}
    {#if paths.length}
      <div class="ct-paths mb16" role="status">
        {#each paths as p (`${p.ipv6}-${p.dialer}`)}<span class="pill {p.works ? 'ok' : 'bad'}">{pathLabel(p)}: {p.works ? t("ctPathWorks") : t("ctPathBlocked")}</span>{/each}
      </div>
    {/if}
    {#if running && state.view?.path_hint && !state.view?.connected}<div class="note warn mb16" role="note"><Icon name="warn" /><span class="ltr edesc">{state.view.path_hint}</span></div>{/if}
    {#if state.state === "failed"}<div class="note bad mb16" role="alert"><Icon name="warn" /><span>{state.error}</span></div>{/if}
    {#if state.report?.stopped}<div class="note warn mb16" role="note"><Icon name="warn" /><span>{t("ctStopped")} {state.report.stopped}</span></div>{/if}

    {#if !running && isTune && tuneGroups.length}
      <div class="ct-tune-res mb16">
        <div class="row-flex"><h4 class="m0 grow">{t("ctTuneRes")}</h4><span class="muted small">{t("ctTuneSub", num(state?.report?.options?.rounds ?? 2))}</span></div>
        {#if tuneGroups.every((g) => !g.rows[0].usable)}<div class="note warn mt8" role="note"><Icon name="warn" /><span>{t("ctNoTune")}</span></div>{/if}
        <div class="table-wrap mt8">
          <table class="speed ct-table">
            <thead><tr><th scope="col">{t("ctOption")}</th><th scope="col">{t("ctWho")}</th><th scope="col">{t("ctWorks")}</th><th scope="col">{t("downTest")} <span class="muted">Mbit/s</span></th><th scope="col">{t("upTest")} <span class="muted">Mbit/s</span></th><th scope="col">{t("ping")}</th><th scope="col">{t("ctLoss")}</th><th scope="col"><span class="sr">{t("actionsOf")}</span></th></tr></thead>
            {#each tuneGroups as g (`${g.transport}-${g.profile ?? ""}-${!!g.ipv6}`)}
              <tbody>
                <tr class="ct-group"><th scope="rowgroup" colspan="8"><span class="ltr">{transportLabel(g.transport)}{g.profile ? ` ${String(g.profile).toUpperCase()}` : ""}{g.ipv6 ? " · IPv6" : ""}</span></th></tr>
                {#each g.rows as row, i (`${row.variant}-${row.dialer}`)}
                  {@const c = row.case_id != null ? caseOf(row.case_id) : null}
                  <tr class:ct-best={i === 0 && row.usable > 0} class:ct-dead={!row.usable}>
                    <td>{#if i === 0 && row.usable > 0}<Icon name="check" />{/if} {row.variant === "plain" ? t("ctDefaultOpt") : t("variant")[row.variant] ?? row.variant}</td>
                    <td>{row.dialer === "foreign" ? t("dialForeign") : row.dialer === "iran" ? t("dialIran") : t("dialBoth")}</td>
                    <td class="num">{num(row.usable)}/{num(row.rounds)}</td>
                    <td class="num">{row.down_mbps != null ? num(Math.round(row.down_mbps)) : row.up_mbps == null && row.parallel_mbps != null ? `${num(Math.round(row.parallel_mbps))} ∥` : "-"}</td>
                    <td class="num">{row.up_mbps != null ? num(Math.round(row.up_mbps)) : "-"}</td>
                    <td class="num">{row.ping_ms != null ? `${num(Math.round(row.ping_ms))} ms` : "-"}</td>
                    <td class="num">{row.udp_loss != null ? `${num(Math.round(row.udp_loss))}%` : "-"}</td>
                    <td>{#if c && canCreate(c)}<button class="btn {i === 0 ? 'primary' : 'ghost'}" onclick={() => createFrom(c)}>{t("ctCreateShort")}</button>{:else if c && terminalOnly(c)}<span class="muted small ct-term" title={t("ctTerminalOnly", name(c))}>{t("ctTerminalShort")}</span>{/if}</td>
                  </tr>
                {/each}
              </tbody>
            {/each}
          </table>
        </div>
      </div>
    {:else if !running && best.length}
      <div class="note info act mb16" role="note">
        <Icon name="check" />
        <div class="grow">
          <b>{t("ctBest", name(best[0]), dialer(best[0]))}</b>
          {#if best.length > 1}<div class="small">{t("ctAlso")} {list(best.slice(1, 4).map((r) => `${name(r)} (${dialer(r)})`))}</div>{/if}
        </div>
        {#if canCreate(best[0])}<button class="btn primary" onclick={() => createFrom(best[0])}><Icon name="plus" />{t("ctCreate")}</button>{/if}
      </div>
      {#if failoverPick.length}
        <div class="row-flex mb16 ct-tunebest">
          <button class="btn" onclick={createFailover}><Icon name="plus" />{t("ctFailover", list(failoverPick.map((r) => transportLabel(r.spec.transport))))}</button>
          <span class="muted small">{t("ctFailoverHelp")}</span>
        </div>
      {/if}
      {#if terminalOnly(best[0])}<p class="muted small mt-n8 mb16">{t("ctTerminalOnly", name(best[0]))}</p>{/if}
      {#if state?.mode !== "tune" && state?.tune_best?.length}
        <div class="row-flex mb16 ct-tunebest">
          <button class="btn" onclick={tuneBest} disabled={starting || !state.iran && !f.foreign} aria-busy={starting}><Icon name="conntest" />{t("ctTuneBest", list(state.tune_best.map((x) => transportLabel(x))))}</button>
          <span class="muted small">{t("ctTuneBestHelp")}</span>
        </div>
      {/if}
    {:else if !running && state.state === "finished"}
      <div class="note warn mb16" role="note"><Icon name="warn" /><span>{t("ctNone")}</span></div>
    {/if}

    {#if isTune && !running}
      <details class="ct-all">
        <summary><span class="flabel m0">{t("ctAllCases", num(rows.length))}</span></summary>
    {@render caseTable()}
      </details>
    {:else}
    {@render caseTable()}
    {/if}
    <p class="muted small m0 mt12">{t("ctLegend")}</p>
    {#snippet caseTable()}
      <div class="ct-filters" role="group" aria-label={t("ctFilter")}>
        <label class="sr" for="ct-q">{t("ctSearch")}</label>
        <input id="ct-q" class="input ct-q" type="search" placeholder={t("ctSearch")} bind:value={view.q} />
        <div class="seg" role="group" aria-label={t("ctVerdict")}>
          {#each [["all", "ctAll"], ["ok", "ctOnlyOk"], ["warn", "ctOnlyWarn"], ["bad", "ctOnlyBad"]] as [v, k]}<button type="button" aria-pressed={view.result === v} onclick={() => (view.result = v)}>{t(k)}</button>{/each}
        </div>
        <div class="seg" role="group" aria-label={t("ctWho")}>
          {#each [["all", "ctAll"], ["foreign", "dialForeign"], ["iran", "dialIran"]] as [v, k]}<button type="button" aria-pressed={view.who === v} onclick={() => (view.who = v)}>{t(k)}</button>{/each}
        </div>
        {#if transportsShown.length > 1}
          <label class="sr" for="ct-tr">{t("transport")}</label>
          <select id="ct-tr" class="input ct-tr" bind:value={view.transport}>
            <option value="">{t("ctAllTransports")}</option>
            {#each transportsShown as x (x)}<option value={x}>{transportLabel(x)}</option>{/each}
          </select>
        {/if}
        <span class="muted small ct-count" aria-live="polite">{t("ctShown", num(shownRows.length), num(rows.length))}</span>
        {#if filtered || view.sort}<button type="button" class="btn ghost sm" onclick={resetView}>{t("ctReset")}</button>{/if}
      </div>
      <div class="table-wrap">
        <table class="speed ct-table">
          <thead>
            <tr>
              {#each SORTS as [key, label, unit] (key)}
                <th scope="col" aria-sort={view.sort === key ? (view.desc ? "descending" : "ascending") : "none"}>
                  <button type="button" class="th-sort" class:on={view.sort === key} onclick={() => sortBy(key)}>{t(label)}{#if unit} <span class="muted">{unit}</span>{/if}<span class="th-arrow" aria-hidden="true">{view.sort === key ? (view.desc ? "↓" : "↑") : "↕"}</span></button>
                </th>
              {/each}
              <th scope="col"><span class="sr">{t("actionsOf")}</span></th>
            </tr>
          </thead>
          <tbody>
            {#each shownRows as r (r.spec.id)}
              <tr class:current={running && state.view?.current === r.spec.id}>
                <th scope="row"><span class="ltr">{name(r)}</span></th>
                <td>{dialer(r)}</td>
                <td>
                  <span class="pill {running && state.view?.current === r.spec.id && !r.verdict ? 'live' : level(r.verdict)}">{r.verdict ? t("verdicts")[r.verdict] ?? r.verdict : running && state.view?.current === r.spec.id ? t("testing") : t("ctWaiting")}</span>
                  {#if r.note}<div class="muted small ltr edesc">{r.note}</div>{/if}
                </td>
                <td>{r.rtt_ms != null ? `${num(r.rtt_ms)} ms` : r.ping?.median_ms != null ? `${num(r.ping.median_ms)} ms` : r.handshake_ms != null ? `${num(r.handshake_ms)} ms*` : "-"}</td>
                <td>{@render speed(r.download)}</td>
                <td>{@render speed(r.upload)}</td>
                <td>{#if !running && canCreate(r)}<button class="btn ghost" onclick={() => createFrom(r)}>{t("ctCreateShort")}</button>{:else if !running && terminalOnly(r)}<span class="muted small ct-term" title={t("ctTerminalOnly", name(r))}>{t("ctTerminalShort")}</span>{/if}</td>
              </tr>
            {:else}
              <tr><td colspan="7" class="muted">{t("ctNoMatch")}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/snippet}
    {#snippet speed(x)}
      {#if x?.mbps != null && !x.error}
        <div class="ct-speed"><span class="num">{num(x.mbps)}</span><svg viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true"><rect class="t" width="100" height="4" rx="2" /><rect class="f" width={Math.max(2, (x.mbps / topSpeed) * 100)} height="4" rx="2" /></svg></div>
      {:else}<span class="muted">-</span>{/if}
    {/snippet}
  </section>
{/if}

<MirageTest />

<NewTunnelPanel open={creating} {prefill} onclose={() => (creating = false)} />
