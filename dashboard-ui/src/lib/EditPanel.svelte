<script>
  // Changing a saved tunnel: its forwarded ports, its traffic limit, its restart schedule and its
  // advanced numbers. Each choice is a direct control (chips, segments, a switch, presets), and the
  // footer shows what will change before anything is saved. Saving restarts the tunnel; if it does
  // not stay up, the server puts the previous settings back.
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import { getEditable, saveEdit, undoEdit } from "./api.js";
  import { pending, pendingKey, say } from "./actions.svelte.js";
  import { t, num } from "./i18n.svelte.js";
  import { live } from "./live.svelte.js";
  import { fleet } from "./servers.svelte.js";
  import { usedPorts, randomPort } from "./view.js";

  let { name = "", server = "local", onclose } = $props();
  let dialog = $state();
  let openGeneration = 0;
  let controller;

  /** "loading" | "ready" | "error" */
  let phase = $state("loading");
  let loadError = $state("");
  let screen = $state(null);
  let form = $state({ ports: "", protocol: "tcp", proxy: "0", limit: "0", days: "30", restart: "0", values: {} });
  /** The problem shown in the dialog after a save: { text, detail }. */
  let problem = $state(null);
  let askUndo = $state(false);
  let showReview = $state(false);
  let draft = $state("");
  let draftError = $state("");
  let lastAdded = $state("");
  let limitOn = $state(false);
  let lastLimit = "100";
  let customRestart = $state(false);
  let find = $state("");
  /** The preset whose values were put into the form, until it is saved or discarded. */
  let chosen = $state(null);
  let draftInput = $state();

  const key = $derived(pendingKey(name, server));
  const working = $derived(pending[key] === "edit" || pending[key] === "undo");
  const settingKey = (s) => `${s.place}:${s.name}`;
  const RESTARTS = ["0", "6", "12", "24"];
  const GB = ["100", "500", "1000"];
  const DAYS = ["7", "30"];

  $effect(() => {
    const n = name;
    const s = server;
    if (n && dialog) {
      if (!dialog.open) dialog.showModal();
      untrack(() => open(n, s));
    }
    if (!n && dialog?.open) dialog.close();
    return () => {
      openGeneration++;
      controller?.abort();
    };
  });

  async function open(n, s) {
    const generation = ++openGeneration;
    controller?.abort();
    controller = new AbortController();
    const signal = controller.signal;
    phase = "loading";
    loadError = "";
    problem = null;
    askUndo = false;
    showReview = false;
    find = "";
    try {
      const { status, data } = await getEditable(n, s, signal);
      if (signal.aborted || generation !== openGeneration || !dialog?.open || n !== name || s !== server) return;
      if (status !== 200) throw new Error(data?.detail ?? "");
      screen = data;
      fill();
      phase = "ready";
    } catch (error) {
      if (signal.aborted || generation !== openGeneration || !dialog?.open || n !== name || s !== server) return;
      loadError = error.message;
      phase = "error";
    }
  }

  /** Puts the saved settings into the form (also what Discard does). */
  function fill() {
    const data = screen;
    const values = {};
    for (const s of data.settings) values[settingKey(s)] = s.value == null ? "" : String(s.value);
    form = {
      ports: split(data.ports?.text ?? "").join(", "),
      protocol: data.ports?.protocol ?? "tcp",
      proxy: String(data.ports?.proxy_protocol ?? 0),
      restart: String(data.restart_hours ?? 0),
      limit: String(data.quota.limit_gb),
      days: String(data.quota.period_days),
      values,
      carrier: { ...(data.carrier ?? {}), pool: data.carrier?.pool == null ? null : String(data.carrier.pool), game: data.carrier?.game ? { ...data.carrier.game } : null },
    };
    limitOn = data.quota.limit_gb > 0;
    if (limitOn) lastLimit = String(data.quota.limit_gb);
    customRestart = !RESTARTS.includes(form.restart);
    draft = "";
    draftError = "";
    lastAdded = "";
    problem = null;
    chosen = null;
  }

  /** Puts a preset's values into the form; nothing is saved until Save. */
  function pickPreset(p) {
    for (const c of p.changes) form.values[`${c.place}:${c.name}`] = c.to == null ? "" : String(c.to);
    if (p.pool != null && form.carrier?.pool != null) form.carrier.pool = String(p.pool);
    chosen = p.id;
  }
  const presetName = (p) => t("presetNames")[p.id] ?? p.label;
  const presetText = (p) => t("presetTexts")[p.id] ?? p.description;
  const presetCount = (p) => p.changes.length + (p.pool != null && p.pool !== screen?.carrier?.pool ? 1 : 0);

  /** Text with Persian or Arabic digits (and separators) written as plain digits. */
  const plain = (text) =>
    String(text ?? "")
      .trim()
      .replace(/[۰-۹]/g, (d) => d.charCodeAt(0) - 0x06f0)
      .replace(/[٠-٩]/g, (d) => d.charCodeAt(0) - 0x0660)
      .replace(/،/g, ",");
  const whole = (text) => /^\d+$/.test(plain(text));
  const split = (text) => plain(text).split(/[,\s]+/).map((p) => p.replace(/\s+/g, "")).filter(Boolean);

  // Ports, as removable chips over the same comma list the server reads.
  const chips = $derived(split(form.ports));

  function portOk(p) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(p);
    if (!m) return false;
    const a = +m[1];
    const b = m[2] == null ? a : +m[2];
    return a >= 1 && b <= 65535 && a <= b;
  }

  /** Adds a random port no tunnel on a known server uses yet. */
  function addRandom() {
    const used = usedPorts([live.snapshot, ...fleet.list.map((s) => s.snapshot)]);
    for (const c of chips) for (const n of c.match(/\d+/g) ?? []) used.add(+n);
    draft = String(randomPort(used));
    addDraft();
  }

  /** Adds what is typed; several ports at once (a paste) also work. Returns false on a bad entry. */
  function addDraft() {
    const items = split(draft);
    if (!items.length) return true;
    const bad = items.find((p) => !portOk(p));
    if (bad) {
      draftError = t("portBad");
      return false;
    }
    const fresh = [...new Set(items.filter((p) => !chips.includes(p)))];
    if (!fresh.length) {
      draftError = t("portDup");
      return false;
    }
    form.ports = [...chips, ...fresh].join(", ");
    lastAdded = fresh[fresh.length - 1];
    draft = "";
    draftError = "";
    return true;
  }

  function removePort(p) {
    form.ports = chips.filter((c) => c !== p).join(", ");
    draftInput?.focus();
  }

  function draftKey(e) {
    if (e.key === "Enter" || e.key === "," || e.key === "،") {
      e.preventDefault();
      addDraft();
    } else if (e.key === "Backspace" && draft === "" && chips.length) {
      e.preventDefault();
      removePort(chips[chips.length - 1]);
    } else if (draftError) {
      draftError = "";
    }
  }

  function setLimitOn(on) {
    limitOn = on;
    if (on) {
      form.limit = whole(lastLimit) && +plain(lastLimit) > 0 ? lastLimit : "100";
      if (!whole(form.days) || +plain(form.days) < 1) form.days = "30";
    } else {
      if (whole(form.limit) && +plain(form.limit) > 0) lastLimit = form.limit;
      form.limit = "0";
    }
  }

  function pickRestart(h) {
    customRestart = h === "custom";
    if (!customRestart) form.restart = h;
  }

  /** Why a setting's input is not acceptable, or "". */
  function settingError(s) {
    const text = plain(form.values[settingKey(s)]);
    if (text === "") return "";
    if (!whole(text) || +text < s.min || +text > s.max) return t("rangeErr", num(s.min), num(s.max));
    return "";
  }
  function settingValue(s) {
    const text = plain(form.values[settingKey(s)]);
    return text === "" ? null : +text;
  }
  const settingChanged = (s) => !settingError(s) && settingValue(s) !== s.value;

  const limit = $derived(+plain(form.limit));
  const days = $derived(+plain(form.days));
  const limitError = $derived(limitOn && (!whole(form.limit) || limit < 1 || limit > 1_000_000) ? t("limitErr") : "");
  const daysError = $derived(limitOn && (!whole(form.days) || days < 1 || days > 3650) ? t("daysErr") : "");
  const portsError = $derived(screen?.ports && !chips.length ? t("portsErr") : "");
  const restartError = $derived(!whole(form.restart) || +plain(form.restart) > 8760 ? t("restartErr") : "");

  const shown = $derived(
    (screen?.settings ?? []).filter((s) => !find.trim() || `${s.name} ${s.description}`.toLowerCase().includes(find.trim().toLowerCase())),
  );
  const changedSettings = $derived((screen?.settings ?? []).filter(settingChanged).length);

  /** Only what differs from the saved settings. */
  const changes = $derived.by(() => {
    if (!screen) return {};
    const out = {};
    const ports = chips.join(", ");
    if (screen.ports && (ports !== split(screen.ports.text).join(", ") || form.protocol !== screen.ports.protocol)) {
      out.ports = { text: ports, protocol: form.protocol };
    }
    if (screen.ports && +form.proxy !== (screen.ports.proxy_protocol ?? 0)) out.proxy_protocol = +form.proxy;
    if (whole(form.restart) && +plain(form.restart) !== (screen.restart_hours ?? 0)) out.restart_hours = +plain(form.restart);
    const gb = limitOn ? limit : 0;
    const period = gb > 0 ? days : screen.quota.period_days;
    if (gb !== screen.quota.limit_gb || (gb > 0 && period !== screen.quota.period_days)) {
      out.quota = { limit_gb: gb, period_days: period };
    }
    // Carrier choices: only the ones that changed (a switched Parallax mode drops speed changes
    // that would not apply).
    const was = screen.carrier ?? {};
    const now = form.carrier ?? {};
    const carrier = {};
    if (was.parallax_mode != null && now.parallax_mode !== was.parallax_mode) carrier.parallax_mode = now.parallax_mode;
    const speedNow = now.parallax_mode === "stream" && was.parallax_mode === "packet" ? null : now.speed;
    if (speedNow != null && speedNow !== "custom" && speedNow !== was.speed) carrier.speed = speedNow;
    if (was.pool != null && whole(now.pool) && +plain(now.pool) !== was.pool) carrier.pool = +plain(now.pool);
    if (was.tls_profile != null && now.tls_profile !== was.tls_profile) carrier.tls_profile = now.tls_profile;
    if (was.tls_fragment != null && now.tls_fragment !== was.tls_fragment) carrier.tls_fragment = now.tls_fragment;
    if (was.game && now.game) {
      const g = now.game;
      const same = g.on === was.game.on && (!g.on || (+g.port === was.game.port && +g.copies === was.game.copies && (g.iran_address ?? "") === (was.game.iran_address ?? "")));
      if (!same) carrier.game = g.on ? { on: true, port: +g.port, copies: +g.copies, iran_address: g.iran_address || null } : { on: false };
    }
    if (Object.keys(carrier).length) out.carrier = carrier;
    const settings = [];
    for (const s of screen.settings) {
      const value = settingValue(s);
      if (value !== s.value) settings.push({ name: s.name, place: s.place, value });
    }
    if (settings.length) out.settings = settings;
    return out;
  });

  const protoName = (p) => (p === "both" ? t("tcpUdp") : p.toUpperCase());
  const proxyName = (v) => t(["proxyOff", "proxyV1", "proxyV2"][+v] ?? "proxyOff");
  const limitName = (gb, d) => (gb > 0 ? t("limitTextE", num(gb), num(d)) : t("noLimitW"));

  /** The changes in words: [label, before, after]. */
  const review = $derived.by(() => {
    if (!screen) return [];
    const rows = [];
    const c = changes;
    if (c.ports) {
      const before = split(screen.ports.text).join(", ");
      if (c.ports.text !== before) rows.push([t("chPorts"), before, c.ports.text]);
      if (c.ports.protocol !== screen.ports.protocol) rows.push([t("chProto"), protoName(screen.ports.protocol), protoName(c.ports.protocol)]);
    }
    if (c.proxy_protocol != null) rows.push([t("chProxy"), proxyName(screen.ports.proxy_protocol ?? 0), proxyName(c.proxy_protocol)]);
    if (c.quota) rows.push([t("chLimit"), limitName(screen.quota.limit_gb, screen.quota.period_days), limitName(c.quota.limit_gb, c.quota.period_days)]);
    const speedName = (v) => t("ntSpeedOpts")[v] ?? v;
    if (c.carrier?.parallax_mode) rows.push([t("chPxMode"), t(screen.carrier.parallax_mode === "packet" ? "ntPacket" : "ntStream"), t(c.carrier.parallax_mode === "packet" ? "ntPacket" : "ntStream")]);
    if (c.carrier?.speed) rows.push([t("chSpeed"), speedName(screen.carrier.speed ?? "default"), speedName(c.carrier.speed)]);
    if (c.carrier?.pool != null) rows.push([t("chPool"), num(screen.carrier.pool), num(c.carrier.pool)]);
    if (c.carrier?.tls_profile) rows.push([t("chTlsLook"), t(screen.carrier.tls_profile === "chrome" ? "ntChrome" : "ntClassic"), t(c.carrier.tls_profile === "chrome" ? "ntChrome" : "ntClassic")]);
    if (c.carrier?.game) rows.push([t("chGame"), screen.carrier.game.on ? `${t("chOn")} · ${screen.carrier.game.copies}× · ${screen.carrier.game.port}` : t("chOff"), c.carrier.game.on ? `${t("chOn")} · ${c.carrier.game.copies}× · ${c.carrier.game.port}` : t("chOff")]);
    if (c.carrier?.tls_fragment != null) rows.push([t("chTlsFrag"), screen.carrier.tls_fragment ? t("chOn") : t("chOff"), c.carrier.tls_fragment ? t("chOn") : t("chOff")]);
    if (c.restart_hours != null) rows.push([t("chRestart"), t("restartEveryT", String(screen.restart_hours ?? 0)), t("restartEveryT", String(c.restart_hours))]);
    for (const s of c.settings ?? []) {
      const old = screen.settings.find((x) => x.name === s.name && x.place === s.place);
      const show = (v) => (v == null ? `${t("dflt")} ${num(old.default)}` : num(v));
      rows.push([s.name, show(old.value), show(s.value)]);
    }
    return rows;
  });

  const changed = $derived(Object.keys(changes).length > 0);
  // Only a changed pool is checked: a saved one above 16 (set by hand) stays as it is.
  const poolChanged = $derived(form.carrier?.pool != null && String(form.carrier.pool).trim() !== String(screen?.carrier?.pool ?? ""));
  const poolError = $derived(poolChanged && (!whole(form.carrier.pool) || +plain(form.carrier.pool) < 1 || +plain(form.carrier.pool) > 16) ? t("poolErr") : "");
  /** Speed modes exist for KCP and FEC carriers, and for Parallax in packet mode. */
  const speedShown = $derived(screen?.carrier?.speed != null || (screen?.carrier?.parallax_mode != null && form.carrier?.parallax_mode === "packet"));
  const invalid = $derived(Boolean(poolError || limitError || daysError || portsError || restartError || draftError || screen?.settings.some(settingError)));
  const portsChanged = $derived(Boolean(changes.ports || changes.proxy_protocol != null));

  function failureText(status) {
    if (status === 401) return t("signedOutNow");
    if (status === 409) return t("busyT");
    return t("saveFailed");
  }

  async function run(kind) {
    if (kind === "edit" && draft.trim() && !addDraft()) return;
    if (pending[key] || pending["*"]) return say(t("busyT"), true);
    pending[key] = kind;
    problem = null;
    askUndo = false;
    try {
      const { status, data } = kind === "undo" ? await undoEdit(name, server) : await saveEdit(name, changes, server);
      if (status !== 200) {
        problem = { text: failureText(status), detail: data?.detail ?? "" };
        return;
      }
      if (data.reverted) {
        const text = { text: data.came_up ? t("revertedUp") : t("revertedDown"), detail: data.detail ?? "" };
        await open(name, server);
        problem = text;
        return;
      }
      if (!data.changed) {
        say(t("noChangeT", name));
      } else if (data.restarted && data.came_up === false) {
        say(t("notUpT", name), true);
      } else if (kind === "undo") {
        say(t(data.restarted ? "undoneRestartedT" : "undoneT", name));
      } else {
        say(t(data.restarted ? "savedRestartedT" : "savedT", name));
      }
      shut();
    } catch {
      problem = { text: t("slowT", name), detail: "" };
    } finally {
      delete pending[key];
    }
  }

  function keys(e) {
    // Ctrl or Cmd + Enter saves from anywhere in the panel.
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && changed && !invalid && !working) {
      e.preventDefault();
      run("edit");
    }
  }
  // Closes the panel and tells the page at once; some browsers deliver the dialog's own close
  // event late or not at all, which would leave the panel unable to open again.
  function shut() {
    openGeneration++;
    controller?.abort();
    if (dialog?.open) dialog.close();
    onclose?.();
  }
</script>

<dialog bind:this={dialog} class="edit-panel" aria-labelledby="edit-title" onclose={() => onclose?.()} oncancel={(e) => { e.preventDefault(); if (!(working)) shut(); }} onkeydown={keys}>
  <div class="dlg-h">
    <span class="dlg-ico"><Icon name="edit" /></span>
    <h2 id="edit-title">{t("editT")} <span class="dlg-sub ltr">{name}</span></h2>
    <button class="btn icon ghost" onclick={shut} disabled={working} aria-label={t("close")}><Icon name="x" /></button>
  </div>
  <div class="dlg-b edit-b">
    {#if phase === "loading"}
      <div class="loading" role="status"><div class="blocks"></div><span class="muted">{t("editLoading")}</span></div>
    {:else if phase === "error"}
      <div class="note bad" role="alert"><Icon name="warn" /><span>{t("editLoadFail")}{#if loadError}{" "}<span class="ltr">{loadError}</span>{/if}</span></div>
    {:else}
      <fieldset disabled={working}>
        {#if screen.presets?.presets?.length}
          <section class="ed-sec" aria-labelledby="ed-presets-h">
            <header><h3 id="ed-presets-h">{t("edPresets")}</h3>{#if chosen}<span class="dot" title={t("changesN", 1)}></span>{/if}</header>
            <p class="muted small m0">{t("edPresetsHelp", num(screen.presets.capacity.memory_mb), num(screen.presets.capacity.cores))}</p>
            <div class="preset-grid mt12" role="group" aria-labelledby="ed-presets-h">
              {#each screen.presets.presets as p (p.id)}
                <button type="button" class="preset" aria-pressed={chosen === p.id} disabled={Boolean(p.problem)} title={p.problem ?? ""} onclick={() => pickPreset(p)}>
                  <span class="preset-h"><b>{presetName(p)}</b>{#if p.active}<span class="pill ok">{t("presetInUse")}</span>{/if}</span>
                  <span class="muted small">{presetText(p)}</span>
                  <span class="small preset-n">{p.problem ? t("presetNoFit") : p.active ? t("presetSame") : t("presetChanges", num(presetCount(p)))}</span>
                </button>
              {/each}
            </div>
            {#if chosen}<p class="small m0 mt8 warn-t">{t("presetChosen")}</p>{/if}
          </section>
        {/if}
        {#if screen.carrier && (screen.carrier.parallax_mode != null || screen.carrier.pool != null || speedShown || screen.carrier.tls_profile != null || screen.carrier.game)}
          <section class="ed-sec" aria-labelledby="ed-carrier-h">
            <header><h3 id="ed-carrier-h">{t("edCarrier")} <span class="dlg-sub ltr">{screen.carrier.transport}</span></h3>{#if changes.carrier}<span class="dot" title={t("changesN", 1)}></span>{/if}</header>
            <p class="muted small m0">{t("edCarrierHelp")}</p>
            <div class="ed-grid mt12">
              {#if screen.carrier.parallax_mode != null}
                <div>
                  <span class="flabel" id="ed-pxm-l">{t("ntPxMode")}</span>
                  <div class="seg full" role="group" aria-labelledby="ed-pxm-l">
                    {#each [["stream", "ntStream"], ["packet", "ntPacket"]] as [v, k]}<button type="button" aria-pressed={form.carrier.parallax_mode === v} onclick={() => (form.carrier.parallax_mode = v)}>{t(k)}</button>{/each}
                  </div>
                </div>
              {/if}
              {#if speedShown}
                <div>
                  <label class="flabel" for="ed-speed">{t("ntSpeed")}</label>
                  <select id="ed-speed" class="input" value={form.carrier.speed ?? "default"} onchange={(e) => (form.carrier.speed = e.currentTarget.value)}>
                    {#each [...(form.carrier.speed === "custom" ? ["custom"] : []), "default", "normal", "fast", "fast2", "fast3"] as v}<option value={v}>{t("ntSpeedOpts")[v]}</option>{/each}
                  </select>
                </div>
              {/if}
              {#if screen.carrier.pool != null}
                <div>
                  <label class="flabel" for="ed-pool">{t("ntPool")}</label>
                  <input id="ed-pool" class="input ltr" inputmode="numeric" bind:value={form.carrier.pool} aria-invalid={Boolean(poolError)} />
                  {#if poolError}<p class="small m0 bad-t">{poolError}</p>{/if}
                </div>
              {/if}
              {#if screen.carrier.tls_profile != null}
                <div>
                  <span class="flabel" id="ed-tls-l">{t("ntTlsLook")}</span>
                  <div class="seg full" role="group" aria-labelledby="ed-tls-l">
                    {#each [["classic", "ntClassic"], ["chrome", "ntChrome"]] as [v, k]}<button type="button" aria-pressed={form.carrier.tls_profile === v} onclick={() => (form.carrier.tls_profile = v)}>{t(k)}</button>{/each}
                  </div>
                </div>
              {/if}
            </div>
            {#if form.carrier.game}
              <label class="chk mt12"><input type="checkbox" bind:checked={form.carrier.game.on} /><span>{t("ntGame")}</span></label>
              <p class="muted small m0">{t("ntGameHelp")}</p>
              {#if form.carrier.game.on}
                <div class="ed-grid mt8">
                  <div><label class="flabel" for="ed-gport">{t("ntGamePort")}</label><input id="ed-gport" class="input ltr" inputmode="numeric" bind:value={form.carrier.game.port} /></div>
                  <div><label class="flabel" for="ed-gcopies">{t("ntGameCopies")}</label><input id="ed-gcopies" class="input ltr" type="number" min="1" max="4" bind:value={form.carrier.game.copies} /></div>
                  {#if screen.carrier.game_needs_iran_address}<div><label class="flabel" for="ed-giran">{t("ntIranAddr")}</label><input id="ed-giran" class="input ltr" bind:value={form.carrier.game.iran_address} /></div>{/if}
                </div>
              {/if}
            {/if}
            {#if screen.carrier.tls_fragment != null}
              <label class="chk mt12"><input type="checkbox" bind:checked={form.carrier.tls_fragment} /><span>{t("ntTlsFrag")}</span></label>
              {#if form.carrier.tls_fragment && !screen.carrier.tls_fragment}<p class="small m0 warn-t">{t("ntTlsFragHelp")}</p>{/if}
            {/if}
          </section>
        {/if}
        {#if screen.ports}
          <section class="ed-sec" aria-labelledby="ed-ports-h">
            <header><h3 id="ed-ports-h">{t("fwdPorts")}</h3>{#if portsChanged}<span class="dot" title={t("changesN", 1)}></span>{/if}</header>
            <div>
              <label class="flabel" for="ed-port-in">{t("portsLabel")}</label>
              <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
              <div class="chips ltr" aria-invalid={Boolean(portsError || draftError)} onclick={() => draftInput?.focus()}>
                {#each chips as p (p)}
                  <span class="chip" class:new={p === lastAdded}>{p}<button type="button" onclick={() => removePort(p)} aria-label={t("removeP", p)}><Icon name="x" /></button></span>
                {/each}
                <input
                  id="ed-port-in"
                  bind:this={draftInput}
                  bind:value={draft}
                  onkeydown={draftKey}
                  onblur={() => draft.trim() && addDraft()}
                  onpaste={() => setTimeout(() => /[,\s،]/.test(draft) && addDraft())}
                  placeholder={chips.length ? "" : t("addPortPh")}
                  inputmode="numeric"
                  autocomplete="off"
                  spellcheck="false"
                  aria-describedby="ed-ports-help" />
                <button type="button" class="dice" onclick={(e) => { e.stopPropagation(); addRandom(); }} title={t("randomPortAdd")} aria-label={t("randomPortAdd")}><Icon name="dice" /></button>
              </div>
              <p id="ed-ports-help" class="small m0 ehelp {draftError || portsError ? 'bad-t' : 'muted'}" aria-live="polite">{draftError || portsError || t("portsHelp2")}</p>
            </div>
            <div>
              <span class="flabel" id="ed-proto-l">{t("protocol")}</span>
              <div class="seg full" role="group" aria-labelledby="ed-proto-l">
                {#each ["tcp", "udp", "both"] as p}
                  <button type="button" aria-pressed={form.protocol === p} onclick={() => (form.protocol = p)}>{protoName(p)}</button>
                {/each}
              </div>
            </div>
            <div>
              <span class="flabel" id="ed-proxy-l">{t("proxyLabel")}</span>
              <div class="seg full" role="group" aria-labelledby="ed-proxy-l" aria-describedby="ed-proxy-h">
                {#each ["0", "1", "2"] as v}
                  <button type="button" aria-pressed={form.proxy === v} onclick={() => (form.proxy = v)}>{proxyName(v)}</button>
                {/each}
              </div>
              <p id="ed-proxy-h" class="muted small m0 ehelp">{t("proxyHelp")}</p>
            </div>
            {#if screen.ports.several_addresses}
              <div class="note warn" role="note"><Icon name="warn" /><span>{t("severalAddr")}</span></div>
            {/if}
          </section>
        {/if}

        <section class="ed-sec" aria-labelledby="ed-limit-h">
          <header><h3 id="ed-limit-h">{t("limitH")}</h3>{#if changes.quota}<span class="dot"></span>{/if}</header>
          <label class="switch"><input type="checkbox" role="switch" checked={limitOn} onchange={(e) => setLimitOn(e.currentTarget.checked)} />{t("limitOn")}</label>
          {#if limitOn}
            <div class="ed-grid">
              <div>
                <label class="flabel" for="ed-limit">{t("limitAmt")}</label>
                <div class="unit-in"><input id="ed-limit" class="input ltr" inputmode="numeric" bind:value={form.limit} aria-invalid={Boolean(limitError)} aria-describedby="ed-limit-help" /><span>{t("gbU")}</span></div>
                <div class="presets mt8" role="group" aria-label={t("limitGb")}>
                  {#each GB as g}<button type="button" aria-pressed={plain(form.limit) === g} onclick={() => (form.limit = g)}>{num(+g)} {t("gbU")}</button>{/each}
                </div>
              </div>
              <div>
                <label class="flabel" for="ed-days">{t("limitPer")}</label>
                <div class="unit-in"><input id="ed-days" class="input ltr" inputmode="numeric" bind:value={form.days} aria-invalid={Boolean(daysError)} aria-describedby="ed-limit-help" /><span>{t("daysU")}</span></div>
                <div class="presets mt8" role="group" aria-label={t("periodDays")}>
                  {#each DAYS as d}<button type="button" aria-pressed={plain(form.days) === d} onclick={() => (form.days = d)}>{num(+d)} {t("daysU")}</button>{/each}
                </div>
              </div>
            </div>
            <p id="ed-limit-help" class="small m0 {limitError || daysError ? 'bad-t' : 'muted'}">{limitError || daysError || t("limitHelp2")}</p>
          {:else}
            <p class="ed-off m0">{t("noLimitNote")}</p>
          {/if}
        </section>

        <section class="ed-sec" aria-labelledby="ed-restart-h">
          <header><h3 id="ed-restart-h">{t("restartH")}</h3>{#if changes.restart_hours != null}<span class="dot"></span>{/if}</header>
          <div class="seg" role="group" aria-labelledby="ed-restart-h">
            {#each RESTARTS as h}
              <button type="button" aria-pressed={!customRestart && form.restart === h} onclick={() => pickRestart(h)}>{h === "0" ? t("never") : t("everyH", num(+h))}</button>
            {/each}
            <button type="button" aria-pressed={customRestart} onclick={() => pickRestart("custom")}>{t("custom")}</button>
          </div>
          {#if customRestart}
            <div class="eset-in">
              <label class="flabel m0" for="ed-restart">{t("restartHours")}</label>
              <div class="unit-in"><input id="ed-restart" class="input ltr" inputmode="numeric" bind:value={form.restart} aria-invalid={Boolean(restartError)} aria-describedby="ed-restart-help" /><span>{t("hU")}</span></div>
            </div>
          {/if}
          <p id="ed-restart-help" class="small m0 {restartError ? 'bad-t' : 'muted'}">{restartError || t("restartHelp")}</p>
        </section>

        {#if screen.settings.length}
          <details class="eadv">
            <summary>
              <h3>{t("advanced")}{#if changedSettings}<span class="code-chip">{t("changesN", changedSettings)}</span>{/if}</h3>
              <span class="muted small">{t("advancedHelp")}</span>
            </summary>
            {#if screen.settings.length > 4}
              <div class="ed-find"><Icon name="search" /><input class="input" type="search" bind:value={find} placeholder={t("findSet")} aria-label={t("findSet")} /></div>
            {/if}
            <div class="elist">
              {#each shown as s, i (settingKey(s))}
                {@const err = settingError(s)}
                {#if s.group && (i === 0 || shown[i - 1].group !== s.group)}
                  <h4 class="egroup">{s.group === "carrier" ? t("grp_carrier", s.carrier ?? s.group_title) : t("grp_" + s.group)}</h4>
                {/if}
                <div class="eset" class:changed={settingChanged(s)}>
                  <div class="eset-h">
                    <label class="ltr mono" for="ed-s{i}">{s.name}</label>
                    {#if s.place !== "top"}<span class="code-chip">{t("place_" + s.place)}</span>{/if}
                  </div>
                  <p class="muted small m0 ltr edesc" id="ed-s{i}-d">{s.description}</p>
                  <div class="eset-in">
                    <div class="unit-in"><input id="ed-s{i}" class="input ltr" inputmode="numeric" bind:value={form.values[settingKey(s)]} placeholder="{t('dflt')} {num(s.default)}" aria-invalid={Boolean(err)} aria-describedby="ed-s{i}-d ed-s{i}-r" />{#if s.unit}<span>{s.unit}</span>{/if}</div>
                    <button type="button" class="btn ghost" onclick={() => (form.values[settingKey(s)] = "")} disabled={form.values[settingKey(s)] === ""}><Icon name="undo" />{t("useDefault")}</button>
                  </div>
                  <p id="ed-s{i}-r" class="small m0 {err ? 'bad-t' : 'muted'}">{err || t("rangeLine", num(s.min), num(s.max), num(s.default))}</p>
                </div>
              {:else}
                <p class="muted small eset">{t("noSetMatch")}</p>
              {/each}
            </div>
          </details>
        {/if}
      </fieldset>

      {#if showReview && review.length}
        <ul class="ed-list" aria-label={t("review")}>
          {#each review as [label, before, after]}
            <li><span class="muted">{label}</span><span class="from ltr">{before}</span><span class="arrow" aria-hidden="true">→</span><span class="to ltr">{after}</span></li>
          {/each}
        </ul>
      {/if}
      {#if problem}
        <div class="note bad" role="alert"><Icon name="warn" /><span>{problem.text}{#if problem.detail}{" "}<span class="ltr">{problem.detail}</span>{/if}</span></div>
      {:else if changed}
        <div class="note info" role="note"><Icon name="restart" /><span>{t("saveNote")}</span></div>
      {/if}
      {#if askUndo}
        <div class="note warn eundo" role="alert">
          <Icon name="undo" /><span class="grow">{t("undoQ")}</span>
          <button class="btn" onclick={() => (askUndo = false)}>{t("cancel")}</button>
          <button class="btn danger" onclick={() => run("undo")}>{t("undoGo")}</button>
        </div>
      {/if}
    {/if}
  </div>
  {#if phase === "ready"}
    <div class="dlg-f">
      <div class="ed-sum" aria-live="polite">
        {#if changed}
          <b>{t("changesN", review.length || 1)}</b>
          <button class="btn ghost" onclick={() => (showReview = !showReview)} aria-expanded={showReview}>{showReview ? t("hideReview") : t("review")}</button>
          <button class="btn ghost" onclick={fill} disabled={working}>{t("discard")}</button>
        {:else}
          <span>{t("noChangesYet")}</span>
          {#if screen.can_undo}
            <button class="btn ghost" onclick={() => (askUndo = true)} disabled={working || askUndo} aria-busy={pending[key] === "undo"}>
              <Icon name="undo" />{pending[key] === "undo" ? t("undoing") : t("undo")}
            </button>
          {/if}
        {/if}
      </div>
      <button class="btn" onclick={shut} disabled={working}>{t("cancel")}</button>
      <button class="btn primary" onclick={() => run("edit")} disabled={!changed || invalid || working} aria-busy={pending[key] === "edit"} title="Ctrl+Enter">
        {pending[key] === "edit" ? t("saving") : t("saveRestart")}
      </button>
    </div>
  {/if}
</dialog>
