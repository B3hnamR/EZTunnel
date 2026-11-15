<script>
  // The log of one tunnel: the last lines, then new lines as they are written (live). Each line is
  // read into time, level, source and message so the eye can scan it; levels can be filtered and
  // the search term is marked. Used on the Logs page (with a tunnel picker) and in the tunnel panel.
  import { onDestroy, untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import { getLogs, followUrl } from "./api.js";
  import { say } from "./actions.svelte.js";
  import { t, num } from "./i18n.svelte.js";

  /** `names` and `onpick` show a tunnel picker; `uid` keeps element ids unique per view. */
  let { name, names = null, onpick = null, uid = "log", server = "local" } = $props();

  const LIMIT = 2000; // lines kept on screen
  const LEVELS = ["all", "error", "warn", "info", "debug"];
  let lines = $state([]);
  let count = $state(200);
  let view = $state("loading"); // loading, ready, error
  let following = $state(true);
  let filter = $state("");
  let only = $state("all");
  let wrap = $state(true);
  let box = $state();
  let atEnd = $state(true);
  let source;
  let loadGeneration = 0;
  let controller;
  let destroyed = false;

  /** "2026-11-13T10:00:42.123Z DEBUG eztunnel::engine: text" into its parts; other lines stay whole. */
  function parse(line) {
    const m = /^(\d{4}-\d\d-\d\dT(\d\d:\d\d:\d\d)\S*)\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+(?:([\w:]+):\s)?(.*)$/.exec(line);
    if (!m) {
      const lvl = /\bERROR\b/.test(line) ? "error" : /\bWARN\b/.test(line) ? "warn" : "info";
      return { time: "", stamp: "", level: lvl, src: "", text: line, raw: line };
    }
    // Shown in the viewer's own time, like every other time on the dashboard; the UTC stamp is
    // kept in the tooltip and in copies of the line.
    const at = new Date(m[1]);
    const time = Number.isNaN(at.getTime()) ? m[2] : at.toLocaleTimeString("en-GB", { hour12: false });
    return { time, stamp: m[1], level: m[3] === "TRACE" ? "debug" : m[3].toLowerCase(), src: (m[4] ?? "").replace(/^eztunnel::/, ""), text: m[5], raw: line };
  }

  const parsed = $derived(lines.map(parse));
  const counts = $derived.by(() => {
    const c = { all: parsed.length, error: 0, warn: 0, info: 0, debug: 0 };
    for (const p of parsed) c[p.level]++;
    return c;
  });
  const words = $derived(filter.trim().toLowerCase());
  const shown = $derived(parsed.filter((p) => (only === "all" || p.level === only) && (!words || p.raw.toLowerCase().includes(words))));

  /** The message split around the search term, so matches can be marked. */
  function pieces(text) {
    if (!words) return [[text, false]];
    const out = [];
    const low = text.toLowerCase();
    let at = 0;
    for (let i = low.indexOf(words); i !== -1; i = low.indexOf(words, at)) {
      if (i > at) out.push([text.slice(at, i), false]);
      out.push([text.slice(i, i + words.length), true]);
      at = i + words.length;
    }
    if (at < text.length) out.push([text.slice(at), false]);
    return out;
  }

  function stop() {
    source?.close();
    source = null;
  }

  function start(target, place = server) {
    stop();
    if (destroyed || !following || !target) return;
    const stream = new EventSource(followUrl(target, place));
    source = stream;
    stream.addEventListener("line", (event) => {
      if (source !== stream) return;
      lines.push(event.data);
      if (lines.length > LIMIT) lines.splice(0, lines.length - LIMIT);
    });
    // The browser reconnects by itself; a signed-out session gets 401 and stays closed.
  }

  async function load(target, n, place = server) {
    if (destroyed) return;
    const generation = ++loadGeneration;
    controller?.abort();
    controller = new AbortController();
    const signal = controller.signal;
    stop();
    if (!target) return;
    view = "loading";
    try {
      const { status, data } = await getLogs(target, n, place, signal);
      if (destroyed || signal.aborted || generation !== loadGeneration) return;
      if (status !== 200) throw new Error(String(status));
      lines = data.lines;
      view = "ready";
      start(target, place);
    } catch {
      if (destroyed || signal.aborted || generation !== loadGeneration) return;
      view = "error";
    }
  }

  $effect(() => {
    const target = name;
    const n = count;
    const place = server;
    untrack(() => load(target, n, place));
    return () => {
      loadGeneration++;
      controller?.abort();
      stop();
    };
  });

  // Keep the newest line in view unless the reader scrolled up.
  $effect(() => {
    shown.length;
    if (box && atEnd) queueMicrotask(() => box && (box.scrollTop = box.scrollHeight));
  });

  function onScroll() {
    // A scroll can still arrive after the page closed and the box is gone.
    if (!box) return;
    atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
  }

  function toggleFollow() {
    following = !following;
    if (following && view === "ready") start(name);
    else stop();
  }

  async function copy() {
    const text = shown.map((p) => p.raw).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      return say(t("copied"));
    } catch {
      // Blocked: select the text so the reader can copy it by hand.
    }
    const range = document.createRange();
    range.selectNodeContents(box);
    getSelection().removeAllRanges();
    getSelection().addRange(range);
    say(t("copyFail"), true);
  }

  function save() {
    const blob = new Blob([shown.map((p) => p.raw).join("\n") + "\n"], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${name}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.log`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function jump() {
    atEnd = true;
    box.scrollTop = box.scrollHeight;
  }

  onDestroy(() => {
    destroyed = true;
    loadGeneration++;
    controller?.abort();
    stop();
  });
</script>

<div class="lv-head">
  {#if names}
    {#if names.length <= 6}
      <div class="seg lv-names" role="group" aria-label={t("name")}>
        {#each names as n}<button type="button" class="ltr" aria-pressed={n === name} onclick={() => onpick?.(n)}>{n}</button>{/each}
      </div>
    {:else}
      <label class="picker" for="{uid}-tunnel">
        <Icon name="tunnels" /><span>{t("name")}</span>
        <select id="{uid}-tunnel" class="ltr" value={name} onchange={(e) => onpick?.(e.currentTarget.value)}>
          {#each names as n}<option value={n}>{n}</option>{/each}
        </select>
      </label>
    {/if}
  {/if}
  <div class="grow"></div>
  <button class="lv-live" class:on={following} onclick={toggleFollow} aria-pressed={following} title={following ? t("logLive") : t("logPaused")}>
    <span class="mark {following ? 'ok' : 'off'}"></span>{following ? t("lvLive") : t("lvPaused")}<Icon name={following ? "pause" : "play"} />
  </button>
</div>

<div class="lv-bar">
  <div class="lv-search">
    <Icon name="search" />
    <input id="{uid}-filter" class="input ltr" type="search" bind:value={filter} placeholder={t("filter")} aria-label={t("filter")} autocomplete="off" spellcheck="false" />
  </div>
  <div class="seg lv-levels" role="group" aria-label={t("logLevel")}>
    {#each LEVELS as l}
      <button type="button" class="lv-l-{l}" aria-pressed={only === l} onclick={() => (only = l)} disabled={l !== "all" && !counts[l]}>
        {#if l !== "all"}<i></i>{/if}{t("lvlName")[l]}<span class="lv-n">{num(counts[l])}</span>
      </button>
    {/each}
  </div>
  <label class="picker lv-count" for="{uid}-lines">
    <span>{t("linesLabel")}</span>
    <select id="{uid}-lines" bind:value={count}>
      {#each [100, 200, 500, 1000] as n}<option value={n}>{num(n)}</option>{/each}
    </select>
  </label>
  <div class="lv-btns">
    <button class="btn icon ghost" onclick={() => (wrap = !wrap)} aria-pressed={wrap} title={t("logWrap")} aria-label={t("logWrap")}><Icon name="menu" /></button>
    <button class="btn icon ghost" onclick={copy} disabled={!shown.length} title={t("copy")} aria-label={t("copy")}><Icon name="copy" /></button>
    <button class="btn icon ghost" onclick={save} disabled={!shown.length} title={t("download")} aria-label={t("download")}><Icon name="logs" /></button>
  </div>
</div>

{#if view === "loading"}
  <div class="loading" role="status"><div class="blocks"></div><span>{t("logLoading")}</span></div>
{:else if view === "error"}
  <div class="note bad act" role="alert">
    <Icon name="warn" />
    <div class="grow">{t("logError")}</div>
    <button class="btn" onclick={() => load(name, count)}><Icon name="restart" />{t("retry")}</button>
  </div>
{:else}
  <div class="lv-wrap">
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div class="log lv" class:nowrap={!wrap} bind:this={box} onscroll={onScroll} tabindex="0" role="log" aria-label="{t('logs')}: {name}">
      {#if shown.length === 0}
        <span class="log-empty">{filter || only !== "all" ? t("logNoMatch") : t("logEmpty")}</span>
      {:else}
        {#each shown as p}
          <div class="lv-row {p.level}">
            <span class="lv-t" title={p.stamp}>{p.time}</span>
            <span class="lv-lvl">{p.level === "debug" ? "DBG" : p.level === "error" ? "ERR" : p.level.toUpperCase()}</span>
            {#if p.src}<span class="lv-src">{p.src}</span>{/if}
            <span class="lv-msg">{#each pieces(p.text) as [part, hit]}{#if hit}<mark>{part}</mark>{:else}{part}{/if}{/each}</span>
          </div>
        {/each}
      {/if}
    </div>
    {#if !atEnd}
      <button class="btn lv-jump" onclick={jump}><Icon name="play" />{t("jumpEnd")}</button>
    {/if}
  </div>
  <p class="muted small lv-foot" aria-live="polite">{t("linesShown", shown.length)}</p>
{/if}
