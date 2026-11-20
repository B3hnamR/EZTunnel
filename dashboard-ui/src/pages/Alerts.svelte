<script>
  // Alerts now firing and the history of what fired and cleared, grouped by day.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { getAlerts } from "../lib/api.js";
  import { t, num, duration, ui } from "../lib/i18n.svelte.js";

  let data = $state(null);
  let failed = $state(false);
  async function load() {
    try {
      const { status, data: body } = await getAlerts();
      if (status === 200) {
        data = body;
        failed = false;
      } else failed = true;
    } catch {
      failed = true;
    }
  }
  $effect(() => {
    untrack(load);
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  });

  // From the language state, so day names and times follow a change of language at once.
  const fa = () => ui.lang === "fa";
  const time = (secs) => new Date(secs * 1000).toLocaleTimeString(fa() ? "fa-IR" : "en-GB", { hour: "2-digit", minute: "2-digit" });
  const day = (secs) => new Date(secs * 1000).toLocaleDateString(fa() ? "fa-IR" : "en-GB", { weekday: "long", day: "numeric", month: "long" });
  const what = (p) => t("alertKind")[p.kind] ?? p.kind;
  const where = (p) => (p.subject ? `${p.server_name} · ${p.subject}` : p.server_name);
  const link = (p) => (p.subject && p.kind !== "offline" ? `#/tunnel?t=${encodeURIComponent(p.subject)}${p.server !== "local" ? `&s=${encodeURIComponent(p.server)}` : ""}` : p.kind === "offline" ? "#/servers" : null);

  // The history comes newest first, one line per fire, escalation and clear. A clear knows when
  // its alert started, so one alert becomes one episode (start to end); a problem that comes back
  // many times in a day becomes one row with each episode inside, instead of two rows per time.
  const episodes = $derived.by(() => {
    const list = [];
    const open = new Map(); // problem key → the episode a later clear already accounts for
    for (const e of data?.history ?? []) {
      const key = e.problem.key;
      if (e.state === "cleared") {
        const episode = { problem: e.problem, start: e.since ?? e.at - (e.lasted ?? 0), end: e.at, lasted: e.lasted ?? e.at - (e.since ?? e.at), worse: false };
        list.push(episode);
        open.set(key, episode);
        continue;
      }
      // A fire or escalation inside an episode already listed belongs to it.
      const known = open.get(key);
      if (known && (known.end === null || (e.at >= known.start - 1 && e.at <= known.end))) {
        if (e.state === "escalated") known.worse = true;
        if (e.state === "fired") {
          // An episode not cleared yet starts at its fire, not at a later escalation.
          if (known.end === null) known.start = e.at;
          open.delete(key);
        }
        continue;
      }
      if (e.state === "fired" || e.state === "escalated") {
        // Not cleared (yet): it is still firing, or the history ends here.
        const episode = { problem: e.problem, start: e.at, end: null, lasted: null, worse: e.state === "escalated" };
        list.push(episode);
        open.set(key, episode);
        if (e.state === "fired") open.delete(key);
      }
    }
    return list;
  });

  const DAYS_SHOWN = 3;
  let allDays = $state(false);
  const days = $derived.by(() => {
    // By label, in order of first appearance: an episode across midnight cannot split a day.
    const groups = new Map();
    for (const episode of episodes) {
      const label = day(episode.start);
      if (!groups.has(label)) groups.set(label, { label, rows: new Map() });
      const rows = groups.get(label).rows;
      const key = episode.problem.key;
      if (!rows.has(key)) rows.set(key, { key, problem: episode.problem, episodes: [] });
      rows.get(key).episodes.push(episode);
    }
    return [...groups.values()].map((g) => ({ label: g.label, rows: [...g.rows.values()] }));
  });
  const shownDays = $derived(allDays ? days : days.slice(0, DAYS_SHOWN));

  const span = (ep) => (ep.end === null ? t("alSinceTime", time(ep.start)) : `${time(ep.start)}–${time(ep.end)}`);
  const longest = (row) => Math.max(...row.episodes.map((ep) => ep.lasted ?? 0));
  const stillOpen = (row) => row.episodes.some((ep) => ep.end === null);
</script>

<div class="al-grid">
<section class="panel" aria-labelledby="al-now">
  <div class="row-flex mb16">
    <h3 id="al-now" class="sec-h grow m0">{t("alNow")}</h3>
    <a class="btn" href="#/settings"><Icon name="telegram" />{t("alSetup")}</a>
  </div>
  {#if failed && !data}
    <div class="note bad" role="alert"><Icon name="warn" /><span>{t("alError")}</span></div>
  {:else if !data}
    <p class="muted m0">{t("loadingT")}</p>
  {:else if !data.active.length}
    <p class="m0 ok-t">{t("alNone")}</p>
  {:else}
    <ul class="hc-list">
      {#each data.active as a (a.key)}
        <li class="hc {a.level}">
          <span class="mark {a.level}" aria-hidden="true"></span>
          <div class="grow">
            <b>{what(a)}</b>
            <span class="muted small"><span class="ltr">{where(a)}</span> · {t("alSince", time(a.since), duration(Math.max(60, Date.now() / 1000 - a.since)))}</span>
          </div>
          {#if link(a)}<a class="btn" href={link(a)}>{t("alOpen")}</a>{/if}
          <span class="sr">{t("lvl")[a.level]}</span>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<section class="panel" aria-labelledby="al-hist">
  <div class="row-flex mb16 al-head">
    <h3 id="al-hist" class="sec-h grow m0">{t("alHistory")}</h3>
  </div>
  <p class="muted small">{t("alAbout")}</p>
  {#if data && !days.length}<p class="muted m0">{t("alNoHistory")}</p>{/if}
  {#each shownDays as group (group.label)}
    <h4 class="al-day">{group.label}</h4>
    <ul class="hc-list">
      {#each group.rows as row (row.key)}
        {@const open = stillOpen(row)}
        {@const first = row.episodes.at(-1)}
        <li class="hc al-row">
          <span class="mark {open ? row.problem.level : 'ok'}" aria-hidden="true"></span>
          <div class="grow">
            <b>{what(row.problem)}{#if row.episodes.some((ep) => ep.worse)}<span class="muted small"> · {t("alWorse")}</span>{/if}</b>
            <span class="muted small">
              <span class="ltr">{where(row.problem)}</span>{" · "}
              {#if row.episodes.length > 1}
                {t("alTimes", row.episodes.length)}{#if longest(row)}{" · "}{t("alLongest", duration(Math.max(60, longest(row))))}{/if}
              {:else if open}
                {t("alNotCleared")}
              {:else}
                {t("alLasted", duration(Math.max(60, first.lasted)))}
              {/if}
            </span>
            {#if row.episodes.length > 1}
              <details class="al-each">
                <summary class="small">{t("alEach")}</summary>
                <ul>
                  {#each row.episodes as ep, i (i)}
                    <li class="small muted"><span class="ltr">{span(ep)}</span>{#if ep.end !== null}{" · "}{duration(Math.max(60, ep.lasted))}{:else}{" · "}{t("alNotCleared")}{/if}</li>
                  {/each}
                </ul>
              </details>
            {/if}
          </div>
          <span class="muted small ltr al-when">{row.episodes.length > 1 ? `${time(first.start)}–${time(row.episodes[0].end ?? row.episodes[0].start)}` : span(first)}</span>
        </li>
      {/each}
    </ul>
  {/each}
  {#if days.length > DAYS_SHOWN}
    <button class="btn al-more" onclick={() => (allDays = !allDays)}>
      {allDays ? t("alFewerDays") : t("alOlderDays", days.length - DAYS_SHOWN)}
    </button>
  {/if}
</section>
</div>
