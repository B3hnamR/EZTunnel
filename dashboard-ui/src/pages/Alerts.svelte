<script>
  // Alerts now firing and the history of what fired and cleared, grouped by day.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { getAlerts } from "../lib/api.js";
  import { t, num, duration } from "../lib/i18n.svelte.js";

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

  const fa = () => document.documentElement.lang === "fa";
  const time = (secs) => new Date(secs * 1000).toLocaleTimeString(fa() ? "fa-IR" : "en-GB", { hour: "2-digit", minute: "2-digit" });
  const day = (secs) => new Date(secs * 1000).toLocaleDateString(fa() ? "fa-IR" : "en-GB", { weekday: "long", day: "numeric", month: "long" });
  const what = (p) => t("alertKind")[p.kind] ?? p.kind;
  const where = (p) => (p.subject ? `${p.server_name} · ${p.subject}` : p.server_name);
  const link = (p) => (p.subject && p.kind !== "offline" ? `#/tunnel?t=${encodeURIComponent(p.subject)}${p.server !== "local" ? `&s=${encodeURIComponent(p.server)}` : ""}` : p.kind === "offline" ? "#/servers" : null);

  const days = $derived.by(() => {
    const groups = [];
    for (const entry of data?.history ?? []) {
      const label = day(entry.at);
      if (groups.at(-1)?.label !== label) groups.push({ label, entries: [] });
      groups.at(-1).entries.push(entry);
    }
    return groups;
  });
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
  {#each days as group (group.label)}
    <h4 class="al-day">{group.label}</h4>
    <ul class="hc-list">
      {#each group.entries as e, i (e.at + e.problem.key + e.state + i)}
        <li class="hc">
          <span class="mark {e.state === 'cleared' ? 'ok' : e.problem.level}" aria-hidden="true"></span>
          <div class="grow">
            <b>{e.state === "cleared" ? t("alCleared") : e.state === "escalated" ? t("alWorse") : t("alFired")}: {what(e.problem)}</b>
            <span class="muted small"><span class="ltr">{where(e.problem)}</span>{#if e.state === "cleared"}{" · "}{t("alLasted", duration(Math.max(60, e.lasted)))}{/if}</span>
          </div>
          <span class="muted small">{time(e.at)}</span>
        </li>
      {/each}
    </ul>
  {/each}
</section>
</div>
