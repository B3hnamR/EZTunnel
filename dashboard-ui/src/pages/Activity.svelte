<script>
  // What happened on the dashboard itself, newest first: sign-ins, actions and certificates.
  import Icon from "../lib/Icon.svelte";
  import Blocks from "../lib/Blocks.svelte";
  import { getActivity } from "../lib/api.js";
  import { t, num, ui } from "../lib/i18n.svelte.js";

  const KINDS = {
    all: () => true,
    signin: (e) => e.event.startsWith("login") || e.event === "logout",
    actions: (e) => e.event.startsWith("action"),
    system: (e) => e.event === "start" || e.event.startsWith("certificate"),
  };
  const BAD = ["login_failed", "login_refused", "action_failed", "certificate_failed"];
  // Events whose label says it all; their stored detail only repeats it.
  const PLAIN = ["login", "logout", "login_failed"];

  let events = $state([]);
  let view = $state("loading"); // loading, ready, error
  let kind = $state("all");
  let limit = $state(200);
  let updated = $state(0);

  const shown = $derived(events.filter(KINDS[kind]));

  async function load() {
    try {
      const { status, data } = await getActivity(limit);
      if (status !== 200) throw new Error(String(status));
      events = data.events;
      view = "ready";
      updated = Date.now();
    } catch {
      if (view !== "ready") view = "error";
    }
  }

  $effect(() => {
    limit;
    load();
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  });

  function when(seconds) {
    return new Intl.DateTimeFormat(ui.lang === "fa" ? "fa-IR" : "en-GB", {
      day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(new Date(seconds * 1000));
  }

  function label(event) {
    return t("ev")[event] ?? event;
  }
</script>

<div class="row-flex act-tools">
  <div class="tabs" role="group" aria-label={t("evFilter")}>
    {#each Object.keys(KINDS) as k}
      <button aria-pressed={kind === k} onclick={() => (kind = k)}>{t("evKind")[k]}</button>
    {/each}
  </div>
  <div class="grow"></div>
  <label class="sr" for="act-limit">{t("linesLabel")}</label>
  <select id="act-limit" class="input act-limit" bind:value={limit}>
    {#each [100, 200, 500, 1000] as n}<option value={n}>{num(n)}</option>{/each}
  </select>
  <button class="btn" onclick={load}><Icon name="restart" />{t("refresh")}</button>
</div>

{#if view === "loading"}
  <div class="loading" role="status"><Blocks value={30} /><span>{t("logLoading")}</span></div>
{:else if view === "error"}
  <div class="note bad act" role="alert">
    <Icon name="warn" />
    <div class="grow">{t("actError")}</div>
    <button class="btn" onclick={load}>{t("retry")}</button>
  </div>
{:else}
  <p class="muted small log-status" aria-live="polite">
    <span>{t("actNote")}</span>
    <span>{t("evCount", shown.length)}</span>
  </p>
  {#if shown.length === 0}
    <div class="muted act-empty">{t("actEmpty")}</div>
  {:else}
    <ul class="act-list">
      {#each shown as e}
        <li>
          <span class="mark {BAD.includes(e.event) ? 'bad' : e.event === 'login_refused' ? 'warn' : 'ok'}" aria-hidden="true"></span>
          <div class="act-main">
            <div><b>{label(e.event)}</b>{#if !PLAIN.includes(e.event)} <span class="ltr act-detail">{e.detail}</span>{/if}</div>
            <div class="muted small">
              <time datetime={new Date(e.time * 1000).toISOString()}>{when(e.time)}</time>
              {#if e.ip}<span class="act-sep" aria-hidden="true">·</span><span>{t("evFrom")}<span class="ltr mono act-ip">{e.ip}</span></span>{/if}
            </div>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
  {#if updated}<span class="sr" aria-live="polite">{t("evCount", shown.length)}</span>{/if}
{/if}
