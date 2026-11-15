<script>
  // The page footer: the program and its licence, whether the live feed is current, and where to
  // find the author. Sits at the bottom of the window even on a short page.
  import Icon from "./Icon.svelte";
  import { live } from "./live.svelte.js";
  import { t, clock } from "./i18n.svelte.js";
  let { version = "", status = true } = $props();
  const LINKS = [
    ["github", "GitHub", "https://github.com/B3hnamR"],
    ["telegram", "Telegram", "https://t.me/B3hnamR"],
  ];
</script>

<footer class="foot">
  <div class="foot-brand">
    <b>EZTunnel</b>
    {#if version}<span class="ver ltr">v{version}</span>{/if}
    <a class="foot-lic" href="https://github.com/B3hnamR/EZTunnel/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">AGPL-3.0</a>
  </div>
  {#if status}
    <div class="foot-live" role="status">
      <span class="mark {live.link === 'lost' ? 'bad' : live.link === 'up' ? 'ok' : 'off'}"></span>
      {#if live.link === "lost"}{t("footLost")}{:else if live.link === "up" && live.lastAt}{t("footLive", clock(live.lastAt))}{:else}{t("loadingT")}{/if}
    </div>
  {/if}
  <nav class="foot-links" aria-label={t("footAuthor")}>
    {#each LINKS as [icon, name, href]}
      <a class="foot-link" {href} target="_blank" rel="noopener noreferrer" aria-label="{name} (B3hnamR)">
        <Icon name={icon} /><span>{name}</span>
      </a>
    {/each}
  </nav>
</footer>
