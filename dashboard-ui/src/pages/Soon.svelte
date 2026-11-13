<script>
  import { t, num } from "../lib/i18n.svelte.js";
  let { key, phase } = $props();
  const lines = $derived(t("soonText")[key]);
</script>

<section class="panel soon" aria-labelledby="soon-h">
  <span class="state off"><span class="mark"></span>{t("soonT")} {num(phase)}</span>
  <h2 id="soon-h">{t(key)}</h2>
  <p class="muted">{lines[0]}</p>
  <ul>
    {#each lines.slice(1) as line}<li>{line}</li>{/each}
  </ul>
  <a class="btn" href="#/">{t("backOv")}</a>
</section>
