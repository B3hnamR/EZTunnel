<script>
  import { t } from "./i18n.svelte.js";
  // Live, 24 hours, 7 days, 30 days. Arrow keys move between tabs, as tablists expect.
  let { value, onchange, label } = $props();
  const RANGES = ["live", "24h", "7d", "30d"];
  const KEYS = { live: "live", "24h": "h24", "7d": "d7", "30d": "d30" };
  let buttons = [];

  function keydown(event, index) {
    const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
    if (!step) return;
    event.preventDefault();
    const rtl = document.documentElement.dir === "rtl";
    const next = (index + (rtl ? -step : step) + RANGES.length) % RANGES.length;
    onchange(RANGES[next]);
    buttons[next]?.focus();
  }
</script>

<div class="tabs" role="tablist" aria-label={label}>
  {#each RANGES as range, i}
    <button
      role="tab"
      bind:this={buttons[i]}
      aria-selected={value === range}
      tabindex={value === range ? 0 : -1}
      onclick={() => onchange(range)}
      onkeydown={(e) => keydown(e, i)}>{t(KEYS[range])}</button>
  {/each}
</div>
