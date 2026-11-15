<script>
  import { areaPaths } from "./chart.js";
  let { values = [], active = true, warn = false, id } = $props();
  const W = 400;
  const H = 64;
  const p = $derived(areaPaths(values, W, H, Math.max(1, ...values)));
</script>

<svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" aria-hidden="true" data-spark={id}>
  {#if !active || values.length < 2}
    <line class="idle" x1="0" x2={W} y1={H - 6} y2={H - 6} stroke-dasharray="4 6" />
  {:else}
    <path d={p.line} class={warn ? "sp-warn" : "sp-line"} fill="none" stroke-width="1.5" vector-effect="non-scaling-stroke" />
  {/if}
</svg>
