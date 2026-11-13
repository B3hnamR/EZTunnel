<script>
  import { areaPaths } from "./chart.js";
  let { values = [], active = true, warn = false, id } = $props();
  const W = 400;
  const H = 64;
  const color = $derived(warn ? "#ffb547" : "#00d7ff");
  const p = $derived(areaPaths(values, W, H, Math.max(1, ...values)));
</script>

<svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" aria-hidden="true">
  {#if !active || values.length < 2}
    <line class="idle" x1="0" x2={W} y1={H - 6} y2={H - 6} stroke-dasharray="4 6" />
  {:else}
    <defs><linearGradient id="sp{id}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color={color} stop-opacity=".28" /><stop offset="1" stop-color={color} stop-opacity="0" /></linearGradient></defs>
    <path d={p.fill} fill="url(#sp{id})" />
    <path d={p.line} fill="none" stroke={color} stroke-width="2" vector-effect="non-scaling-stroke" />
  {/if}
</svg>
