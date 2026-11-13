<script>
  import { areaPaths } from "./chart.js";
  // Received (cyan, solid) and sent (violet, dashed) over the live window.
  let { recv = [], sent = [], label, id = "c" } = $props();
  const W = 900;
  const H = 220;
  const max = $derived(Math.max(1, ...recv, ...sent));
  const a = $derived(areaPaths(recv, W, H, max));
  const b = $derived(areaPaths(sent, W, H, max));
</script>

<svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" role="img" aria-label={label}>
  <defs>
    <linearGradient id="ar{id}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#00d7ff" stop-opacity=".28" /><stop offset="1" stop-color="#00d7ff" stop-opacity="0" /></linearGradient>
    <linearGradient id="as{id}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#875fff" stop-opacity=".28" /><stop offset="1" stop-color="#875fff" stop-opacity="0" /></linearGradient>
  </defs>
  {#each [1, 2, 3] as i}<line class="gridline" x1="0" x2={W} y1={(i * H) / 4} y2={(i * H) / 4} />{/each}
  <path d={a.fill} fill="url(#ar{id})" />
  <path d={a.line} fill="none" stroke="#00d7ff" stroke-width="2" vector-effect="non-scaling-stroke" />
  <path d={b.fill} fill="url(#as{id})" />
  <path d={b.line} fill="none" stroke="#875fff" stroke-width="2" stroke-dasharray="5 5" vector-effect="non-scaling-stroke" />
</svg>
