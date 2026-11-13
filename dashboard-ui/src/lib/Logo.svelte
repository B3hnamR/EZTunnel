<script>
  import { LOGO } from "./logo.js";
  let { id } = $props();
</script>

<svg viewBox="-6 -6 {LOGO.width + 12} {LOGO.height + 12}" role="img" aria-label="EZTunnel">
  <defs>
    <linearGradient id="g{id}" x1="0" x2={LOGO.width} gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#00ffff" />
      <stop offset=".3" stop-color="#00afff" />
      <stop offset=".62" stop-color="#5f5fff" />
      <stop offset="1" stop-color="#d75fff" />
    </linearGradient>
    <filter id="b{id}"><feGaussianBlur stdDeviation="7" /></filter>
  </defs>
  <g filter="url(#b{id})" opacity=".45" fill="url(#g{id})">
    {#each LOGO.rects as r}<rect x={r.x} y={r.y} width={r.w} height={r.h} />{/each}
  </g>
  <g fill="url(#g{id})">
    {#each LOGO.rects as r}<rect x={r.x} y={r.y} width={r.w} height={r.h} />{/each}
  </g>
  <path d={LOGO.path} fill="none" stroke="url(#g{id})" stroke-width="1.6" stroke-linecap="round" opacity=".5" />
</svg>
