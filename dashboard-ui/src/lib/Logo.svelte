<script>
  import { LOGO } from "./logo.js";
  // The block wordmark, flat in the current text colour.
  let { id = "" } = $props();
</script>

<svg viewBox="0 0 {LOGO.width} {LOGO.height}" role="img" aria-label="EZTunnel" data-logo={id}>
  <g fill="currentColor">
    {#each LOGO.rects as r}<rect x={r.x} y={r.y} width={r.w} height={r.h} />{/each}
  </g>
</svg>
