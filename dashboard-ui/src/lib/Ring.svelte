<script>
  // A ring gauge for a percentage: a tick scale, a lit arc with a marker at its end, and the figure
  // in the middle. Drawn with SVG attributes only (the page allows no inline styles).
  // `tone` overrides the usage colours (high = bad) for a ring where high is good, like a score.
  let { value = null, label = "", id = "r", tone: forced = null } = $props();
  const R = 30;
  const C = 2 * Math.PI * R;
  const v = $derived(value == null ? 0 : Math.max(0, Math.min(100, value)));
  const tone = $derived(forced ?? (v >= 92 ? "bad" : v >= 80 ? "warn" : ""));
  const angle = $derived(((v / 100) * 360 - 90) * (Math.PI / 180));
  const end = $derived([40 + R * Math.cos(angle), 40 + R * Math.sin(angle)]);
</script>

<svg class="ring {tone}" viewBox="0 0 80 80" role="img" aria-label="{label} {value == null ? '-' : Math.round(v) + '%'}">
  <defs>
    <linearGradient id="rg{id}" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" class="rg-a" />
      <stop offset="1" class="rg-b" />
    </linearGradient>
  </defs>
  <circle class="ring-ticks" cx="40" cy="40" r="37.5" />
  <circle class="ring-track" cx="40" cy="40" r={R} />
  {#if value != null && v > 0}
    <circle class="ring-arc" cx="40" cy="40" r={R} stroke="url(#rg{id})" stroke-dasharray="{(v / 100) * C} {C}" transform="rotate(-90 40 40)" />
    <!-- A full ring has no end to mark: the dot would sit on the seam at the top. -->
    {#if v < 99.5}<circle class="ring-end" cx={end[0]} cy={end[1]} r="3.2" />{/if}
  {/if}
  <text class="ring-num" x="40" y="40" text-anchor="middle" dominant-baseline="central">{value == null ? "-" : Math.round(v)}<tspan class="ring-pct" dx="1" dy="-6">%</tspan></text>
</svg>
