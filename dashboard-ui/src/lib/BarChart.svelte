<script>
  // Daily totals for the 30-day range; the newest day is drawn full strength.
  let { values = [], label, height = 220 } = $props();
  const W = 900;
  const max = $derived(Math.max(1, ...values));
  const bw = $derived(values.length ? W / values.length : W);
</script>

<svg viewBox="0 0 {W} {height}" preserveAspectRatio="none" role="img" aria-label={label}>
  {#each [1, 2, 3] as i}<line class="gridline" x1="0" x2={W} y1={(i * height) / 4} y2={(i * height) / 4} />{/each}
  {#each values as v, i}
    {@const h = (v / (max * 1.1)) * height}
    <rect class="bar" class:last={i === values.length - 1} x={i * bw + bw * 0.12} y={height - h} width={bw * 0.76} height={h} rx="2" />
  {/each}
</svg>
