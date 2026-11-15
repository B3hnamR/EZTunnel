<script>
  // A thin meter. The fill is an SVG attribute, since the page allows no inline styles.
  let { value = 0, cls = "" } = $props();
  const w = $derived(Math.max(0, Math.min(100, value ?? 0)));
</script>

<div class="blocks {cls}" aria-hidden="true">
  <svg viewBox="0 0 100 1" preserveAspectRatio="none"><rect class="bar" width={w} height="1" /></svg>
</div>
