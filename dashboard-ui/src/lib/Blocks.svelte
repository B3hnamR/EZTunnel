<script>
  // The identity motif: a 10-segment block meter.
  let { value = 0, cls = "" } = $props();
  const on = $derived(Math.max(0, Math.min(10, Math.round((value ?? 0) / 10))));
</script>

<div class="blocks {cls}" aria-hidden="true">
  {#each Array(10) as _, i}<i class:on={i < on}></i>{/each}
</div>
