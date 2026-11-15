<script>
  // The signature: two servers joined by a line whose drawing shows the link's state.
  // state: ok (solid), live (moving dash, connecting), warn (dashed), down (dotted).
  let { from, to, label = "", state = "ok", title = "" } = $props();
</script>

<div class="link {state}" title={title || undefined}>
  <span class="end"><b>{from}</b></span>
  <span class="dot"></span>
  <span class="wire"><i></i>{#if label}<span class="mono ltr">{label}</span>{/if}<i></i></span>
  <span class="dot"></span>
  <span class="end"><b class="ltr">{String(to ?? "").replace(/^→\s*/, "")}</b></span>
</div>
