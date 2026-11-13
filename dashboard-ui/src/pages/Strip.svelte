<script>
  import Blocks from "../lib/Blocks.svelte";
  import { t, num, pct, rate } from "../lib/i18n.svelte.js";
  let { host } = $props();
  const meters = $derived([
    ["cpu", host.cpu_pct, ""],
    ["ram", host.mem_pct, "violet"],
    ["disk", host.disk_pct, ""],
  ]);
</script>

<section class="panel strip" aria-label={t("thisServer")}>
  <div class="who">
    <span class="muted small">{t("thisServer")}</span>
    <b class="ltr">{host.hostname}</b>
    {#if host.address}<span class="muted small ltr">{host.address}</span>{/if}
  </div>
  {#each meters as [key, value, cls]}
    <div>
      <div class="k"><span>{t(key)}</span><span>{value == null ? "-" : pct(value, 0)}</span></div>
      <Blocks value={value ?? 0} {cls} />
    </div>
  {/each}
  <div>
    <div class="k"><span>{t("up")} / {t("down")}</span></div>
    <div class="v">
      <span class="ltr">{host.tx_bps == null ? "-" : rate(host.tx_bps)} / {host.rx_bps == null ? "-" : rate(host.rx_bps)}</span>
      <span class="muted small">Mb/s</span>
    </div>
  </div>
  <div>
    <div class="k"><span>{t("uptime")}</span></div>
    <div class="v">{host.uptime_sec == null ? "-" : num(Math.floor(host.uptime_sec / 86400))} <span class="muted small">{t("days")}</span></div>
  </div>
</section>
