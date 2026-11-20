<script>
  import { localName } from "../lib/servers.svelte.js";
  // This server at a glance: who it is, how loaded it is (rings with a short trend under each),
  // and what its network is doing right now.
  import { untrack } from "svelte";
  import Ring from "../lib/Ring.svelte";
  import Spark from "../lib/Spark.svelte";
  import { hostHist, record } from "../lib/hosthist.svelte.js";
  import { live } from "../lib/live.svelte.js";
  import { t, num, pct, rate, amount, duration } from "../lib/i18n.svelte.js";
  let { host } = $props();

  // Only a new snapshot records; the history itself is not a dependency.
  $effect(() => {
    const at = live.snapshot?.at;
    const h = host;
    untrack(() => record(at, h));
  });

  const size = (b) => (b ? amount(b).join(" ") : "");
  const gauges = $derived([
    ["cpu", host.cpu_pct, hostHist.cpu, host.cores ? t("coresN", num(host.cores)) : ""],
    ["ram", host.mem_pct, hostHist.mem, host.mem_total ? t("ofSize", size(host.mem_total)) : ""],
    ["disk", host.disk_pct, null, host.disk_total ? t("ofSize", size(host.disk_total)) : ""],
  ]);
  const facts = $derived([host.os, host.kernel && `Linux ${host.kernel}`, host.congestion && host.congestion.toUpperCase(), live.snapshot?.version && `EZTunnel ${live.snapshot.version}`].filter(Boolean));
</script>

<section class="panel strip" aria-label={t("thisServer")}>
  <div class="who">
    <span class="eyebrow"><span class="mark ok"></span>{t("thisServer")}</span>
    <b class="ltr">{localName(host.hostname)}</b>
    {#if host.address}<span class="addr ltr">{host.address}</span>{/if}
    {#if facts.length}
      <div class="facts-row">{#each facts as f}<span class="code-chip ltr">{f}</span>{/each}</div>
    {/if}
  </div>

  <div class="gauges">
    {#each gauges as [key, value, trend, sub] (key)}
      <div class="gauge">
        <Ring {value} label={t(key)} id={"s" + key} />
        <div class="gauge-v">
          <span class="k">{t(key)}</span>
          {#if sub}<span class="sub ltr">{sub}</span>{/if}
          {#if trend}<div class="spark mini"><Spark values={trend} id={"h" + key} warn={(value ?? 0) >= 80} /></div>{:else}<div class="gauge-free small muted">{value == null ? "" : t("freePct", pct(100 - value, 0))}</div>{/if}
        </div>
      </div>
    {/each}
  </div>

  <div class="net">
    <div class="net-row">
      <span class="dir up" aria-hidden="true">↑</span>
      <div class="grow"><span class="k">{t("up")}</span><span class="v num ltr">{host.tx_bps == null ? "-" : rate(host.tx_bps)}<small>Mb/s</small></span></div>
      <div class="spark mini"><Spark values={hostHist.tx} id="htx" /></div>
    </div>
    <div class="net-row">
      <span class="dir down" aria-hidden="true">↓</span>
      <div class="grow"><span class="k">{t("down")}</span><span class="v num ltr">{host.rx_bps == null ? "-" : rate(host.rx_bps)}<small>Mb/s</small></span></div>
      <div class="spark mini"><Spark values={hostHist.rx} id="hrx" /></div>
    </div>
    <div class="uptime"><span class="k">{t("uptime")}</span><span class="num">{host.uptime_sec == null ? "-" : duration(host.uptime_sec)}</span></div>
  </div>
</section>
