<script>
  // Every log in one place: each tunnel's log on this or a joined server, and the dashboard's own
  // activity. A server with no tunnels (a dashboard that only manages others) still has its
  // activity here.
  import LogView from "../lib/LogView.svelte";
  import ServerPicker from "../lib/ServerPicker.svelte";
  import Activity from "./Activity.svelte";
  import { live } from "../lib/live.svelte.js";
  import { fleet, serverById, LOCAL } from "../lib/servers.svelte.js";
  import { t } from "../lib/i18n.svelte.js";

  let { tunnel = "", source = "", server = LOCAL } = $props();

  const remote = $derived(server !== LOCAL);
  const tunnels = $derived(remote ? serverById(server)?.snapshot?.tunnels ?? [] : live.snapshot?.tunnels ?? []);
  const names = $derived(tunnels.map((x) => x.name));
  let chosen = $state("");
  const name = $derived(names.includes(chosen) ? chosen : names.includes(tunnel) ? tunnel : names[0] ?? "");
  let picked = $state("");
  const tab = $derived(picked || (source === "activity" || (!tunnel && !remote && names.length === 0) ? "activity" : "tunnel"));

  function show(next) {
    picked = next;
    history.replaceState(null, "", next === "activity" ? "#/logs?v=activity" : remote ? `#/logs?s=${encodeURIComponent(server)}` : "#/logs");
  }
</script>

<div class="tabs mb16 src-tabs" role="tablist" aria-label={t("logSources")}>
  <button role="tab" id="tab-tunnel" aria-controls="panel-tunnel" aria-selected={tab === "tunnel"} onclick={() => show("tunnel")}>{t("tunnelLogs")}</button>
  <button role="tab" id="tab-activity" aria-controls="panel-activity" aria-selected={tab === "activity"} onclick={() => show("activity")}>{t("activity")}</button>
</div>

{#if tab === "tunnel" && fleet.list.length}<ServerPicker value={server} route="logs" />{/if}

<div class="panel" role="tabpanel" id="panel-{tab}" aria-labelledby="tab-{tab}">
  {#if tab === "activity"}
    <Activity />
  {:else if names.length === 0}
    <div class="act-empty">
      <b>{remote ? t("noTunnelsThere") : t("noTunnelLogsT")}</b>
      <p class="muted m0">{t("noTunnelLogs")}</p>
    </div>
  {:else}
    {#key name + server}<LogView {name} {names} {server} onpick={(n) => (chosen = n)} uid="page" />{/key}
  {/if}
</div>
