<script>
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import Blocks from "../lib/Blocks.svelte";
  import Spark from "../lib/Spark.svelte";
  import RangeTabs from "../lib/RangeTabs.svelte";
  import { history, load, key, trimmed } from "../lib/history.svelte.js";
  import Empty from "./Empty.svelte";
  import State from "./State.svelte";
  import { live } from "../lib/live.svelte.js";
  import { t, num, pct, amount, duration } from "../lib/i18n.svelte.js";
  import { tunnelState, transportLabel, isUp } from "../lib/view.js";

  const tunnels = $derived(live.snapshot?.tunnels ?? []);

  function size(bytes) {
    const [value, unit] = amount(bytes ?? 0);
    return `${value} ${unit}`;
  }

  // Each card has its own range; every non-live range is one request for all tunnels.
  let ranges = $state({});
  const rangeOf = (name) => ranges[name] ?? "live";
  const day = $derived(history[key("24h", "tunnels")]?.data);

  $effect(() => {
    const wanted = new Set(["24h", ...Object.values(ranges).filter((r) => r !== "live")]);
    untrack(() => wanted.forEach((r) => load(r, "tunnels")));
    const timer = setInterval(() => wanted.forEach((r) => load(r, "tunnels", true)), 60_000);
    return () => clearInterval(timer);
  });

  function series(name) {
    const range = rangeOf(name);
    if (range === "live") return live.history.map((p) => p.t?.[name]?.[0] ?? 0);
    const data = history[key(range, "tunnels")]?.data;
    const points = data?.tunnels?.[name]?.points;
    return points ? trimmed(points, data.bucket_sec, range !== "30d").map((p) => p.down / data.bucket_sec) : [];
  }

  function uptime(name) {
    const value = day?.tunnels?.[name]?.uptime_24h_pct;
    return value == null ? null : t("upLine", pct(value));
  }

  /** The note under a card for a link that is not working well. */
  function linkNote(x) {
    if (x.state === "failed") return ["bad", t("note").failed];
    if (x.state !== "running") return null;
    const issue = t("note")[x.link_state];
    if (x.link_state === "not_connected") return ["bad", issue];
    if (["no_traffic", "silent", "quota"].includes(x.link_state)) return ["warn", issue];
    return null;
  }

  function carried(x) {
    // [label, technical value shown left to right]
    const parts = [];
    if (x.carry?.ports?.length) parts.push([t("ports"), x.carry.ports.join(", ")]);
    if (x.carry?.socks) parts.push([t("socks"), ""]);
    if (x.carry?.tun) parts.push([t("tun"), ""]);
    if (x.carry?.exits?.length) parts.push([t("exits"), x.carry.exits.join(", ")]);
    return parts;
  }
</script>

{#if live.snapshot}
  {#if tunnels.length === 0}
    <Empty />
  {:else}
    <div class="tgrid">
      {#each tunnels as x, i (x.name)}
        {@const [mark, label] = tunnelState(x)}
        {@const note = linkNote(x)}
        <article class="panel tcard" aria-labelledby="t{i}">
          <div class="hd">
            <div class="grow">
              <div class="title"><h2 id="t{i}" class="ltr">{x.name}</h2>{#if x.transport}<span class="code-chip">{transportLabel(x.transport)}</span>{/if}</div>
              <div class="meta">
                {#if x.side}<span>{t(x.side)}</span><span aria-hidden="true">·</span>{/if}
                {#if x.direction}<span>{t(x.direction)}</span><span aria-hidden="true">·</span>{/if}
                <span class="ltr mono">{x.link}</span>
                {#each carried(x) as [label, value]}<span aria-hidden="true">·</span><span>{label}{#if value}{" "}<span class="ltr">{value}</span>{/if}</span>{/each}
              </div>
            </div>
            <State {mark} {label} />
          </div>
          {#if x.error}
            <div class="note bad" role="note"><Icon name="warn" /><span>{t("unreadable")} <span class="ltr">{x.error}</span></span></div>
          {:else}
            <div class="kv">
              <div><b>{isUp(x) && x.rtt_ms != null ? `${num(x.rtt_ms)} ms` : "-"}</b><span>{t("ping")}</span></div>
              <div><b>{isUp(x) && x.loss_pct != null ? pct(x.loss_pct) : "-"}</b><span>{t("loss")}</span></div>
              <div><b>{isUp(x) && x.uptime_sec != null ? duration(x.uptime_sec) : "-"}</b><span>{t("uptime")}</span></div>
              <div><b>{x.sessions != null ? num(x.sessions) : "-"}</b><span>{t("sessions")}</span></div>
            </div>
            <div class="row-flex">
              <span class="muted small grow">{t("recv")} {size(x.down_total)} · {t("sent")} {size(x.up_total)}</span>
              <RangeTabs value={rangeOf(x.name)} onchange={(r) => (ranges[x.name] = r)} label="{t('rangeLabel')}: {x.name}" />
            </div>
            <div class="spark">
              <Spark values={series(x.name)} active={rangeOf(x.name) !== "live" || x.state === "running"} warn={mark === "warn"} id={i} />
            </div>
            {#if uptime(x.name)}<div class="muted small">{uptime(x.name)}</div>{/if}
            {#if x.quota}
              <div class="limit">
                <div class="q">
                  <span>{t("limit")}</span>
                  <span>{size(x.quota.used)} {t("of")} {size(x.quota.limit)} · {size(Math.max(0, x.quota.limit - x.quota.used))} {t("left")}</span>
                </div>
                <Blocks value={(x.quota.used / x.quota.limit) * 100} cls={x.quota.used >= x.quota.limit * 0.9 ? "big warn" : "big"} />
              </div>
            {/if}
            {#if note}
              <div class="note {note[0]}" role="note"><Icon name="warn" /><span>{note[1]}</span></div>
            {/if}
            {#if x.last_drop && isUp(x)}
              <div class="muted small">{t("lastDrop")} <span class="ltr">{x.last_drop}</span></div>
            {/if}
          {/if}
        </article>
      {/each}
    </div>
  {/if}
{/if}
