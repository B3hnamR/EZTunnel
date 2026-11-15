<script>
  // The transport check between two managed servers: which transports work in which direction,
  // how fast and how steady, with the best one recommended and a tunnel one click away.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import Blocks from "../lib/Blocks.svelte";
  import NewTunnelPanel from "../lib/NewTunnelPanel.svelte";
  import MirageTest from "../lib/MirageTest.svelte";
  import PathFinder from "../lib/PathFinder.svelte";
  import CheckCustom, { presetOptions } from "../lib/CheckCustom.svelte";
  import { startCheck, getCheck, stopCheck, getNewTunnel } from "../lib/api.js";
  import { say } from "../lib/actions.svelte.js";
  import { live } from "../lib/live.svelte.js";
  import { fleet, LOCAL } from "../lib/servers.svelte.js";
  import { t, num, duration, list } from "../lib/i18n.svelte.js";
  import { transportLabel } from "../lib/view.js";

  const places = $derived([
    { id: LOCAL, name: t("thisServerIs", live.snapshot?.host?.hostname ?? ""), address: live.snapshot?.host?.address ?? "", online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, address: s.snapshot?.host?.address ?? "", online: s.online })),
  ]);
  const placeOf = (id) => places.find((p) => p.id === id);

  let f = $state({ iran: LOCAL, foreign: "", iranIp: "", foreignIp: "", iranIpTouched: false, foreignIpTouched: false, preset: "quick", directions: "both", priority: "stability" });
  // Customize starts from the preset chosen last, and keeps its changes while it stays open.
  let base = $state("quick");
  let custom = $state(presetOptions("quick"));
  function pickPreset(v) {
    if (v === "custom" && f.preset !== "custom") {
      base = f.preset;
      custom = presetOptions(base);
    }
    f.preset = v;
  }
  const customBad = $derived(f.preset === "custom" && (!custom.transports.length || (custom.transports.includes("tun") && !custom.tun_profiles.length) || (custom.pings === 0 && !custom.download && !custom.upload && !custom.parallel && custom.hold_sec === 0 && !custom.udp)));
  // Pick the first joined server once the list arrives, and follow each server's address.
  $effect(() => {
    if (!f.foreign) {
      const first = places.find((p) => p.id !== LOCAL && p.online);
      if (first) untrack(() => (f.foreign = first.id));
    }
  });
  $effect(() => {
    const iran = placeOf(f.iran)?.address ?? "";
    const foreign = placeOf(f.foreign)?.address ?? "";
    untrack(() => {
      if (!f.iranIpTouched) f.iranIp = iran;
      if (!f.foreignIpTouched) f.foreignIp = foreign;
    });
  });

  function pickEnd(field, value) {
    f[field] = value;
    const ipField = field === "iran" ? "iranIp" : "foreignIp";
    const touchedField = `${ipField}Touched`;
    f[touchedField] = false;
    f[ipField] = placeOf(value)?.address ?? "";
  }

  let state = $state(null);
  let starting = $state(false);
  let stopping = $state(false);
  let problem = $state("");
  let creatable = $state([]);

  async function poll() {
    try {
      const { status, data } = await getCheck();
      if (status === 200) state = data;
    } catch {}
  }
  $effect(() => {
    untrack(poll);
    getNewTunnel().then(({ status, data }) => {
      if (status === 200) creatable = data.transports.map((x) => x.name);
    });
    const timer = setInterval(poll, 2000);
    return () => clearInterval(timer);
  });

  const running = $derived(state?.state === "running");
  const rows = $derived(state?.view?.rows ?? state?.report?.cases ?? []);
  const done = $derived(rows.filter((r) => r.verdict).length);
  const best = $derived((state?.best ?? []).map((id) => rows.find((r) => r.spec.id === id)).filter(Boolean));

  async function start() {
    starting = true;
    problem = "";
    try {
      const { status, data } = await startCheck({
        iran: f.iran, foreign: f.foreign, iran_ip: f.iranIp.trim(), foreign_ip: f.foreignIp.trim(),
        preset: f.preset === "custom" ? base : f.preset, directions: f.directions, priority: f.priority,
        custom: f.preset === "custom" ? custom : null,
      });
      if (status !== 200) problem = data?.detail ?? t("failedShort");
      else poll();
    } catch {
      problem = t("slowShort");
    } finally {
      starting = false;
    }
  }

  async function stop() {
    if (stopping) return;
    stopping = true;
    try {
      const { status, data } = await stopCheck();
      if (status === 200) say(t("ctStopping"));
      else say(data?.detail ?? t("failedShort"), true);
    } catch {
      say(t("slowShort"), true);
    } finally {
      stopping = false;
    }
  }

  const VERDICT_LEVEL = { works: "ok", reachable: "ok", unstable: "warn", slow: "warn", "download-only": "warn", "upload-only": "warn" };
  const level = (v) => (v ? VERDICT_LEVEL[v] ?? (v === "skipped" || v === "stopped" ? "off" : "bad") : "off");
  const name = (r) => `${transportLabel(r.spec.transport)}${r.spec.profile ? ` ${String(r.spec.profile).toUpperCase()}` : ""}${r.spec.variant && r.spec.variant !== "plain" ? ` · ${t("variant")[r.spec.variant] ?? r.spec.variant}` : ""}`;
  const dialer = (r) => (r.spec.dialer === "foreign" ? t("dialForeign") : r.spec.dialer === "iran" ? t("dialIran") : t("dialBoth"));
  const topSpeed = $derived(Math.max(1, ...rows.flatMap((r) => [r.download?.mbps ?? 0, r.upload?.mbps ?? 0])));
  const mbps = (x) => (x?.mbps != null && !x.error ? `${num(x.mbps)} Mbit/s` : "-");

  // A tunnel from a result: the transport, the direction and the port that worked.
  let creating = $state(false);
  let prefill = $state(null);
  function createFrom(r) {
    const direction = r.spec.dialer === "iran" ? "direct" : "reverse";
    const iranId = state?.iran ?? f.iran;
    const foreignId = state?.foreign ?? f.foreign;
    prefill = {
      iran: iranId, foreign: foreignId, transport: r.spec.transport, direction,
      port: r.port ? String(r.port) : undefined,
      address: direction === "reverse" ? state?.report?.iran_ip ?? state?.view?.iran_ip : state?.report?.foreign_ip ?? state?.view?.foreign_ip,
    };
    creating = true;
  }
  const usable = (r) => ["works", "reachable", "slow", "unstable"].includes(r.verdict);
  const canCreate = (r) => creatable.includes(r.spec.transport) && (!r.spec.variant || r.spec.variant === "plain") && usable(r);
  // Raw-socket, TUN, Parallax and Mirage tunnels need choices on the machine itself.
  const terminalOnly = (r) => usable(r) && !canCreate(r);
</script>

{#if !running}<PathFinder />{/if}

{#if !running}
  <section class="panel mb16 ct-sec" aria-labelledby="ct-form">
    <div class="sec-row"><span class="ct-ico"><Icon name="conntest" /></span><h3 id="ct-form" class="sec-h grow m0">{t("ctNew")}</h3></div>
    <p class="muted small">{t("ctAbout")}</p>
    <div class="ct-route">
      <div class="ct-end">
        <span class="eyebrow"><span class="mark ok"></span>{t("iranEnd")}</span>
        <label class="sr" for="ct-iran">{t("iranEnd")}</label>
        <select id="ct-iran" class="input" value={f.iran} onchange={(e) => pickEnd("iran", e.currentTarget.value)}>{#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}</select>
        <label class="flabel m0" for="ct-iip">{t("ctIranIp")}</label>
        <input id="ct-iip" class="input ltr" bind:value={f.iranIp} oninput={() => (f.iranIpTouched = true)} autocomplete="off" spellcheck="false" />
      </div>
      <div class="ct-wire link live" aria-hidden="true"><span class="wire"><i></i></span></div>
      <div class="ct-end">
        <span class="eyebrow"><span class="mark ok"></span>{t("foreignEnd")}</span>
        <label class="sr" for="ct-foreign">{t("foreignEnd")}</label>
        <select id="ct-foreign" class="input" value={f.foreign} onchange={(e) => pickEnd("foreign", e.currentTarget.value)}>{#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}</select>
        <label class="flabel m0" for="ct-fip">{t("ctForeignIp")}</label>
        <input id="ct-fip" class="input ltr" bind:value={f.foreignIp} oninput={() => (f.foreignIpTouched = true)} autocomplete="off" spellcheck="false" />
      </div>
    </div>
    <div class="ct-opts">
      {#each [["ct-preset", "ctPreset", "preset", [["quick", "ctQuick"], ["standard", "ctStandard"], ["thorough", "ctThorough"], ["custom", "ctCustom"]]], ["ct-dir", "ctDirections", "directions", [["both", "ctBoth"], ["foreign", "dirReverse"], ["iran", "dirDirect"]]], ["ct-pri", "ctPriority", "priority", [["stability", "ctStability"], ["speed", "ctSpeed"], ["hiding", "ctHiding"], ["lossy", "ctLossy"]]]] as [id, label, field, opts] (id)}
        <div>
          <span class="flabel" id="{id}-l">{t(label)}</span>
          <div class="ct-list" role="group" aria-labelledby="{id}-l">
            {#each opts as [v, k]}<button type="button" aria-pressed={f[field] === v} onclick={() => (field === "preset" ? pickPreset(v) : (f[field] = v))}>{t(k)}</button>{/each}
          </div>
        </div>
      {/each}
    </div>
    {#if f.preset === "custom"}
      <div class="ct-custom mt16">
        <CheckCustom bind:value={custom} dirs={f.directions === "both" ? 2 : 1} />
      </div>
    {/if}
    <p class="muted small mt12 m0">{t("ctPortsNote")}</p>
    {#if places.length < 2}<div class="note warn mt12" role="note"><Icon name="warn" /><span>{t("needAgent")}</span></div>{/if}
    {#if problem}<div class="note bad mt12" role="alert"><Icon name="warn" /><span>{t("ctFailed")} <span class="ltr">{problem}</span></span></div>{/if}
    <div class="row-flex mt16">
      <button class="btn primary ct-go" onclick={start} disabled={starting || customBad || !f.foreign || f.iran === f.foreign || !f.iranIp || !f.foreignIp} aria-busy={starting}>
        <Icon name="conntest" />{starting ? t("ctStarting") : t("ctStart")}
      </button>
    </div>
  </section>
{/if}

{#if state && state.state !== "idle"}
  <section class="panel" aria-labelledby="ct-res">
    <div class="row-flex mb16">
      <h3 id="ct-res" class="sec-h grow m0">{running ? t("ctRunning") : state.state === "failed" ? t("ctEndedBad") : t("ctResults")}</h3>
      {#if running}<button class="btn danger" onclick={stop} disabled={stopping} aria-busy={stopping}><Icon name="stop" />{t("stop")}</button>{/if}
    </div>
    {#if running}
      <div class="ct-progress" role="status">
        <Blocks value={rows.length ? (done / rows.length) * 100 : 0} cls="big" />
        <span class="muted small">{state.view?.step} · {t("ctDone", num(done), num(rows.length))}{state.view?.remaining_sec ? ` · ${t("ctLeft", duration(state.view.remaining_sec))}` : ""}</span>
      </div>
    {/if}
    {#if running && state.view?.path_hint && !state.view?.connected}<div class="note warn mb16" role="note"><Icon name="warn" /><span class="ltr edesc">{state.view.path_hint}</span></div>{/if}
    {#if state.state === "failed"}<div class="note bad mb16" role="alert"><Icon name="warn" /><span>{state.error}</span></div>{/if}
    {#if state.report?.stopped}<div class="note warn mb16" role="note"><Icon name="warn" /><span>{t("ctStopped")} {state.report.stopped}</span></div>{/if}

    {#if !running && best.length}
      <div class="note info act mb16" role="note">
        <Icon name="check" />
        <div class="grow">
          <b>{t("ctBest", name(best[0]), dialer(best[0]))}</b>
          {#if best.length > 1}<div class="small">{t("ctAlso")} {list(best.slice(1, 4).map((r) => `${name(r)} (${dialer(r)})`))}</div>{/if}
        </div>
        {#if canCreate(best[0])}<button class="btn primary" onclick={() => createFrom(best[0])}><Icon name="plus" />{t("ctCreate")}</button>{/if}
      </div>
      {#if terminalOnly(best[0])}<p class="muted small mt-n8 mb16">{t("ctTerminalOnly", name(best[0]))}</p>{/if}
    {:else if !running && state.state === "finished"}
      <div class="note warn mb16" role="note"><Icon name="warn" /><span>{t("ctNone")}</span></div>
    {/if}

    <div class="table-wrap">
      <table class="speed ct-table">
        <thead>
          <tr><th scope="col">{t("transport")}</th><th scope="col">{t("ctWho")}</th><th scope="col">{t("ctVerdict")}</th><th scope="col">{t("ping")}</th><th scope="col">{t("downTest")} <span class="muted">Mbit/s</span></th><th scope="col">{t("upTest")} <span class="muted">Mbit/s</span></th><th scope="col"><span class="sr">{t("actionsOf")}</span></th></tr>
        </thead>
        <tbody>
          {#each rows as r (r.spec.id)}
            <tr class:current={running && state.view?.current === r.spec.id}>
              <th scope="row"><span class="ltr">{name(r)}</span></th>
              <td>{dialer(r)}</td>
              <td>
                <span class="pill {running && state.view?.current === r.spec.id && !r.verdict ? 'live' : level(r.verdict)}">{r.verdict ? t("verdicts")[r.verdict] ?? r.verdict : running && state.view?.current === r.spec.id ? t("testing") : t("ctWaiting")}</span>
                {#if r.note}<div class="muted small ltr edesc">{r.note}</div>{/if}
              </td>
              <td>{r.rtt_ms != null ? `${num(r.rtt_ms)} ms` : r.ping?.median_ms != null ? `${num(r.ping.median_ms)} ms` : r.handshake_ms != null ? `${num(r.handshake_ms)} ms*` : "-"}</td>
              <td>{@render speed(r.download)}</td>
              <td>{@render speed(r.upload)}</td>
              <td>{#if !running && canCreate(r)}<button class="btn ghost" onclick={() => createFrom(r)}>{t("ctCreateShort")}</button>{:else if !running && terminalOnly(r)}<span class="muted small ct-term" title={t("ctTerminalOnly", name(r))}>{t("ctTerminalShort")}</span>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="muted small m0 mt12">{t("ctLegend")}</p>
    {#snippet speed(x)}
      {#if x?.mbps != null && !x.error}
        <div class="ct-speed"><span class="num">{num(x.mbps)}</span><svg viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true"><rect class="t" width="100" height="4" rx="2" /><rect class="f" width={Math.max(2, (x.mbps / topSpeed) * 100)} height="4" rx="2" /></svg></div>
      {:else}<span class="muted">-</span>{/if}
    {/snippet}
  </section>
{/if}

<MirageTest />

<NewTunnelPanel open={creating} {prefill} onclose={() => (creating = false)} />
