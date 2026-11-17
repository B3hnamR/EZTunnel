<script>
  // Customize a transport check the way the terminal checker allows: which transports and raw TUN
  // packet types, which measurements, which extra variants, the ports and the slow threshold.
  // `value` holds the choices; it starts from the preset that was selected.
  import { t, num } from "./i18n.svelte.js";
  import { transportLabel } from "./view.js";

  /** `tune`: a tune check, whose transports are chosen on the page and which runs every option;
   *  the panel then offers the rounds instead of the extra variants. */
  let { value = $bindable(), dirs = 2, tune = false, tuned = [], family = "ipv4" } = $props();

  const STANDARD = ["tcp", "wss", "https", "xhttps", "ws", "http", "xhttp", "kcp", "parallax", "fec-udp"];
  const PROFILES = ["tcp", "udp", "icmp", "gre", "ipip", "raw", "dns"];
  const TLS = ["wss", "https", "xhttps"];
  const TCPISH = ["tcp", "wss", "https", "xhttps", "ws", "http", "xhttp", "parallax"];
  const FEC = ["fec-udp", "fec-raw", "fec-raw-gaming"];

  const eligible = $derived(transportsFor(family));
  const selected = $derived(value.transports.filter((x) => eligible.some(([n]) => n === x)));
  const has = (x) => selected.includes(x);
  function toggle(x) {
    value.transports = has(x) ? value.transports.filter((y) => y !== x) : TRANSPORTS.map(([n]) => n).filter((n) => n === x || value.transports.includes(n));
  }
  function toggleProfile(p) {
    value.tun_profiles = value.tun_profiles.includes(p) ? value.tun_profiles.filter((x) => x !== p) : PROFILES.filter((x) => x === p || value.tun_profiles.includes(x));
  }
  const anyTls = $derived(selected.some((x) => TLS.includes(x)));
  const anyTcp = $derived(selected.some((x) => TCPISH.includes(x)));
  const anyFec = $derived(selected.some((x) => FEC.includes(x)));
  const anyGame = $derived(selected.some((x) => !RAW.includes(x)));
  const speed = $derived(value.download || value.upload || value.parallel);
  // What it adds up to: one case per transport, direction and variant (TUN: per packet type).
  const n = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.round(+v || 0)));
</script>

<div class="cc">
  <section class="cc-col" aria-labelledby="cc-tr">
    {#if !tune}
    <div class="cc-h"><h4 id="cc-tr">{t(family === "ipv6" ? "ntOverIpv6" : "ccTransports")}</h4>
      <span class="cc-quick">
        <button type="button" class="btn ghost sm" onclick={() => (value.transports = eligible.map(([x]) => x))}>{t("ccAll")}</button>
        <button type="button" class="btn ghost sm" onclick={() => (value.transports = STANDARD.slice())}>{t("ccStandardSet")}</button>
      </span>
    </div>
    <div class="cc-grid">
      {#each eligible as [x, note] (x)}
        <label class="chk cc-chk" class:on={has(x)} title={note ? t(note) : ""}>
          <input type="checkbox" checked={has(x)} onchange={() => toggle(x)} />
          <span class="ltr">{transportLabel(x)}</span>{#if note}<i class="cc-dot" aria-hidden="true"></i>{/if}
        </label>
      {/each}
    </div>
    {#if family !== "ipv6"}<p class="muted small m0"><i class="cc-dot" aria-hidden="true"></i> {t("ccRootNote")}</p>{/if}
    {/if}
    {#if tune ? tuned.includes("tun") : has("tun")}
      <div class="cc-sub">
        <span class="flabel m0">{t("ccTunTypes")}</span>
        <div class="cc-grid tight">
          {#each PROFILES as p (p)}
            <label class="chk cc-chk" class:on={value.tun_profiles.includes(p)}><input type="checkbox" checked={value.tun_profiles.includes(p)} onchange={() => toggleProfile(p)} /><span class="ltr">{p.toUpperCase()}</span></label>
          {/each}
        </div>
      </div>
    {/if}
  </section>

  <section class="cc-col" aria-labelledby="cc-ms">
    <div class="cc-h"><h4 id="cc-ms">{t("ccMeasure")}</h4></div>
    <div class="cc-row">
      <label class="chk"><input type="checkbox" checked={value.pings > 0} onchange={(e) => (value.pings = e.currentTarget.checked ? 10 : 0)} /><span>{t("ccPings")}</span></label>
      {#if value.pings > 0}<input class="input cc-num ltr" type="number" min="1" max="100" value={value.pings} onchange={(e) => (value.pings = n(e.currentTarget.value, 1, 100))} aria-label={t("ccPingsN")} />{/if}
    </div>
    <label class="chk"><input type="checkbox" bind:checked={value.download} /><span>{t("ccDownload")}</span></label>
    <label class="chk"><input type="checkbox" bind:checked={value.upload} /><span>{t("ccUpload")}</span></label>
    <label class="chk"><input type="checkbox" bind:checked={value.parallel} /><span>{t("ccParallel")}</span></label>
    {#if speed}
      <div class="cc-row sub"><span class="small muted">{t("ccSpeedSec")}</span><input class="input cc-num ltr" type="number" min="1" max="60" value={value.speed_sec} onchange={(e) => (value.speed_sec = n(e.currentTarget.value, 1, 60))} aria-label={t("ccSpeedSec")} /></div>
    {/if}
    <div class="cc-row">
      <label class="chk"><input type="checkbox" checked={value.hold_sec > 0} onchange={(e) => (value.hold_sec = e.currentTarget.checked ? 30 : 0)} /><span>{t("ccHold")}</span></label>
      {#if value.hold_sec > 0}<input class="input cc-num ltr" type="number" min="1" max="600" value={value.hold_sec} onchange={(e) => (value.hold_sec = n(e.currentTarget.value, 1, 600))} aria-label={t("ccHoldSec")} />{/if}
    </div>
    <label class="chk"><input type="checkbox" bind:checked={value.udp} /><span>{t("ccUdp")}</span></label>
    <label class="chk"><input type="checkbox" bind:checked={value.mtu} /><span>{t("ccMtu")}</span></label>
    <label class="chk"><input type="checkbox" bind:checked={value.repeat_failed} /><span>{t("ccRepeat")}</span></label>
  </section>

  <section class="cc-col" aria-labelledby="cc-vr">
    {#if tune}
      <div class="cc-h"><h4 id="cc-vr">{t("ccRounds")}</h4></div>
      <div class="cc-row"><span class="small muted">{t("ccRoundsHelp")}</span><input class="input cc-num ltr" type="number" min="1" max="3" value={value.rounds ?? 2} onchange={(e) => (value.rounds = n(e.currentTarget.value, 1, 3))} aria-label={t("ccRounds")} /></div>
    {:else}
    <div class="cc-h"><h4 id="cc-vr">{t("ccVariants")}</h4></div>
    <label class="chk" class:off={!anyTls}><input type="checkbox" bind:checked={value.browser_tls} disabled={!anyTls} /><span>{t("ccBrowserTls")}</span></label>
    <label class="chk" class:off={!anyTls}><input type="checkbox" bind:checked={value.tls_fragment} disabled={!anyTls} /><span>{t("ccTlsFragment")}</span></label>
    <label class="chk" class:off={!anyTcp}><input type="checkbox" bind:checked={value.also_congestion} disabled={!anyTcp} /><span>{t("ccCongestion")}</span></label>
    <label class="chk" class:off={!anyFec}><input type="checkbox" bind:checked={value.also_pacer} disabled={!anyFec} /><span>{t("ccPacer")}</span></label>
    <label class="chk" class:off={!has("tun")}><input type="checkbox" bind:checked={value.also_fragment} disabled={!has("tun")} /><span>{t("ccTunFragment")}</span></label>
    <label class="chk" class:off={!has("parallax")}><input type="checkbox" bind:checked={value.parallax_packet} disabled={!has("parallax")} /><span>{t("ccParallaxPacket")}</span></label>
    <label class="chk" class:off={!anyGame}><input type="checkbox" bind:checked={value.also_game} disabled={!anyGame} /><span>{t("ccGame")}</span></label>
    {/if}

    <div class="cc-h mt12"><h4>{t("ccPorts")}</h4></div>
    <div class="cc-ports">
      <label><span class="flabel">{t("ccTlsPort")}</span><input class="input ltr" type="number" min="0" max="65535" value={value.tls_port} onchange={(e) => (value.tls_port = n(e.currentTarget.value, 0, 65535))} /></label>
      <label><span class="flabel">{t("ccOtherPort")}</span><input class="input ltr" type="number" min="0" max="65535" value={value.port} onchange={(e) => (value.port = n(e.currentTarget.value, 0, 65535))} /></label>
    </div>
    <p class="muted small m0">{t("ccPortsHelp")}</p>
    <label class="cc-slow"><span class="flabel">{t("ccSlow")}</span><input class="input ltr cc-num" type="number" min="0" max="10000" value={value.slow_mbps} onchange={(e) => (value.slow_mbps = n(e.currentTarget.value, 0, 10000))} /></label>
  </section>
</div>
{#if !tune && !selected.length}<p class="small bad-t m0 mt8">{t("ccNoTransport")}</p>{/if}
{#if (tune ? tuned.includes("tun") : has("tun")) && !value.tun_profiles.length}<p class="small bad-t m0 mt8">{t("ccNoTunType")}</p>{/if}
{#if value.pings === 0 && !speed && value.hold_sec === 0 && !value.udp}<p class="small bad-t m0 mt8">{t("ccNoMeasure")}</p>{/if}
<p class="muted small m0 mt8">{t("ccCases", num(tune ? tuneCount(tuned, value, dirs, family) : caseCount({ ...value, transports: selected }, dirs, family)))}</p>

<script module>
  /** Every transport the checker has, with a note for the ones that need root and IPv4. */
  const TRANSPORTS = [
    ["tcp", ""], ["wss", ""], ["https", ""], ["xhttps", ""], ["ws", ""], ["http", ""], ["xhttp", ""], ["kcp", ""],
    ["fec-udp", ""], ["parallax", ""], ["fec-raw", "ccRootV4"], ["tun", "ccRootV4"],
  ];
  const RAW = ["fec-raw", "fec-raw-gaming", "tun"];

  export function transportsFor(family) {
    return family === "ipv6" ? TRANSPORTS.filter(([x]) => !RAW.includes(x)) : TRANSPORTS;
  }

  /** The options a tune check tries for a transport besides its defaults, as the checker lists them. */
  export function tuneVariants(x) {
    const out = [];
    if (["wss", "https", "xhttps"].includes(x)) out.push("browser-tls", "tls-fragment");
    if (!RAW.includes(x) && !["kcp", "fec-udp"].includes(x)) out.push("congestion");
    if (["fec-udp", "fec-raw", "fec-raw-gaming"].includes(x)) out.push("pacer");
    if (x === "tun") out.push("fragment");
    if (x === "parallax") out.push("packet");
    if (!RAW.includes(x)) out.push("game");
    return out;
  }

  /** Cases of a tune check: every option of every chosen transport, in each direction, each round. */
  export function tuneCount(transports, v, dirs = 2, family = "ipv4") {
    let total = 0;
    for (const x of transports) {
      const variants = 1 + tuneVariants(x).length;
      total += variants * (x === "tun" ? v.tun_profiles.length : 1) * (RAW.includes(x) ? 1 : dirs * (family === "both" ? 2 : 1));
    }
    return total * Math.min(3, Math.max(1, v.rounds ?? 2));
  }

  // Mirrors the checker's own case list, for the count under the panel.
  function caseCount(v, dirs, family) {
    let total = 0;
    for (const x of v.transports) {
      let variants = 1;
      if (["wss", "https", "xhttps"].includes(x)) variants += (v.browser_tls ? 1 : 0) + (v.tls_fragment ? 1 : 0);
      if (v.also_congestion && !["fec-raw", "fec-raw-gaming", "tun", "kcp", "fec-udp"].includes(x)) variants += 1;
      if (v.also_pacer && ["fec-udp", "fec-raw", "fec-raw-gaming"].includes(x)) variants += 1;
      if (v.also_fragment && x === "tun") variants += 1;
      if (x === "parallax" && v.parallax_packet !== false) variants += 1;
      if (v.also_game && !["fec-raw", "fec-raw-gaming", "tun"].includes(x)) variants += 1;
      total += variants * (x === "tun" ? v.tun_profiles.length : 1) * (RAW.includes(x) ? 1 : dirs * (family === "both" ? 2 : 1));
    }
    return total;
  }

  /** The options a preset starts from, as the checker sets them. */
  export function presetOptions(preset) {
    const p = { quick: [5, false, 0, false, false, false], standard: [10, true, 30, false, false, true], thorough: [10, true, 60, true, true, true] }[preset] ?? [5, false, 0, false, false, false];
    return {
      transports: ["tcp", "wss", "https", "xhttps", "ws", "http", "xhttp", "kcp", "parallax", "fec-udp"],
      tun_profiles: ["tcp", "udp", "icmp", "gre", "ipip", "raw", "dns"],
      pings: p[0], download: p[1], upload: p[1], parallel: p[3], speed_sec: 5, hold_sec: p[2], udp: true, mtu: p[4], repeat_failed: p[5],
      browser_tls: false, tls_fragment: false, also_congestion: false, also_pacer: false, also_fragment: false, parallax_packet: true, also_game: false, rounds: 1,
      tls_port: 0, port: 0, slow_mbps: 5,
    };
  }
</script>
