<script>
  // A new tunnel built on both servers at once: the dashboard makes the key and both
  // configurations, starts the listening end, then the end that connects, and waits for the link.
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import { getNewTunnel, createTunnel } from "./api.js";
  import { say } from "./actions.svelte.js";
  import { live } from "./live.svelte.js";
  import { fleet, LOCAL, localName, refreshFleet } from "./servers.svelte.js";
  import { t, num } from "./i18n.svelte.js";
  import { transportLabel, usedPorts, randomPort } from "./view.js";

  /** `prefill`: answers to start from (a connection-test result): iran, foreign, transport,
   *  direction, port, address. */
  let { open = false, prefill = null, onclose } = $props();
  let dialog = $state();
  let transports = $state([]);
  /** "form" | "working" | "done" */
  let step = $state("form");
  let problem = $state("");
  let made = $state(null);
  let waited = $state(0);
  /** Errors show once Create was pressed. */
  let tried = $state(false);

  const blank = () => ({
    name: "", iran: LOCAL, foreign: "", direction: "reverse", transport: "tcp", port: "", portTouched: false,
    address: "", addressTouched: false, carry: "ports", ports: "", protocol: "tcp", reach: "local", socks: "127.0.0.1:1080",
    parallax_mode: "stream", speed: "default", tls_profile: "classic", tls_fragment: false, tcp_congestion: "", fec_pacer: false, pool: "4",
    game: false, game_port: "", game_copies: "3", iran_address: "", ipv6_transport: "tcp",
    fromCheck: false,
    // "one": one transport; "failover": several carriers in order behind the same user ports.
    mode: "one",
    // The usual choice: plain TCP first, then two that look like web traffic.
    carriers: [
      { transport: "tcp", port: "", touched: false },
      { transport: "wss", port: "", touched: false },
      { transport: "xhttps", port: "", touched: false },
    ],
  });
  let f = $state(blank());

  /** Servers an end can go on: this one and the joined servers that are online. */
  const places = $derived([
    { id: LOCAL, name: t("thisServerIs", localName(live.snapshot?.host?.hostname)), address: live.snapshot?.host?.address ?? "", address6: live.snapshot?.host?.address6 ?? "", online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, address: s.snapshot?.host?.address ?? "", address6: s.snapshot?.host?.address6 ?? "", online: s.online })),
  ]);
  const placeOf = (id) => places.find((p) => p.id === id);

  $effect(() => {
    if (open && dialog && !dialog.open) {
      f = blank();
      f.foreign = places.find((p) => p.id !== LOCAL && p.online)?.id ?? "";
      if (prefill) {
        for (const [k, v] of Object.entries(prefill)) if (v != null) f[k] = v;
        f.portTouched = prefill.port != null;
        f.addressTouched = prefill.address != null;
        // A result over IPv6 is made with the IPv6 entry, on the transport it tested.
        if (String(prefill.address ?? "").includes(":")) {
          f.ipv6_transport = f.transport;
          f.transport = "ipv6";
        }
      }
      step = "form";
      problem = "";
      made = null;
      tried = false;
      dialog.showModal();
      getNewTunnel().then(({ status, data }) => {
        if (status === 200) {
          transports = data.transports;
          failoverMost = data.failover_most ?? 4;
        }
      });
    }
    if (!open && dialog?.open) dialog.close();
  });

  // Random ports: never one a tunnel on any known server already uses, or one typed here.
  const avoid = () => {
    const used = usedPorts([live.snapshot, ...fleet.list.map((s) => s.snapshot)]);
    for (const n of `${f.port} ${f.ports} ${f.socks}`.match(/\d{2,5}/g) ?? []) used.add(+n);
    return used;
  };
  function randomTunnelPort() {
    f.port = String(randomPort(avoid()));
    f.portTouched = true;
  }
  function randomForward() {
    const p = randomPort(avoid());
    f.ports = f.ports.trim() ? `${f.ports.trim().replace(/[,\s]+$/, "")}, ${p}` : String(p);
  }
  function randomSocks() {
    const host = f.socks.includes(":") ? f.socks.slice(0, f.socks.lastIndexOf(":")) : "127.0.0.1";
    f.socks = `${host || "127.0.0.1"}:${randomPort(avoid())}`;
  }

  const isIp = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^\[?[0-9a-fA-F:.]*:[0-9a-fA-F:.]*\]?$/.test(s);
  // The IPv6 entry runs another transport over IPv6: that one decides the options and port.
  const isIpv6 = $derived(f.transport === "ipv6");
  const kind = $derived(isIpv6 ? f.ipv6_transport : f.transport);
  const ipv6Choices = $derived(transports.find((x) => x.name === "ipv6")?.transports ?? []);
  const transportInfo = $derived(transports.find((x) => x.name === kind));
  // GAME switches Game mode on and expects game UDP: TCP and UDP forwarding by default.
  $effect(() => {
    if (kind === "game") {
      untrack(() => {
        f.game = true;
        if (f.protocol === "tcp") f.protocol = "both";
      });
    }
  });
  /** The carrier's own choices; speed mode also applies to Parallax in packet mode. */
  const opts = $derived(transportInfo?.options ?? {});
  const speedOn = $derived(Boolean(opts.speed || (opts.parallax && f.parallax_mode === "packet")));
  const hasOpts = $derived(Boolean(opts.tls || opts.congestion || opts.pacer || opts.parallax || opts.speed || opts.game));
  const gameUdp = $derived(f.carry === "socks" || f.protocol !== "tcp");
  /** Only the choices the chosen carrier has go to the server, so a changed carrier sends none of the old ones. */
  function carrierOptions() {
    const out = { pool: Math.min(16, Math.max(1, +plain(String(f.pool)) || 4)) };
    if (opts.parallax) out.parallax_mode = f.parallax_mode;
    if (speedOn && f.speed !== "default") out.speed = f.speed;
    if (opts.tls) {
      out.tls_profile = f.tls_profile;
      out.tls_fragment = f.tls_fragment;
    }
    if (opts.congestion && f.tcp_congestion) out.tcp_congestion = f.tcp_congestion;
    if (opts.pacer) out.fec_pacer = f.fec_pacer;
    if (opts.game && (f.game || kind === "game")) {
      out.game = true;
      if (/^\d+$/.test(plain(String(f.game_port)))) out.game_port = +plain(String(f.game_port));
      out.game_copies = Math.min(4, Math.max(1, +plain(String(f.game_copies)) || 3));
      // The foreign end sends game datagrams to the Iran server's IP: needed in a direct tunnel,
      // and when the tunnel reaches the Iran server by a host name.
      const iran = f.iran_address.trim() || placeOf(f.iran)?.address || "";
      if (iran && (f.direction === "direct" || (!isIp(f.address.trim()) && isIp(iran)))) out.iran_address = iran;
    }
    return out;
  }
  // Failover: the plain transports only (not the IPv6 or GAME entries).
  let failoverMost = $state(4);
  const plainTransports = $derived(transports.filter((x) => !x.ipv6 && !x.game));
  const isFailover = $derived(f.mode === "failover");
  // A carrier follows its transport's usual port until the user types one; when that port is
  // already taken by an earlier carrier, the next free one is used, so the defaults never clash.
  $effect(() => {
    const taken = new Set(untrack(tunnelPorts));
    for (const c of f.carriers) {
      const info = transports.find((x) => x.name === c.transport);
      if (!c.touched && info) {
        let port = info.port;
        while (taken.has(port)) port = port >= 65535 ? 1024 : port + 1;
        if (c.port !== String(port)) c.port = String(port);
      }
      if (/^\d+$/.test(plain(c.port))) taken.add(+plain(c.port));
    }
  });
  /** Transports another carrier already uses: each transport once. */
  const usedElsewhere = (i) => new Set(f.carriers.filter((_, j) => j !== i).map((c) => c.transport));
  function addCarrier() {
    if (f.carriers.length >= failoverMost) return;
    const used = new Set(f.carriers.map((c) => c.transport));
    const next = plainTransports.find((x) => !used.has(x.name))?.name ?? "tcp";
    f.carriers.push({ transport: next, port: "", touched: false });
  }
  function moveCarrier(i, by) {
    const j = i + by;
    if (j < 0 || j >= f.carriers.length) return;
    [f.carriers[i], f.carriers[j]] = [f.carriers[j], f.carriers[i]];
  }
  function dropCarrier(i) {
    if (f.carriers.length > 2) f.carriers.splice(i, 1);
  }
  function randomCarrierPort(i) {
    const used = avoid();
    for (const c of f.carriers) if (/^\d+$/.test(plain(c.port))) used.add(+plain(c.port));
    f.carriers[i].port = String(randomPort(used));
    f.carriers[i].touched = true;
  }

  /** The end that connects to the other, and the server it connects to. */
  const target = $derived(f.direction === "reverse" ? placeOf(f.iran) : placeOf(f.foreign));

  // Follow the transport's usual port and the listening server's address until the user types one.
  // Forwarded ports another tunnel on the Iran server already listens on (the part before "=").
  const portsTaken = $derived.by(() => {
    const snap = f.iran === LOCAL ? live.snapshot : fleet.list.find((s) => s.id === f.iran)?.snapshot;
    const used = usedPorts([snap]);
    const out = [];
    for (const item of plain(f.ports).split(/[,\s]+/).filter(Boolean)) {
      const [a, b = a] = (item.split("=")[0].match(/\d+/g) ?? []).map(Number);
      for (let n = a; a && n <= Math.min(b, a + 5000); n++) if (used.has(n) && !out.includes(n)) out.push(n);
    }
    return out;
  });
  // The usual port, or the next one no tunnel on the known servers uses yet.
  const tunnelPorts = () => usedPorts([live.snapshot, ...fleet.list.map((s) => s.snapshot)]);
  const freeFrom = (port, taken) => {
    while (taken.has(port)) port = port >= 65535 ? 1024 : port + 1;
    return port;
  };
  $effect(() => {
    if (!f.portTouched && transportInfo) f.port = String(freeFrom(transportInfo.port, untrack(tunnelPorts)));
  });
  // IPv4 or IPv6: which address of the listening server the other end connects to.
  // IPv6 entry: the listening server's IPv6 address (it must have one).
  const noIpv6 = $derived(isIpv6 && Boolean(target) && !target.address6);
  $effect(() => {
    if (!f.addressTouched) f.address = (isIpv6 ? target?.address6 : target?.address) || "";
  });

  const plain = (text) =>
    text
      .trim()
      .replace(/[۰-۹]/g, (d) => d.charCodeAt(0) - 0x06f0)
      .replace(/[٠-٩]/g, (d) => d.charCodeAt(0) - 0x0660)
      .replace(/،/g, ",");

  const errors = $derived.by(() => {
    const e = {};
    if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(f.name.trim())) e.name = t("nameRule");
    if (!f.foreign || f.iran === f.foreign) e.servers = t("twoServers");
    if (f.mode === "failover") {
      const ports = f.carriers.map((c) => plain(c.port));
      if (ports.some((p) => !/^\d+$/.test(p) || +p < 1 || +p > 65535)) e.port = t("portRule");
      else if (new Set(ports).size !== ports.length) e.port = t("foPortTwice");
    } else {
      const port = plain(f.port);
      if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) e.port = t("portRule");
    }
    if (!f.address.trim()) e.address = t("addressMissing");
    if (f.carry === "ports" && !plain(f.ports)) e.ports = t("portsErr");
    return e;
  });
  const valid = $derived(Object.keys(errors).length === 0);
  const show = (key) => (tried ? errors[key] : "");

  async function create() {
    tried = true;
    if (!valid) return;
    step = "working";
    problem = "";
    const shared = {
      name: f.name.trim(), iran: f.iran, foreign: f.foreign, direction: f.direction, address: f.address.trim(), carry: f.carry,
      ports: plain(f.ports), protocol: f.protocol, reach: f.reach, socks_bind: f.socks.trim(),
    };
    const body = isFailover
      ? { ...shared, carriers: f.carriers.map((c) => ({ transport: c.transport, tunnel_port: +plain(c.port) })), tunnel_port: +plain(f.carriers[0].port) }
      : {
          ...shared, transport: f.transport, tunnel_port: +plain(f.port),
          ipv6_transport: isIpv6 ? f.ipv6_transport : undefined,
          ...carrierOptions(),
        };
    try {
      const { status, data } = await createTunnel(body);
      if (status !== 200) {
        problem = status === 401 ? t("signedOutNow") : status === 409 && !data?.detail ? t("busyT") : data?.detail ?? t("createFailed");
        step = "form";
        return;
      }
      made = body;
      waited = 0;
      step = "done";
      refreshFleet();
      say(t("createdT", body.name));
    } catch {
      problem = t("createSlow");
      step = "form";
    }
  }

  /** The new tunnel as each server reports it. */
  function endOn(server) {
    const tunnels = server === LOCAL ? live.snapshot?.tunnels : fleet.list.find((s) => s.id === server)?.snapshot?.tunnels;
    return tunnels?.find((x) => x.name === made?.name);
  }
  const linked = (x) => x && x.state === "running" && ((x.sessions ?? 0) > 0 || ["working", "no_traffic"].includes(x.link_state));
  const bothLinked = $derived(made ? linked(endOn(made.iran)) && linked(endOn(made.foreign)) : false);

  // Ask for fresh server snapshots while waiting for the link (up to a minute).
  $effect(() => {
    if (step !== "done" || bothLinked) return;
    const timer = setInterval(() => {
      waited += 2;
      refreshFleet();
      if (waited >= 60) clearInterval(timer);
    }, 2000);
    return () => clearInterval(timer);
  });
  // Closes the panel and tells the page at once; some browsers deliver the dialog's own close
  // event late or not at all, which would leave the panel unable to open again.
  function shut() {
    if (dialog?.open) dialog.close();
    onclose?.();
  }
</script>

<dialog bind:this={dialog} class="edit-panel" aria-labelledby="new-title" onclose={() => onclose?.()} oncancel={(e) => { e.preventDefault(); if (!(step === "working")) shut(); }}>
  <div class="dlg-h">
    <span class="dlg-ico"><Icon name="plus" /></span>
    <h2 id="new-title">{t("newTunnel")}</h2>
    <button class="btn icon ghost" onclick={shut} disabled={step === "working"} aria-label={t("close")}><Icon name="x" /></button>
  </div>
  <div class="dlg-b edit-b">
    {#if step === "done"}
      <div class="note info" role="status"><Icon name="check" /><span>{t("createdNote", made.name)}</span></div>
      <div class="new-ends">
        {#each [["iranEnd", made.iran], ["foreignEnd", made.foreign]] as [label, server]}
          {@const x = endOn(server)}
          <div class="new-end">
            <b>{t(label)}</b>
            <span class="muted small">{placeOf(server)?.name ?? server}</span>
            <span class="small">{linked(x) ? t("linkUp") : waited >= 60 ? t("linkNotYet") : t("linkWaiting")}</span>
          </div>
        {/each}
      </div>
      {#if made.carriers}
        {@const listener = placeOf(made.direction === "reverse" ? made.iran : made.foreign)?.name ?? ""}
        <div class="note info" role="note"><Icon name="lock" /><span>{t("foOpenPorts", listener, made.carriers.map((c) => `${c.tunnel_port} ${transports.find((x) => x.name === c.transport)?.udp ? "UDP" : "TCP"}`).join(", "))}</span></div>
      {/if}
      {#if !bothLinked && waited >= 60}
        <div class="note warn" role="note"><Icon name="warn" /><span>{t("linkHelp", made.tunnel_port)}</span></div>
      {/if}
    {:else}
      <fieldset disabled={step === "working"}>
        <section class="ed-sec">
          <header><span class="step-n">1</span><h3><label for="nt-name">{t("tunnelName")}</label></h3></header>
          <input id="nt-name" class="input ltr" bind:value={f.name} placeholder="game" autocomplete="off" spellcheck="false" aria-invalid={Boolean(show("name"))} aria-describedby="nt-name-h" />
          <p id="nt-name-h" class="small m0 ehelp {show('name') ? 'bad-t' : 'muted'}">{show("name") || t("nameRule")}</p>
        </section>

        <section class="ed-sec" aria-labelledby="nt-srv-h">
          <header><span class="step-n">2</span><h3 id="nt-srv-h">{t("whichServers")}</h3></header>
          <div class="nt-route">
            <div>
              <label class="flabel" for="nt-iran">{t("iranEnd")}</label>
              <select id="nt-iran" class="input" bind:value={f.iran}>
                {#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}
              </select>
            </div>
            <div class="link live nt-wire" aria-hidden="true"><span class="wire"><i></i></span></div>
            <div>
              <label class="flabel" for="nt-foreign">{t("foreignEnd")}</label>
              <select id="nt-foreign" class="input" bind:value={f.foreign}>
                {#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}
              </select>
            </div>
          </div>
          <p class="small m0 ehelp {show('servers') ? 'bad-t' : 'muted'}">{show("servers") || t("serversHelp")}</p>
          {#if places.length < 2}<div class="note warn" role="note"><Icon name="warn" /><span>{t("needAgent")}</span></div>{/if}
        </section>

        <section class="ed-sec" aria-labelledby="nt-link-h">
          <header><span class="step-n">3</span><h3 id="nt-link-h">{t("linkH")}</h3></header>
          <div class="seg full mb12" role="group" aria-label={t("foModeL")}>
            {#each [["one", "foOne"], ["failover", "foMode"]] as [v, k]}<button type="button" aria-pressed={f.mode === v} onclick={() => (f.mode = v)}>{t(k)}</button>{/each}
          </div>
          {#if isFailover}
            <p class="muted small m0 ehelp">{t("foHelp")}</p>
            <ol class="fo-list mt8">
              {#each f.carriers as c, i (i)}
                <li class="fo-row">
                  <span class="fo-n" aria-hidden="true">{i + 1}</span>
                  <div class="grow">
                    <label class="flabel" for="fo-t{i}">{i === 0 ? t("foMain") : t("foBackup", num(i))}</label>
                    <select id="fo-t{i}" class="input" bind:value={c.transport}>
                      {#each plainTransports as x (x.name)}<option value={x.name} disabled={usedElsewhere(i).has(x.name)}>{transportLabel(x.name)}</option>{/each}
                    </select>
                  </div>
                  <div class="eproto">
                    <label class="flabel" for="fo-p{i}">{t("tunnelPort")}</label>
                    <div class="dice-in">
                      <input id="fo-p{i}" class="input ltr" inputmode="numeric" bind:value={c.port} oninput={() => (c.touched = true)} />
                      <button type="button" class="dice" onclick={() => randomCarrierPort(i)} title={t("randomPort")} aria-label={t("randomPort")}><Icon name="dice" /></button>
                    </div>
                  </div>
                  <div class="fo-act">
                    <button type="button" class="btn icon ghost" onclick={() => moveCarrier(i, -1)} disabled={i === 0} aria-label={t("foUp")} title={t("foUp")}>↑</button>
                    <button type="button" class="btn icon ghost" onclick={() => moveCarrier(i, 1)} disabled={i === f.carriers.length - 1} aria-label={t("foDown")} title={t("foDown")}>↓</button>
                    <button type="button" class="btn icon ghost" onclick={() => dropCarrier(i)} disabled={f.carriers.length <= 2} aria-label={t("foRemove")} title={t("foRemove")}><Icon name="x" /></button>
                  </div>
                </li>
              {/each}
            </ol>
            {#if f.carriers.length < failoverMost}
              <button type="button" class="btn mt8" onclick={addCarrier}><Icon name="plus" />{t("foAdd")}</button>
            {/if}
            {#if show("port")}<p class="small m0 bad-t">{show("port")}</p>{/if}
            <p class="muted small m0 ehelp mt8">{t("foHow")}</p>
            <p class="small m0 ehelp warn-t">{t("foFirewall")}</p>
          {:else}
          <div class="erow">
            <div class="grow">
              <label class="flabel" for="nt-transport">{t("transport")}</label>
              <select id="nt-transport" class="input" bind:value={f.transport}>
                {#each transports as x (x.name)}<option value={x.name}>{x.name === "ipv6" ? "IPv6" : transportLabel(x.name)}</option>{/each}
              </select>
              {#if isIpv6}
                <label class="flabel mt8" for="nt-v6t">{t("ntOverIpv6")}</label>
                <select id="nt-v6t" class="input" bind:value={f.ipv6_transport}>
                  {#each ipv6Choices as x (x)}<option value={x}>{transportLabel(x)}</option>{/each}
                </select>
              {/if}
            </div>
            <div class="eproto">
              <label class="flabel" for="nt-port">{t("tunnelPort")}</label>
              <div class="dice-in">
                <input id="nt-port" class="input ltr" inputmode="numeric" bind:value={f.port} oninput={() => (f.portTouched = true)} aria-invalid={Boolean(show("port"))} />
                <button type="button" class="dice" onclick={randomTunnelPort} title={t("randomPort")} aria-label={t("randomPort")}><Icon name="dice" /></button>
              </div>
            </div>
          </div>
          <p class="muted small m0 ehelp">{isIpv6 ? `${t("trDesc").ipv6} ` : ""}{t("trDesc")[kind] ?? ""}{transportInfo?.udp ? ` ${t("udpPortNote")}` : ""}</p>
          {#if noIpv6}<p class="small m0 bad-t" role="alert">{t("ntNoIpv6", target?.name ?? "")}</p>{/if}
          {#if show("port")}<p class="small m0 bad-t">{show("port")}</p>{/if}
          {/if}
          <div class="ed-grid">
            <div>
              <span class="flabel" id="nt-dir-l">{t("whoConnects")}</span>
              <div class="ct-list" role="group" aria-labelledby="nt-dir-l">
                {#each [["reverse", "dirReverse"], ["direct", "dirDirect"]] as [v, k]}<button type="button" aria-pressed={f.direction === v} onclick={() => (f.direction = v)}>{t(k)}</button>{/each}
              </div>
            </div>
            <div>
              <label class="flabel" for="nt-addr">{t("connectsTo", target?.name ?? "")}</label>
              <input id="nt-addr" class="input ltr" bind:value={f.address} oninput={() => (f.addressTouched = true)} autocomplete="off" spellcheck="false" aria-invalid={Boolean(show("address"))} />
            </div>
          </div>
          <p class="small m0 ehelp {show('address') ? 'bad-t' : 'muted'}">{show("address") || t(f.direction === "reverse" ? "reverseHelp" : "directHelp")}</p>
          {#if hasOpts && !isFailover}
            <details class="nt-opts mt12" open={f.fromCheck}>
              <summary><span class="flabel m0">{t("ntOpts")}</span></summary>
              <p class="muted small m0 ehelp">{f.fromCheck ? t("ntFromCheck") : t("ntOptsHelp")}</p>
              <div class="ed-grid mt8">
                {#if opts.parallax}
                  <div>
                    <span class="flabel" id="nt-pxm-l">{t("ntPxMode")}</span>
                    <div class="seg full" role="group" aria-labelledby="nt-pxm-l">
                      {#each [["stream", "ntStream"], ["packet", "ntPacket"]] as [v, k]}<button type="button" aria-pressed={f.parallax_mode === v} onclick={() => (f.parallax_mode = v)}>{t(k)}</button>{/each}
                    </div>
                  </div>
                {/if}
                {#if speedOn}
                  <div>
                    <label class="flabel" for="nt-speed">{t("ntSpeed")}</label>
                    <select id="nt-speed" class="input" bind:value={f.speed}>
                      {#each ["default", "normal", "fast", "fast2", "fast3"] as v}<option value={v}>{t("ntSpeedOpts")[v]}</option>{/each}
                    </select>
                  </div>
                {/if}
                {#if opts.tls}
                  <div>
                    <span class="flabel" id="nt-tls-l">{t("ntTlsLook")}</span>
                    <div class="seg full" role="group" aria-labelledby="nt-tls-l">
                      {#each [["classic", "ntClassic"], ["chrome", "ntChrome"]] as [v, k]}<button type="button" aria-pressed={f.tls_profile === v} onclick={() => (f.tls_profile = v)}>{t(k)}</button>{/each}
                    </div>
                  </div>
                {/if}
                {#if opts.congestion}
                  <div>
                    <label class="flabel" for="nt-cong">{t("ntCong")}</label>
                    <select id="nt-cong" class="input" bind:value={f.tcp_congestion}>
                      <option value="">{t("ntCongDefault")}</option><option value="cubic">cubic</option><option value="system">{t("ntCongSystem")}</option>
                    </select>
                  </div>
                {/if}
                <div>
                  <label class="flabel" for="nt-pool">{t("ntPool")}</label>
                  <input id="nt-pool" class="input ltr" type="number" min="1" max="16" bind:value={f.pool} />
                </div>
              </div>
              {#if opts.tls}
                <label class="chk mt12"><input type="checkbox" bind:checked={f.tls_fragment} /><span>{t("ntTlsFrag")}</span></label>
                {#if f.tls_fragment}<p class="small m0 ehelp warn-t">{t("ntTlsFragHelp")}</p>{/if}
              {/if}
              {#if opts.pacer}<label class="chk mt12"><input type="checkbox" bind:checked={f.fec_pacer} /><span>{t("ntPacer")}</span></label>{/if}
              {#if opts.game}
                <label class="chk mt12"><input type="checkbox" bind:checked={f.game} /><span>{t("ntGame")}</span></label>
                <p class="muted small m0 ehelp">{t("ntGameHelp")}</p>
                {#if f.game}
                  {#if !gameUdp}<p class="small m0 warn-t">{t("ntGameNeedsUdp")}</p>{/if}
                  <div class="ed-grid mt8">
                    <div><label class="flabel" for="nt-gport">{t("ntGamePort")}</label><input id="nt-gport" class="input ltr" inputmode="numeric" bind:value={f.game_port} placeholder={String((+plain(f.port) || 7000) + 1)} /></div>
                    <div><label class="flabel" for="nt-gcopies">{t("ntGameCopies")}</label><input id="nt-gcopies" class="input ltr" type="number" min="1" max="4" bind:value={f.game_copies} /></div>
                    {#if f.direction === "direct" || !isIp(f.address.trim())}<div><label class="flabel" for="nt-giran">{t("ntIranAddr")}</label><input id="nt-giran" class="input ltr" bind:value={f.iran_address} placeholder={placeOf(f.iran)?.address ?? ""} /></div>{/if}
                  </div>
                {/if}
              {/if}
            </details>
          {/if}
        </section>

        <section class="ed-sec" aria-labelledby="nt-carry-h">
          <header><span class="step-n">4</span><h3 id="nt-carry-h">{t("carryH")}</h3></header>
          <div class="ed-grid">
            <div>
              <span class="flabel" id="nt-carry-l">{t("carryWhat")}</span>
              <div class="seg full" role="group" aria-labelledby="nt-carry-l">
                {#each [["ports", "carryPorts"], ["socks", "carrySocks"]] as [v, k]}<button type="button" aria-pressed={f.carry === v} onclick={() => (f.carry = v)}>{t(k)}</button>{/each}
              </div>
            </div>
            {#if f.carry === "ports"}
              <div>
                <span class="flabel" id="nt-proto-l">{t("protocol")}</span>
                <div class="seg full" role="group" aria-labelledby="nt-proto-l">
                  {#each [["tcp", "TCP"], ["udp", "UDP"], ["both", t("tcpUdp")]] as [v, label]}<button type="button" aria-pressed={f.protocol === v} onclick={() => (f.protocol = v)}>{label}</button>{/each}
                </div>
              </div>
            {/if}
          </div>
          {#if f.carry === "ports"}
            <div class="mt12">
              <label class="flabel" for="nt-ports">{t("portsLabel")}</label>
              <div class="dice-in">
                <input id="nt-ports" class="input ltr" bind:value={f.ports} placeholder="443, 8443, 2000-2010" autocomplete="off" spellcheck="false" aria-invalid={Boolean(show("ports"))} />
                <button type="button" class="dice" onclick={randomForward} title={t("randomPortAdd")} aria-label={t("randomPortAdd")}><Icon name="dice" /></button>
              </div>
              <p class="small m0 ehelp {show('ports') ? 'bad-t' : 'muted'}">{show("ports") || t("newPortsHelp")}</p>
              {#if portsTaken.length}<p class="small m0 ehelp warn-t" role="status">{t("portsTakenT", portsTaken.join(", "))}</p>{/if}
            </div>
            <div class="mt12">
              <span class="flabel" id="nt-reach-l">{t("reachLabel")}</span>
              <div class="ct-list" role="group" aria-labelledby="nt-reach-l">
                {#each [["local", "reachLocal"], ["any", "reachAny"]] as [v, k]}<button type="button" aria-pressed={f.reach === v} onclick={() => (f.reach = v)}>{t(k)}</button>{/each}
              </div>
            </div>
          {:else}
            <div class="mt12">
              <label class="flabel" for="nt-socks">{t("socksBind")}</label>
              <div class="dice-in">
                <input id="nt-socks" class="input ltr" bind:value={f.socks} autocomplete="off" spellcheck="false" />
                <button type="button" class="dice" onclick={randomSocks} title={t("randomPort")} aria-label={t("randomPort")}><Icon name="dice" /></button>
              </div>
              <p class="muted small m0 ehelp">{t("socksHelp")}</p>
            </div>
          {/if}
        </section>
      </fieldset>
      <p class="muted small m0">{t("advancedLater")}</p>
      {#if problem}
        <div class="note bad" role="alert"><Icon name="warn" /><span>{t("createFailed")} <span class="ltr">{problem}</span></span></div>
      {/if}
    {/if}
  </div>
  <div class="dlg-f">
    {#if step === "done"}
      <button class="btn primary" onclick={shut}>{t("done")}</button>
    {:else}
      <button class="btn" onclick={shut} disabled={step === "working"}>{t("cancel")}</button>
      <button class="btn primary" onclick={create} disabled={step === "working" || (tried && !valid)} aria-busy={step === "working"}>
        <Icon name="play" />{step === "working" ? t("creating") : t("createStart")}
      </button>
    {/if}
  </div>
</dialog>
