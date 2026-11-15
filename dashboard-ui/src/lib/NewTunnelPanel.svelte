<script>
  // A new tunnel built on both servers at once: the dashboard makes the key and both
  // configurations, starts the listening end, then the end that connects, and waits for the link.
  import Icon from "./Icon.svelte";
  import { getNewTunnel, createTunnel } from "./api.js";
  import { say } from "./actions.svelte.js";
  import { live } from "./live.svelte.js";
  import { fleet, LOCAL, refreshFleet } from "./servers.svelte.js";
  import { t } from "./i18n.svelte.js";
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
  });
  let f = $state(blank());

  /** Servers an end can go on: this one and the joined servers that are online. */
  const places = $derived([
    { id: LOCAL, name: t("thisServerIs", live.snapshot?.host?.hostname ?? ""), address: live.snapshot?.host?.address ?? "", online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, address: s.snapshot?.host?.address ?? "", online: s.online })),
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
      }
      step = "form";
      problem = "";
      made = null;
      tried = false;
      dialog.showModal();
      getNewTunnel().then(({ status, data }) => {
        if (status === 200) transports = data.transports;
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

  const transportInfo = $derived(transports.find((x) => x.name === f.transport));
  /** The end that connects to the other, and the server it connects to. */
  const target = $derived(f.direction === "reverse" ? placeOf(f.iran) : placeOf(f.foreign));

  // Follow the transport's usual port and the listening server's address until the user types one.
  $effect(() => {
    if (!f.portTouched && transportInfo) f.port = String(transportInfo.port);
  });
  $effect(() => {
    if (!f.addressTouched) f.address = target?.address ?? "";
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
    const port = plain(f.port);
    if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) e.port = t("portRule");
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
    const body = {
      name: f.name.trim(), iran: f.iran, foreign: f.foreign, transport: f.transport, direction: f.direction,
      tunnel_port: +plain(f.port), address: f.address.trim(), carry: f.carry,
      ports: plain(f.ports), protocol: f.protocol, reach: f.reach, socks_bind: f.socks.trim(),
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
          <div class="erow">
            <div class="grow">
              <label class="flabel" for="nt-transport">{t("transport")}</label>
              <select id="nt-transport" class="input" bind:value={f.transport}>
                {#each transports as x (x.name)}<option value={x.name}>{transportLabel(x.name)}</option>{/each}
              </select>
            </div>
            <div class="eproto">
              <label class="flabel" for="nt-port">{t("tunnelPort")}</label>
              <div class="dice-in">
                <input id="nt-port" class="input ltr" inputmode="numeric" bind:value={f.port} oninput={() => (f.portTouched = true)} aria-invalid={Boolean(show("port"))} />
                <button type="button" class="dice" onclick={randomTunnelPort} title={t("randomPort")} aria-label={t("randomPort")}><Icon name="dice" /></button>
              </div>
            </div>
          </div>
          <p class="muted small m0 ehelp">{t("trDesc")[f.transport] ?? ""}{transportInfo?.udp ? ` ${t("udpPortNote")}` : ""}</p>
          {#if show("port")}<p class="small m0 bad-t">{show("port")}</p>{/if}
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
