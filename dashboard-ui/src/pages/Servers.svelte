<script>
  // This server and every joined one, with Easy connect: a one-time command run on another server.
  import { onDestroy } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { live } from "../lib/live.svelte.js";
  import { fleet, refreshFleet, localName, LOCAL } from "../lib/servers.svelte.js";
  import { createJoinCode, removeServer, renameServer } from "../lib/api.js";
  import SshAdd from "../lib/SshAdd.svelte";
  import { ask, say } from "../lib/actions.svelte.js";
  import { t, num, pct, duration, clock, rate } from "../lib/i18n.svelte.js";
  import Ring from "../lib/Ring.svelte";
  import { isUp } from "../lib/view.js";

  let join = $state(null); // { code, command, expires }
  let left = $state(0);
  let making = $state(false);
  let ticker;

  function tick() {
    left = join ? Math.max(0, join.expires - Math.floor(Date.now() / 1000)) : 0;
  }

  async function makeCommand() {
    making = true;
    try {
      const { status, data } = await createJoinCode();
      if (status !== 200) return say(data?.detail ?? t("joinFail"), true);
      join = data;
      tick();
      clearInterval(ticker);
      ticker = setInterval(tick, 1000);
    } catch {
      say(t("joinFail"), true);
    } finally {
      making = false;
    }
  }

  async function copy(text, node) {
    try {
      await navigator.clipboard.writeText(text);
      return say(t("copied"));
    } catch {
      const range = document.createRange();
      range.selectNodeContents(node);
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      say(t("copyFail"), true);
    }
  }

  function askRemove(server) {
    ask(t("removeQ", server.name), t("removeText"), t("removeSrv"), async () => {
      try {
        const { status, data } = await removeServer(server.id);
        if (status === 200) {
          say(t("removedT", server.name));
          refreshFleet();
        } else say(data?.detail ?? t("failedT", server.name), true);
      } catch { say(t("slowShort"), true); }
    });
  }

  // Renaming: which card is being renamed, and the text typed so far.
  let naming = $state(null);
  let nameText = $state("");
  let nameBad = $state(false);
  let saving = $state(false);
  const NAME_OK = /^[\p{L}\p{N} ()#._-]{0,40}$/u;

  function startRename(id, current) {
    naming = id;
    nameText = current;
    nameBad = false;
  }

  async function saveName(id, own) {
    const text = nameText.trim().replace(/\s+/g, " ");
    if (!NAME_OK.test(text)) return (nameBad = true);
    saving = true;
    try {
      const { status } = await renameServer(id, text === own ? "" : text);
      if (status === 200) {
        naming = null;
        say(text && text !== own ? t("renamedT", text) : t("renameResetT", own));
        refreshFleet();
      } else if (status === 400) nameBad = true;
      else say(t("renameFail"), true);
    } catch { say(t("slowShort"), true); }
    finally { saving = false; }
  }

  function nameKeys(event, id, own) {
    if (event.key === "Enter") { event.preventDefault(); saveName(id, own); }
    else if (event.key === "Escape") naming = null;
  }

  function focus(node) { node.focus(); node.select(); }

  function summary(snapshot) {
    const tunnels = snapshot?.tunnels ?? [];
    return { total: tunnels.length, up: tunnels.filter(isUp).length, issues: snapshot?.issues?.length ?? 0 };
  }

  const mmss = (s) => `${num(Math.floor(s / 60))}:${num(s % 60).padStart(2, num(0))}`;
  let cmdBox = $state();
  let cmdShort = $state();

  onDestroy(() => clearInterval(ticker));
</script>

<section class="panel easy" aria-labelledby="easy-h">
  <div>
    <h2 id="easy-h">{t("easyT")}</h2>
    <p class="muted">{t("easyText")}</p>
    <ol class="steps">
      <li>{t("easyStep1")}</li>
      <li>{t("easyStep2")}</li>
      <li>{t("easyStep3")}</li>
    </ol>
  </div>
  <div class="connect-card">
    {#if join && left > 0}
      <div class="flabel">{t("joinCmd")}</div>
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <pre class="cmdline ltr" bind:this={cmdBox} tabindex="0">{join.command}</pre>
      <div class="row-flex">
        <button class="btn primary grow" onclick={() => copy(join.command, cmdBox)}><Icon name="copy" />{t("copy")}</button>
        <span class="muted small" aria-live="off">{t("expiresIn", mmss(left))}</span>
      </div>
      <details class="small">
        <summary>{t("haveEz")}</summary>
        <p class="muted">{t("haveEzText")}</p>
        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <pre class="cmdline ltr" bind:this={cmdShort} tabindex="0">sudo eztunnel agent join {join.code}</pre>
        <button class="btn" onclick={() => copy(`sudo eztunnel agent join ${join.code}`, cmdShort)}><Icon name="copy" />{t("copy")}</button>
      </details>
    {:else}
      {#if join}<div class="note warn" role="note"><Icon name="warn" /><span>{t("joinExpired")}</span></div>{/if}
      <button class="btn primary" onclick={makeCommand} disabled={making} aria-busy={making}>
        <Icon name="servers" />{join ? t("joinNew") : t("joinMake")}
      </button>
      <p class="muted small m0">{t("joinNote")}</p>
    {/if}
  </div>
</section>

<SshAdd />

<div class="sec-head mt16"><h2>{t("serversList")}</h2></div>
<div class="tgrid srv-grid">
  {#if live.snapshot}
    {@const s = summary(live.snapshot)}
    <article class="panel tcard" aria-labelledby="srv-local">
      <div class="hd">
        <div class="grow">
          {#if naming === LOCAL}
            {@render nameForm(LOCAL, live.snapshot.host?.hostname ?? "")}
          {:else}
            <div class="title"><h2 id="srv-local" class="ltr">{localName(live.snapshot.host?.hostname)}</h2><span class="code-chip">{t("thisServer")}</span>{@render renameButton(LOCAL, localName(live.snapshot.host?.hostname))}</div>
            {#if fleet.localName}<div class="meta"><span class="ltr">{t("ownName", live.snapshot.host?.hostname ?? "")}</span></div>{/if}
          {/if}
          <div class="meta"><span class="ltr mono">{live.snapshot.host?.address ?? ""}</span>{#if live.snapshot.host?.address6}<span aria-hidden="true">·</span><span class="ltr mono">{live.snapshot.host.address6}</span>{/if}<span aria-hidden="true">·</span><span class="ltr">{live.snapshot.version}</span></div>
        </div>
        <span class="pill ok">{t("online")}</span>
      </div>
      {@render load(live.snapshot.host, "loc")}
      <div class="muted small">{t("srvTunnels", s.up, s.total)}{#if s.issues}{" · "}{t("attn", s.issues)}{/if}</div>
      <div class="actions"><a class="btn" href="#/tunnels"><Icon name="tunnels" />{t("tunnels")}</a></div>
    </article>
  {/if}
  {#each fleet.list as server, i (server.id)}
    {@const s = summary(server.snapshot)}
    <article class="panel tcard" aria-labelledby="srv-{i}">
      <div class="hd">
        <div class="grow">
          {#if naming === server.id}
            {@render nameForm(server.id, server.joined_name ?? server.name)}
          {:else}
            <div class="title"><h2 id="srv-{i}" class="ltr">{server.name}</h2>{#if server.hello?.arch}<span class="code-chip">{server.hello.arch}</span>{/if}{@render renameButton(server.id, server.name)}</div>
            {#if server.joined_name && server.joined_name !== server.name}<div class="meta"><span class="ltr">{t("ownName", server.joined_name)}</span></div>{/if}
          {/if}
          <div class="meta">
            {#if server.snapshot?.host?.address}<span class="ltr mono">{server.snapshot.host.address}</span>{/if}
            {#if server.snapshot?.host?.address6}<span aria-hidden="true">·</span><span class="ltr mono">{server.snapshot.host.address6}</span>{/if}
            {#if server.hello?.version}{#if server.snapshot?.host?.address}<span aria-hidden="true">·</span>{/if}<span class="ltr">{server.hello.version}</span>{/if}
          </div>
        </div>
        {#if server.online}
          <span class="pill ok">{t("online")}</span>
        {:else}
          <span class="pill off">{t("offline")}</span>
        {/if}
      </div>
      {#if server.online && server.snapshot}
        {@render load(server.snapshot.host, "s" + i)}
        <div class="muted small">{t("srvTunnels", s.up, s.total)}{#if s.issues}{" · "}{t("attn", s.issues)}{/if}</div>
      {:else}
        <div class="note warn" role="note"><Icon name="warn" /><span>{server.last_seen ? t("lastSeen", clock(server.last_seen * 1000)) : t("neverSeen")}</span></div>
      {/if}
      <div class="actions">
        <a class="btn" href="#/tunnels?s={encodeURIComponent(server.id)}"><Icon name="tunnels" />{t("tunnels")}</a>
        <a class="btn" href="#/logs?s={encodeURIComponent(server.id)}"><Icon name="logs" />{t("logs")}</a>
        <button class="btn danger" onclick={() => askRemove(server)}><Icon name="x" />{t("removeSrv")}</button>
      </div>
    </article>
  {/each}
</div>
{#if fleet.loaded && fleet.list.length === 0}
  <p class="muted mt16">{t("noServers")}</p>
{/if}

{#snippet renameButton(id, current)}
  <button class="btn ghost icon sm rename-btn" onclick={() => startRename(id, current)} title={t("renameSrv")} aria-label={t("renameSrv")}><Icon name="edit" /></button>
{/snippet}

{#snippet nameForm(id, own)}
  <form class="rename" onsubmit={(e) => { e.preventDefault(); saveName(id, own); }}>
    <label class="sr" for="rename-{id}">{t("renameSrv")}</label>
    <input id="rename-{id}" class="input" maxlength="40" bind:value={nameText} use:focus onkeydown={(e) => nameKeys(e, id, own)} aria-invalid={nameBad} aria-describedby="rename-hint-{id}" placeholder={own} />
    <div class="row-flex">
      <button class="btn primary sm" type="submit" disabled={saving} aria-busy={saving}><Icon name="check" />{t("save")}</button>
      <button class="btn ghost sm" type="button" onclick={() => (naming = null)}>{t("cancel")}</button>
    </div>
    <p id="rename-hint-{id}" class="small m0" class:muted={!nameBad} class:bad-text={nameBad}>{nameBad ? t("renameBad") : t("renameHint", own)}</p>
  </form>
{/snippet}

{#snippet load(host, key)}
  <div class="srv-load">
    {#each [["cpu", host?.cpu_pct], ["ram", host?.mem_pct], ["disk", host?.disk_pct]] as [k, v] (k)}
      <div class="srv-g"><Ring value={v} label={t(k)} id={key + k} /><span>{t(k)}</span></div>
    {/each}
    <div class="srv-side">
      <div><span class="k">{t("uptime")}</span><b class="num">{host?.uptime_sec != null ? duration(host.uptime_sec) : "-"}</b></div>
      <div><span class="k">{t("up")} / {t("down")}</span><b class="num ltr">{host?.tx_bps != null ? rate(host.tx_bps) : "-"} / {host?.rx_bps != null ? rate(host.rx_bps) : "-"} <small>Mb/s</small></b></div>
    </div>
  </div>
{/snippet}
