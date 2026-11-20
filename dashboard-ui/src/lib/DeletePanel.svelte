<script>
  // Deleting a tunnel, and optionally its other end when that end is on another managed server.
  // The name has to be typed, since nothing here can be undone.
  import Icon from "./Icon.svelte";
  import { deleteTunnel } from "./api.js";
  import { pending, pendingKey, say } from "./actions.svelte.js";
  import { live } from "./live.svelte.js";
  import { fleet, LOCAL, refreshFleet } from "./servers.svelte.js";
  import { t } from "./i18n.svelte.js";
  import { copyText } from "./share.js";

  /** `pair` is the tunnel's pair fingerprint: the other end has the same one. */
  let { name = "", server = LOCAL, pair = null, onclose } = $props();
  let dialog = $state();
  let typed = $state("");
  // The toast sits under an open dialog, so the name says it was copied itself.
  let nameCopied = $state(false);
  let copiedTimer;
  async function copyName() {
    if (await copyText(name, name)) {
      nameCopied = true;
      clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => (nameCopied = false), 1600);
    }
  }
  /** "server/name" keys of the other ends chosen for deleting too. */
  let also = $state({});
  let problem = $state("");
  // A replaced pair invalidates the dialog's original selection. Never retry it.
  let stalePair = $state(false);
  // Preserve failed targets even when live snapshots remove the successfully deleted primary.
  let remaining = $state(null);
  let targetCount = $state(0);

  $effect(() => {
    if (name && dialog && !dialog.open) {
      typed = "";
      also = {};
      problem = "";
      stalePair = false;
      remaining = null;
      targetCount = 0;
      dialog.showModal();
    }
    if (!name && dialog?.open) dialog.close();
  });

  /** The other ends: same pair, on this server or a joined one, other than this tunnel. */
  const others = $derived.by(() => {
    if (!pair) return [];
    const places = [{ id: LOCAL, name: t("thisServer"), online: true, tunnels: live.snapshot?.tunnels ?? [] }];
    for (const s of fleet.list) places.push({ id: s.id, name: s.name, online: s.online, tunnels: s.snapshot?.tunnels ?? [] });
    const found = [];
    for (const place of places) {
      for (const x of place.tunnels) {
        if (x.pair === pair && !(place.id === server && x.name === name)) {
          found.push({ key: `${place.id}/${x.name}`, server: place.id, serverName: place.name, name: x.name, online: place.online });
        }
      }
    }
    return found;
  });

  const key = $derived(pendingKey(name, server));
  const working = $derived(pending[key] === "delete");
  const confirmed = $derived(typed.trim() === name);

  function failure(status, data) {
    if (status === 401) return t("signedOutNow");
    if (data?.error === "pair_changed") return t("pairChangedT");
    if (status === 409) return t("busyT");
    return data?.detail ?? "";
  }

  async function run() {
    if (!confirmed || stalePair || pending[key] || pending["*"]) return;
    const targets = remaining ?? [{ server, name }, ...others.filter((o) => also[o.key] && o.online)];
    if (remaining === null) targetCount = targets.length;
    remaining = targets;
    pending[key] = "delete";
    problem = "";
    const failed = [];
    const retry = [];
    try {
      for (const target of targets) {
        const k = pendingKey(target.name, target.server);
        if (k !== key && (pending[k] || pending[`${target.server}/*`])) {
          failed.push(`${target.name}: ${t("busyT")}`);
          retry.push(target);
          continue;
        }
        if (k !== key) pending[k] = "delete";
        try {
          // Match the pair fingerprint under the Agent store lock so a reused name
          // cannot make this panel delete a different tunnel after a stale snapshot.
          const { status, data } = await deleteTunnel(target.name, target.server, pair);
          if (status !== 200) {
            failed.push(`${target.name}: ${failure(status, data)}`);
            if (data?.error === "pair_changed") {
              // Remaining targets came from the same stale selection; stop here.
              stalePair = true;
              break;
            }
            retry.push(target);
          }
        } catch {
          failed.push(`${target.name}: ${t("slowShort")}`);
          retry.push(target);
        } finally {
          if (k !== key) delete pending[k];
        }
      }
    } finally {
      delete pending[key];
    }
    refreshFleet();
    remaining = retry;
    if (failed.length) {
      problem = failed.join(" · ");
      return;
    }
    say(targetCount > 1 ? t("deletedBothT", name, targetCount) : t("deletedT", name));
    shut();
  }
  // Closes the panel and tells the page at once; some browsers deliver the dialog's own close
  // event late or not at all, which would leave the panel unable to open again.
  function shut() {
    if (dialog?.open) dialog.close();
    onclose?.();
  }
</script>

<dialog bind:this={dialog} class="delete-panel" aria-labelledby="del-title" aria-describedby="del-text" onclose={() => onclose?.()} oncancel={(e) => { e.preventDefault(); if (!(working)) shut(); }}>
  <div class="dlg-h">
    <span class="dlg-ico bad"><Icon name="trash" /></span>
    <h2 id="del-title">{t("deleteQ", name)}</h2>
    <button class="btn icon ghost" onclick={shut} disabled={working} aria-label={t("close")}><Icon name="x" /></button>
  </div>
  <div class="dlg-b edit-b">
    <div class="note bad" role="note"><Icon name="warn" /><span id="del-text">{t("deleteText")}</span></div>
    {#if others.length}
      <fieldset class="del-others" disabled={working || remaining !== null}>
        <legend class="flabel">{t("otherEnd")}</legend>
        {#each others as o (o.key)}
          <label class="del-other">
            <input type="checkbox" bind:checked={also[o.key]} disabled={!o.online} />
            <span>{t("alsoDelete")} <b class="ltr">{o.name}</b> {t("onServer")} <b class="ltr">{o.serverName}</b>{#if !o.online}{" "}<span class="muted">({t("srvOff")})</span>{/if}</span>
          </label>
        {/each}
      </fieldset>
    {:else if pair}
      <p class="muted small m0">{t("noOtherEnd")}</p>
    {/if}
    <div>
      <div class="flabel del-label"><label for="del-name">{t("typeName")}</label> <button type="button" class="name-copy ltr" class:done={nameCopied} onclick={copyName} title={t("clickCopy")}>{name}<Icon name={nameCopied ? "check" : "copy"} />{#if nameCopied}<span class="small">{t("copied")}</span>{/if}</button></div>
      <div class="unit-in del-type" class:ok={confirmed}><input id="del-name" class="input ltr" bind:value={typed} autocomplete="off" spellcheck="false" disabled={working} />{#if confirmed}<span><Icon name="check" /></span>{/if}</div>
    </div>
    {#if problem}
      <div class="note bad" role="alert"><Icon name="warn" /><span>{t("deleteFailed")} <span class="ltr">{problem}</span></span></div>
    {/if}
  </div>
  <div class="dlg-f">
    <button class="btn" onclick={shut} disabled={working}>{t("cancel")}</button>
    <button class="btn danger" onclick={run} disabled={!confirmed || working || stalePair} aria-busy={working}>
      <Icon name="trash" />{working ? t("deleting") : t("deleteTunnel")}
    </button>
  </div>
</dialog>
