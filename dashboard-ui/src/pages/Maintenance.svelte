<script>
  // Program versions on every server, official releases (checked, downloaded or uploaded),
  // installing one server at a time or all of them in stages, rollback, and backups.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { serverTool, getReleases, checkRelease, fetchRelease, uploadProgram, installOn, getBackups, backupNow, deleteBackup, restoreBackup, saveSettings } from "../lib/api.js";
  import { say, ask } from "../lib/actions.svelte.js";
  import { live } from "../lib/live.svelte.js";
  import { fleet, LOCAL, localName } from "../lib/servers.svelte.js";
  import { t, num, amount } from "../lib/i18n.svelte.js";

  const places = $derived([
    { id: LOCAL, name: t("thisServerIs", localName(live.snapshot?.host?.hostname)), online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, online: s.online })),
  ]);
  const nameOf = (id) => places.find((p) => p.id === id)?.name ?? id;
  const when = (secs) => (secs ? new Date(secs * 1000).toLocaleString(document.documentElement.lang === "fa" ? "fa-IR" : "en-GB") : "-");
  const size = (bytes) => amount(bytes ?? 0).join(" ");

  // Versions per server.
  let versions = $state({});
  async function loadVersions() {
    for (const p of places.filter((p) => p.online)) {
      serverTool(p.id, "versions").then(({ status, data }) => {
        versions[p.id] = status === 200 ? data : { error: data?.detail ?? t("failedShort") };
      }).catch(() => (versions[p.id] = { error: t("slowShort") }));
    }
  }
  const onlineIds = $derived(places.filter((p) => p.online).map((p) => p.id).join(","));
  $effect(() => {
    onlineIds;
    untrack(loadVersions);
  });

  // Releases.
  let kept = $state([]);
  let latest = $state(null);
  let checking = $state(false);
  let fetching = $state("");
  let uploading = $state(false);
  let releaseError = $state("");
  async function loadKept() {
    try {
      const { status, data } = await getReleases();
      if (status === 200) kept = data.kept;
    } catch {}
  }
  async function check() {
    checking = true;
    releaseError = "";
    try {
      const { status, data } = await checkRelease();
      if (status === 200) latest = data;
      else releaseError = data?.detail ?? t("failedShort");
    } catch {
      releaseError = t("slowShort");
    } finally {
      checking = false;
    }
  }
  /** The newest release for a CPU type: kept already, or downloaded and checked now. */
  async function releaseFor(arch) {
    const want = bare(latest?.version);
    const have = kept.find((k) => k.arch === arch && bare(k.version) === want);
    if (have) return have;
    fetching = arch;
    try {
      const { status, data } = await fetchRelease(latest?.version ?? "latest", arch);
      if (status !== 200) throw new Error(data?.detail ?? t("failedShort"));
      return data;
    } finally {
      fetching = "";
      loadKept();
    }
  }
  async function upload(event) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    uploading = true;
    releaseError = "";
    try {
      const { status, data } = await uploadProgram(file);
      if (status === 200) say(t("relKept", data.version || data.arch));
      else releaseError = data?.detail ?? t("failedShort");
    } catch {
      releaseError = t("slowShort");
    } finally {
      uploading = false;
      loadKept();
    }
  }

  // Installing: one server, or every matching server in turn (the first one as a canary).
  let chosen = $state("");
  const program = $derived(kept.find((k) => k.file === chosen) ?? kept[0]);
  let installing = $state({});
  let staged = $state(null);
  async function installOne(id, file, allowDowngrade = false) {
    if (!file) return false;
    installing[id] = "running";
    try {
      const { status, data } = await installOn(id, file, allowDowngrade);
      installing[id] = status === 200 ? "done" : "failed";
      if (status !== 200) say(`${nameOf(id)}: ${data?.detail ?? t("failedShort")}`, true);
      return status === 200;
    } catch {
      installing[id] = "failed";
      return false;
    } finally {
      loadVersions();
    }
  }
  /** Whether version `a` is the same as or older than `b` (0.9.14 style). */
  function older(a, b) {
    const parts = (x) => x.split(/[.+-]/).slice(0, 3).map((n) => Number(n) || 0);
    const [p, q] = [parts(a), parts(b)];
    for (let i = 0; i < 3; i++) if (p[i] !== q[i]) return p[i] < q[i];
    return true;
  }
  function confirmInstall(id) {
    const file = program?.file;
    const v = versions[id];
    const downgrade = Boolean(program?.version && v?.installed && older(program.version, v.installed));
    ask(t("instQ", program?.version || file, nameOf(id)), t(downgrade ? "instSameText" : "instText"), t("install"), () => installOne(id, file, downgrade));
  }
  // Updating to the newest official release: each server's CPU type is known, so the right file is
  // picked (and downloaded once) by the dashboard; the reader only says yes or no.
  const isNewer = (a, b) => Boolean(a && b) && !older(a, b);
  const updatable = (id) => {
    const v = versions[id];
    return Boolean(latest?.version && v?.installed && v?.arch) && isNewer(bare(latest.version), bare(v.installed));
  };
  const aheadOf = (id) => Boolean(latest?.version && versions[id]?.installed) && isNewer(bare(versions[id].installed), bare(latest.version));
  const toUpdate = $derived(places.filter((p) => p.online && updatable(p.id)));
  async function updateOne(id) {
    const v = versions[id];
    installing[id] = "running";
    try {
      const program = await releaseFor(v.arch);
      return await installOne(id, program.file);
    } catch (failure) {
      installing[id] = "failed";
      say(`${nameOf(id)}: ${failure.message}`, true);
      return false;
    }
  }
  function confirmUpdate(id) {
    const v = versions[id];
    ask(t("updQ", nameOf(id), latest.version), t("updText", v.installed, latest.version, v.arch), t("updGo"), () => updateOne(id));
  }
  function updateAll() {
    const order = toUpdate.map((p) => p.id);
    if (!order.length) return;
    ask(t("updAllQ", num(order.length), latest.version), t("stageText"), t("updGo"), async () => {
      if (staged?.running) return;
      staged = { running: true, cancel: false, order };
      for (const id of order) {
        if (staged.cancel) break;
        if (!(await updateOne(id))) {
          say(t("stageStopped", nameOf(id)), true);
          break;
        }
      }
      staged.running = false;
    });
  }

  // Only servers the program would update: the updater refuses the same or an older version,
  // which would stop the rollout at the first server that is already current.
  const matching = $derived(
    places.filter((p) => {
      const v = versions[p.id];
      if (!p.online || v?.arch !== program?.arch) return false;
      return !program?.version || !v?.installed || !older(program.version, v.installed);
    }),
  );
  function stagedUpgrade() {
    const file = program?.file;
    const order = matching.map((p) => p.id);
    if (!file || !order.length) return;
    ask(t("stageQ", num(order.length)), t("stageText"), t("stageGo"), async () => {
      if (staged?.running) return;
      staged = { running: true, cancel: false, file, order };
      for (const id of order) {
        if (staged.cancel) break;
        const ok = await installOne(id, file);
        if (!ok) {
          say(t("stageStopped", nameOf(id)), true);
          break;
        }
      }
      staged.running = false;
    });
  }
  function rollback(id) {
    ask(t("rbQ", nameOf(id)), t("rbText"), t("rollback"), async () => {
      installing[id] = "running";
      try {
        const { status, data } = await serverTool(id, "rollback");
        installing[id] = status === 200 ? "done" : "failed";
        say(status === 200 ? t("rbDone", nameOf(id)) : `${t("failedShort")}: ${data?.detail ?? ""}`, status !== 200);
      } catch {
        installing[id] = "failed";
      } finally {
        loadVersions();
      }
    });
  }

  // Backups.
  let backups = $state([]);
  let auto = $state(7);
  let backingUp = $state(false);
  async function loadBackups() {
    try {
      const { status, data } = await getBackups();
      if (status === 200) {
        backups = data.backups;
        auto = data.auto;
      }
    } catch {}
  }
  async function backupAll() {
    backingUp = true;
    try {
      const { status, data } = await backupNow();
      const failed = status === 200 ? data.results.filter((r) => r.error) : [];
      say(status !== 200 ? t("failedShort") : failed.length ? t("bkSome", failed.map((r) => nameOf(r.server)).join(", ")) : t("bkDone", num(data.results.length)), status !== 200 || failed.length > 0);
    } catch {
      say(t("slowShort"), true);
    } finally {
      backingUp = false;
      loadBackups();
    }
  }
  let restoreTo = $state({});
  let replace = $state(false);
  let replaceFile = $state(false);
  function restore(b) {
    const to = restoreTo[b.file] ?? (places.some((p) => p.id === b.server) ? b.server : LOCAL);
    ask(t("rsQ", nameOf(to)), t(replace ? "rsReplaceText" : "rsKeepText"), t("restore"), async () => {
      try {
        const { status, data } = await restoreBackup(to, { file: b.file, replace });
        if (status !== 200) return say(`${t("failedShort")}: ${data?.detail ?? ""}`, true);
        { const down = (data.started ?? []).filter((x) => !x.came_up).map((x) => x.name); if (down.length) say(t("rsNotUp", down.join(", ")), true); else say(t("rsDone", num(data.imported.length), num(data.skipped.length), num(data.failed.length)), data.failed.length > 0); }
      } catch {
        say(t("slowShort"), true);
      }
    });
  }
  async function restoreFile(event, to) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    const text = await file.text();
    const replace = replaceFile;
    ask(t("rsQ", nameOf(to)), t(replace ? "rsReplaceText" : "rsKeepText"), t("restore"), async () => {
      try {
        const { status, data } = await restoreBackup(to, { text, replace });
        if (status !== 200) return say(`${t("failedShort")}: ${data?.detail ?? ""}`, true);
        { const down = (data.started ?? []).filter((x) => !x.came_up).map((x) => x.name); if (down.length) say(t("rsNotUp", down.join(", ")), true); else say(t("rsDone", num(data.imported.length), num(data.skipped.length), num(data.failed.length)), data.failed.length > 0); }
      } catch {
        say(t("slowShort"), true);
      }
    });
  }
  function remove(b) {
    ask(t("bkDelQ"), t("bkDelText"), t("delete"), async () => {
      try {
        const { status, data } = await deleteBackup(b.file);
        if (status === 200) loadBackups();
        else say(data?.detail ?? t("failedShort"), true);
      } catch { say(t("slowShort"), true); }
    });
  }
  let uploadTo = $state(LOCAL);
  // Backups by server, newest first; the open row shows where and how to restore.
  let opened = $state("");
  const groups = $derived.by(() => {
    const by = new Map();
    for (const b of [...backups].sort((x, y) => y.at - x.at)) {
      if (!by.has(b.server)) by.set(b.server, []);
      by.get(b.server).push(b);
    }
    return [...by.entries()];
  });

  $effect(() => {
    untrack(() => {
      loadKept();
      loadBackups();
      check();
    });
  });

  // Automatic backups, set here beside the backups themselves.
  let savingAuto = $state(false);
  async function setAuto(days) {
    savingAuto = true;
    try {
      const { status, data } = await saveSettings({ auto_backup_days: days });
      if (status === 200) {
        auto = data.prefs.auto_backup_days;
        say(t("saved"));
      } else say(data?.detail ?? t("failedShort"), true);
    } catch {
      say(t("slowShort"), true);
    } finally {
      savingAuto = false;
    }
  }
  const bare = (v) => String(v ?? "").replace(/^v/, "");
</script>

<section aria-labelledby="mt-ver">
  <div class="sec-head mt0"><h2 id="mt-ver">{t("verH")}</h2></div>
  <div class="mt-grid">
    {#each places as p (p.id)}
      {@const v = versions[p.id]}
      {@const newer = updatable(p.id)}
      <article class="panel mt-srv" class:off={!p.online}>
        <header>
          <span class="mark {p.online ? 'ok' : 'off'}"></span>
          <h3 class="grow">{p.name}</h3>
          {#if v?.arch}<span class="code-chip ltr">{v.arch}</span>{/if}
        </header>
        {#if !p.online}
          <p class="muted m0">{t("offline")}</p>
        {:else if !v}
          <div class="loading"><div class="blocks"></div></div>
        {:else if v.error}
          <p class="bad-t m0 small">{v.error}</p>
        {:else}
          <div class="mt-ver">
            <span class="mt-num ltr">{v.installed ?? "-"}</span>
            {#if newer}<span class="pill warn">{t("verNewer", latest.version)}</span>{:else if aheadOf(p.id)}<span class="pill ok">{t("verAhead")}</span>{:else if latest}<span class="pill ok">{t("verCurrent")}</span>{/if}
          </div>
          <p class="muted small m0">{t("verPrevious")}: <span class="ltr">{v.has_previous ? (v.previous ?? "?") : "-"}</span>{#if v.has_previous && v.previous && v.previous === v.installed}{" · "}{t("verEarlierBuild")}{/if}</p>
          {#if v.restart_needed}<p class="warn-t small m0">{t("verRestartNeeded", p.id === "local" ? t("verDashboard") : t("verAgent"))}</p>{/if}
          <div class="mt-act">
            {#if installing[p.id] === "running"}<span class="muted small" role="status">{t("working")}</span>{:else}
              {#if newer}<button class="btn primary" onclick={() => confirmUpdate(p.id)} disabled={Boolean(staged?.running) || Boolean(fetching)}><Icon name="download" />{t("updTo", latest.version)}</button>{/if}
              {#if program && program.arch === v.arch}<button class="btn" onclick={() => confirmInstall(p.id)} disabled={Boolean(staged?.running)} title={t("instKeptHelp")}><Icon name="play" />{t("instKept")}</button>{/if}
              {#if v.has_previous}<button class="btn ghost" onclick={() => rollback(p.id)} disabled={Boolean(staged?.running)}><Icon name="undo" />{t("rollback")}</button>{/if}
              {#if installing[p.id] === "done"}<span class="ok-t small">{t("fixDone")}</span>{:else if installing[p.id] === "failed"}<span class="bad-t small">{t("failedShort")}</span>{/if}
            {/if}
          </div>
        {/if}
      </article>
    {/each}
  </div>

  <div class="panel mt-stage">
    {#if kept.length}
      <div class="mt-stage-row">
        <label class="picker" for="mt-prog">
          <Icon name="maintenance" /><span>{t("instWhich")}</span>
          <select id="mt-prog" bind:value={chosen} disabled={Boolean(staged?.running)}>
            {#each kept as k (k.file)}<option value={k.file}>{k.version || "?"} · {k.arch} · {k.sha256.slice(0, 12)}</option>{/each}
          </select>
        </label>
        <div class="grow"></div>
        {#if staged?.running}<button class="btn" onclick={() => (staged.cancel = true)} disabled={staged.cancel}><Icon name="stop" />{t("stageCancel")}</button>{/if}
        <button class="btn primary" onclick={stagedUpgrade} disabled={!matching.length || Boolean(staged?.running)} aria-busy={Boolean(staged?.running)}><Icon name="route" />{t("stageBtn", num(matching.length))}</button>
      </div>
      <p class="muted small m0">{t("instNote")}</p>
    {:else}
      <p class="muted small m0">{t("instNone")}</p>
    {/if}
  </div>
</section>

<div class="mt-cols">
  <section class="panel" aria-labelledby="mt-rel">
    <div class="sec-row">
      <h3 id="mt-rel" class="sec-h grow m0">{t("relH")}</h3>
      <button class="btn" onclick={check} disabled={checking} aria-busy={checking}><Icon name="restart" />{checking ? t("hcRunning") : t("relCheck")}</button>
      <label class="btn" class:disabled={uploading}>
        <input type="file" class="sr" onchange={upload} disabled={uploading} /><Icon name="plus" />{uploading ? t("working") : t("relUpload")}
      </label>
    </div>
    <p class="muted small">{t("relAbout")} {t("relUploadHelp")}</p>
    {#if latest}
      <div class="rel-card">
        <div class="rel-top">
          <div class="grow">
            <span class="eyebrow">{t("relLatestT")}</span><span class="mt-num ltr">{latest.version}</span>
            <span class="small {toUpdate.length ? 'warn-t' : 'muted'} rel-state">{toUpdate.length ? t("updCount", num(toUpdate.length)) : places.some((p) => aheadOf(p.id)) ? t("updAhead") : t("updNone")}</span>
          </div>
          {#if staged?.running}<button class="btn" onclick={() => (staged.cancel = true)} disabled={staged.cancel}><Icon name="stop" />{t("stageCancel")}</button>{/if}
          {#if toUpdate.length}<button class="btn primary" onclick={updateAll} disabled={Boolean(staged?.running) || Boolean(fetching)} aria-busy={Boolean(staged?.running)}><Icon name="download" />{fetching ? t("updFetching", fetching) : t("updAll", num(toUpdate.length))}</button>{/if}
        </div>
        {#if latest.notes}<details><summary class="muted small">{t("relNotes")}</summary><pre class="notes ltr">{latest.notes}</pre></details>{/if}
      </div>
    {/if}
    {#if releaseError}<div class="note bad mt12" role="alert"><Icon name="warn" /><span class="ltr">{releaseError}</span></div>{/if}
    {#if kept.length}
      <h4 class="mt-sub">{t("relKept")}</h4>
      <ul class="row-list">
        {#each kept as k (k.file)}
          <li>
            <span class="mt-num sm ltr">{k.version || "?"}</span>
            <span class="code-chip ltr">{k.arch}</span>
            <span class="mono muted small ltr grow" title={k.sha256}>{k.sha256.slice(0, 16)}…</span>
            <span class="row-meta"><span>{size(k.size)}</span><span class="muted">{when(k.added)}</span></span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="panel" aria-labelledby="mt-bk">
    <div class="sec-row">
      <h3 id="mt-bk" class="sec-h grow m0">{t("bkH")}</h3>
    </div>
    <div class="bk-auto">
      <label class="picker" for="bk-auto">
        <Icon name="restart" /><span>{t("bkEvery")}</span>
        <select id="bk-auto" value={String(auto)} onchange={(e) => setAuto(+e.currentTarget.value)} disabled={savingAuto}>
          {#each [0, 1, 3, 7, 14, 30] as d}<option value={String(d)}>{d === 0 ? t("bkOff") : t("bkDays", num(d))}</option>{/each}
        </select>
      </label>
      <button class="btn primary bk-now" onclick={backupAll} disabled={backingUp} aria-busy={backingUp} title={t("bkNow")}><Icon name="plus" />{backingUp ? t("working") : t("bkNowShort")}</button>
    </div>
    <p class="muted small m0 mt8">{t("bkEveryHelp")}</p>
    <div class="note warn mt12 mb16" role="note"><Icon name="lock" /><span>{t("bkSecret")}</span></div>
    {#if backups.length}
      {#each groups as [server, list] (server)}
        <div class="bk-group">
          <div class="bk-gh">
            <span class="mark {places.some((p) => p.id === server && p.online) ? 'ok' : 'off'}"></span>
            <b class="grow">{nameOf(server)}</b>
            <span class="muted small">{t("bkCount", num(list.length))}</span>
          </div>
          <ul class="row-list bk-list">
            {#each list as b, i (b.file)}
              <li class:open={opened === b.file}>
                <div class="bk-row">
                  <div class="bk-main grow">
                    <b><span class="bk-date">{when(b.at)}</span>{#if i === 0}<span class="pill ok bk-new">{t("bkNewest")}</span>{/if}</b>
                    <span class="muted small">{size(b.size)}</span>
                  </div>
                  <div class="bk-act">
                    <button class="btn" onclick={() => (opened = opened === b.file ? "" : b.file)} aria-expanded={opened === b.file}><Icon name="undo" />{t("restore")}</button>
                    <a class="btn ghost icon" href="/api/backups/{encodeURIComponent(b.file)}" download aria-label="{t('download')} {when(b.at)}" title={t("download")}><Icon name="download" /></a>
                    <button class="btn ghost danger icon" onclick={() => remove(b)} aria-label="{t('delete')} {when(b.at)}" title={t("delete")}><Icon name="trash" /></button>
                  </div>
                </div>
                {#if opened === b.file}
                  <div class="bk-restore">
                    <label class="picker" for="rs-{b.file}">
                      <Icon name="servers" /><span>{t("rsTo")}</span>
                      <select id="rs-{b.file}" value={restoreTo[b.file] ?? (places.some((p) => p.id === b.server) ? b.server : LOCAL)} onchange={(e) => (restoreTo[b.file] = e.currentTarget.value)}>
                        {#each places.filter((p) => p.online) as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
                      </select>
                    </label>
                    <label class="chk"><input type="checkbox" bind:checked={replace} /><span>{t("rsReplace")}</span></label>
                    <div class="row-flex">
                      <button class="btn primary" onclick={() => restore(b)}><Icon name="undo" />{t("restore")}</button>
                      <button class="btn ghost" onclick={() => (opened = "")}>{t("cancel")}</button>
                    </div>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      {/each}
    {:else}
      <div class="bk-empty"><Icon name="lock" /><span class="muted">{t("bkNone")}</span></div>
    {/if}
    <div class="bk-up">
      <h4 class="mt-sub m0">{t("rsFileH")}</h4>
      <p class="muted small m0">{t("rsFileHelp")}</p>
      <div class="bk-restore">
        <label class="picker" for="rs-up-to">
          <Icon name="servers" /><span>{t("rsUploadTo")}</span>
          <select id="rs-up-to" bind:value={uploadTo}>{#each places.filter((p) => p.online) as p (p.id)}<option value={p.id}>{p.name}</option>{/each}</select>
        </label>
        <label class="chk"><input type="checkbox" bind:checked={replaceFile} /><span>{t("rsReplace")}</span></label>
        <div class="row-flex">
          <label class="btn"><input type="file" accept=".json,application/json" class="sr" onchange={(e) => restoreFile(e, uploadTo)} /><Icon name="plus" />{t("rsUpload")}</label>
        </div>
      </div>
    </div>
  </section>
</div>
