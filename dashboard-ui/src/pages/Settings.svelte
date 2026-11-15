<script>
  // The dashboard's own settings: how it is reached, the password and signed-in sessions,
  // Telegram alerts, automatic backups, the download proxy, the metrics endpoint and the colours.
  import { untrack } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import { getSettings, saveSettings, setPassword, getSessions, revokeSession, testTelegram } from "../lib/api.js";
  import { say, ask } from "../lib/actions.svelte.js";
  import { t, num, duration, ui, setTheme, clock } from "../lib/i18n.svelte.js";
  import { copyText } from "../lib/share.js";

  let info = $state(null);
  let sessions = $state([]);
  let form = $state({ days: "7", proxy: "", tg: { enabled: false, token: "", chats: "", lang: "en", level: "bad", resolved: true } });
  let metricsToken = $state("");
  let saving = $state("");

  async function load() {
    try {
      const { status, data } = await getSettings();
      if (status !== 200) return;
      info = data;
      const p = data.prefs;
      form = {
        days: String(p.auto_backup_days), proxy: p.proxy ?? "",
        tg: { enabled: p.telegram.enabled, token: "", chats: p.telegram.chats.join(", "), lang: p.telegram.lang, level: p.telegram.level, resolved: p.telegram.resolved },
      };
    } catch {}
    loadSessions();
  }
  async function loadSessions() {
    try {
      const { status, data } = await getSessions();
      if (status === 200) sessions = data.sessions;
    } catch {}
  }
  $effect(() => {
    untrack(load);
  });

  async function save(part, body) {
    saving = part;
    try {
      const { status, data } = await saveSettings(body);
      if (status !== 200) {
        say(data?.detail ?? t("failedShort"), true);
        return false;
      }
      info.prefs = data.prefs;
      if (data.metrics_token) metricsToken = data.metrics_token;
      say(t("saved"));
      return true;
    } catch {
      say(t("slowShort"), true);
      return false;
    } finally {
      saving = "";
    }
  }

  // Telegram: what is saved, what the form would change, and how the last message went.
  const chatList = (text) => text.split(/[,\s]+/).filter(Boolean).map(Number);
  const tgSaved = $derived(info?.prefs?.telegram);
  const tgDirty = $derived(Boolean(tgSaved) && (
    form.tg.token.trim() !== "" || form.tg.enabled !== tgSaved.enabled || form.tg.lang !== tgSaved.lang ||
    form.tg.level !== tgSaved.level || form.tg.resolved !== tgSaved.resolved ||
    chatList(form.tg.chats).join(",") !== tgSaved.chats.join(",")));
  const tgState = $derived(!tgSaved?.token_set ? "none" : tgSaved.enabled ? "on" : "off");
  let tgSavedAt = $state(0);
  // A failure to reach Telegram at all (not a refusal from it): usually blocked from this server.
  const unreachable = (detail) => /timed out|Could not resolve|Failed to connect|Connection refused|curl: \((6|7|28|35|56)\)/i.test(detail ?? "");

  function saveTelegram() {
    const token = form.tg.token;
    const chats = chatList(form.tg.chats);
    if (chats.some((c) => !Number.isInteger(c))) return say(t("tgChatsBad"), true);
    const telegram = { enabled: form.tg.enabled, chats, lang: form.tg.lang, level: form.tg.level, resolved: form.tg.resolved };
    if (form.tg.token.trim()) telegram.token = form.tg.token.trim();
    save("telegram", { telegram }).then((ok) => {
      if (ok && form.tg.token === token) form.tg.token = "";
      if (ok) tgSavedAt = Date.now();
    });
  }

  function removeBot() {
    ask(t("tgRemoveQ"), t("tgRemoveText"), t("tgRemove"), async () => {
      if (await save("telegram", { telegram: { enabled: false, token: "" } })) {
        form.tg.enabled = false;
        form.tg.token = "";
        tgSavedAt = Date.now();
      }
    });
  }

  async function test() {
    const chats = chatList(form.tg.chats);
    if (chats.some((c) => !Number.isInteger(c))) return say(t("tgChatsBad"), true);
    // The form's values are tried as they are, saved or not.
    const telegram = { chats, lang: form.tg.lang };
    if (form.tg.token.trim()) telegram.token = form.tg.token.trim();
    saving = "test";
    try {
      const { status, data } = await testTelegram({ telegram });
      say(status === 200 ? t("tgSent") : `${t("tgFailed")} ${data?.detail ?? ""}`, status !== 200);
    } catch {
      say(t("slowShort"), true);
    } finally {
      saving = "";
      refreshLast();
    }
  }
  async function refreshLast() {
    try {
      const { status, data } = await getSettings();
      if (status === 200) info.telegram_last = data.telegram_last;
    } catch {}
  }

  // Password.
  let pw = $state({ current: "", next: "", again: "" });
  const pwError = $derived(pw.next && pw.next.length < 12 ? t("pwShort") : pw.again && pw.again !== pw.next ? t("pwMismatch") : "");
  async function changePassword(event) {
    event.preventDefault();
    if (pwError || !pw.current || !pw.next) return;
    saving = "password";
    try {
      const { status, data } = await setPassword(pw.current, pw.next);
      if (status !== 200) return say(data?.detail ?? t("failedShort"), true);
      pw = { current: "", next: "", again: "" };
      say(t("pwDone"));
      loadSessions();
    } catch {
      say(t("slowShort"), true);
    } finally {
      saving = "";
    }
  }

  function end(id) {
    const all = id === "others";
    ask(t(all ? "sesAllQ" : "sesQ"), t("sesText"), t("sesEnd"), async () => {
      try {
        const { status, data } = await revokeSession(id);
        if (status === 200) say(t("sesEnded", num(data.ended)));
        else say(data?.detail ?? t("failedShort"), true);
        loadSessions();
      } catch { say(t("slowShort"), true); }
    });
  }

  function metrics(on) {
    if (on) return save("metrics", { metrics: true });
    ask(t("mxOffQ"), t("mxOffText"), t("mxOff"), () => {
      metricsToken = "";
      save("metrics", { metrics: false });
    });
  }
  const certLeft = $derived(info?.panel?.cert?.not_after ? info.panel.cert.not_after - Date.now() / 1000 : null);
  const origin = typeof location !== "undefined" ? location.origin : "";
</script>

{#if !info}
  <div class="panel act-empty">{t("loadingT")}</div>
{:else}
  <div class="tp-grid">
    <section class="panel" aria-labelledby="st-panel">
      <h3 id="st-panel" class="sec-h">{t("stPanel")}</h3>
      <dl class="facts">
        <div><dt>{t("stAddress")}</dt><dd class="ltr">{info.panel.https ? "https" : "http"}://{info.panel.address}:{info.panel.port}</dd></div>
        <div><dt>{t("stCert")}</dt><dd>{#if info.panel.cert}{info.panel.cert.lets_encrypt ? "Let's Encrypt" : t("stSelfSigned")}{#if certLeft != null && (info.panel.cert.lets_encrypt || certLeft < 400 * 86400)}{" · "}{t("stCertLeft", duration(Math.max(0, certLeft)))}{/if}{:else}-{/if}</dd></div>
        <div><dt>{t("versionF")}</dt><dd class="ltr">{info.panel.version}</dd></div>
        <div><dt>{t("stData")}</dt><dd class="ltr mono">{info.panel.state_dir}</dd></div>
      </dl>
      <p class="muted small m0 mt12">{t("stPanelNote")}</p>
      <div class="cmdline ltr mt12">eztunnel dashboard certificate --lets-encrypt</div>
    </section>

    <section class="panel" aria-labelledby="st-pw">
      <h3 id="st-pw" class="sec-h">{t("pwH")}</h3>
      <form onsubmit={changePassword}>
        <input type="text" class="sr" autocomplete="username" value="admin" readonly tabindex="-1" aria-hidden="true" />
        <label class="flabel" for="pw-cur">{t("pwCurrent")}</label>
        <input id="pw-cur" class="input" type="password" autocomplete="current-password" bind:value={pw.current} />
        <label class="flabel mt12" for="pw-new">{t("pwNew")}</label>
        <input id="pw-new" class="input" type="password" autocomplete="new-password" bind:value={pw.next} aria-invalid={Boolean(pwError)} />
        <label class="flabel mt12" for="pw-again">{t("pwAgain")}</label>
        <input id="pw-again" class="input" type="password" autocomplete="new-password" bind:value={pw.again} aria-invalid={Boolean(pwError)} aria-describedby="pw-help" />
        <p id="pw-help" class="small m0 ehelp {pwError ? 'bad-t' : 'muted'}">{pwError || t("pwHelp")}</p>
        <button class="btn primary mt12" disabled={saving === "password" || !pw.current || !pw.next || pw.next !== pw.again || Boolean(pwError)}>{t("pwChange")}</button>
      </form>
    </section>
  </div>

  <div class="tp-grid mt16 st-pair">
  <section class="panel" aria-labelledby="st-tg">
    <div class="sec-row">
      <h3 id="st-tg" class="sec-h grow m0">{t("tgH")}</h3>
      <span class="pill {tgState === 'on' ? 'ok' : 'off'}">{t(tgState === "on" ? "tgStateOn" : tgState === "off" ? "tgStateOff" : "tgStateNone")}</span>
    </div>
    <p class="muted small">{t("tgAbout")}</p>
    <dl class="facts tg-facts">
      <div><dt>{t("tgBot")}</dt><dd>{#if tgSaved.token_set}<span class="ltr">{t("tgBotSaved", tgSaved.bot_id ?? "?")}</span>{:else}<span class="muted">{t("tgBotNone")}</span>{/if}</dd></div>
      <div><dt>{t("tgChats")}</dt><dd class="ltr">{tgSaved.chats.length ? tgSaved.chats.join(", ") : "-"}</dd></div>
      <div><dt>{t("tgLast")}</dt><dd>
        {#if info.telegram_last}
          <span class={info.telegram_last.ok ? "ok-t" : "bad-t"}>{t(info.telegram_last.ok ? "tgLastOk" : "tgLastBad", t(info.telegram_last.kind === "test" ? "tgKindTest" : "tgKindAlert"))}</span>
          <span class="muted"> · {clock(info.telegram_last.at * 1000)}</span>
        {:else}<span class="muted">{t("tgLastNone")}</span>{/if}
      </dd></div>
    </dl>
    {#if info.telegram_last && !info.telegram_last.ok}
      <div class="note bad mt12" role="note"><Icon name="warn" /><span><span class="ltr edesc">{info.telegram_last.detail}</span>{#if unreachable(info.telegram_last.detail)}<br />{t(info.prefs.proxy ? "tgNetProxy" : "tgNetHint")}{/if}</span></div>
    {/if}
    <hr class="sep" />
    <label class="switch"><input type="checkbox" role="switch" bind:checked={form.tg.enabled} /><span>{t("tgOn")}</span></label>
    <div class="erow mt12">
      <div class="grow">
        <label class="flabel" for="tg-token">{t("tgToken")}</label>
        <input id="tg-token" class="input ltr" type="password" autocomplete="off" bind:value={form.tg.token} placeholder={info.prefs.telegram.token_set ? t("tgTokenSaved") : "123456789:ABC…"} />
      </div>
      <div class="grow">
        <label class="flabel" for="tg-chats">{t("tgChats")}</label>
        <input id="tg-chats" class="input ltr" bind:value={form.tg.chats} placeholder="123456789, -100123456789" autocomplete="off" />
      </div>
    </div>
    <div class="erow mt12">
      <div class="grow">
        <label class="flabel" for="tg-lang">{t("tgLang")}</label>
        <select id="tg-lang" class="input" bind:value={form.tg.lang}><option value="en">English</option><option value="fa">فارسی</option></select>
      </div>
      <div class="grow">
        <label class="flabel" for="tg-level">{t("tgLevel")}</label>
        <select id="tg-level" class="input" bind:value={form.tg.level}><option value="bad">{t("tgBad")}</option><option value="all">{t("tgAll")}</option></select>
      </div>
    </div>
    <label class="switch mt12"><input type="checkbox" role="switch" bind:checked={form.tg.resolved} /><span>{t("tgResolved")}</span></label>
    <p class="muted small m0 mt12">{t("tgHelp")}</p>
    <div class="row-flex mt12">
      <button class="btn primary" onclick={saveTelegram} disabled={saving === "telegram" || !tgDirty} aria-busy={saving === "telegram"}><Icon name="check" />{t("save")}</button>
      <button class="btn" onclick={test} disabled={saving === "test" || (!tgSaved.token_set && !form.tg.token.trim()) || !form.tg.chats.trim()} aria-busy={saving === "test"}><Icon name="telegram" />{saving === "test" ? t("working") : t("tgTest")}</button>
      <span class="grow small" role="status">{#if tgDirty}<span class="warn-t">{t("tgUnsaved")}</span>{:else if tgSavedAt}<span class="ok-t">{t("tgSavedAt", clock(tgSavedAt))}</span>{/if}</span>
      {#if tgSaved.token_set}<button class="btn ghost danger" onclick={removeBot}><Icon name="trash" />{t("tgRemove")}</button>{/if}
    </div>
    <p class="muted small m0 mt12">{t("tgTestNote")}</p>
  </section>

  <div class="st-stack">
    <section class="panel" aria-labelledby="st-proxy">
      <h3 id="st-proxy" class="sec-h">{t("pxH")}</h3>
      <label class="flabel" for="st-px">{t("pxLabel")}</label>
      <div class="row-flex">
        <input id="st-px" class="input ltr grow" bind:value={form.proxy} placeholder="socks5h://127.0.0.1:1080" autocomplete="off" spellcheck="false" />
        <button class="btn" onclick={() => save("proxy", { proxy: form.proxy })} disabled={saving === "proxy"}>{t("save")}</button>
      </div>
      <p class="muted small m0 mt12">{t("pxHelp")}</p>
    </section>

    <section class="panel" aria-labelledby="st-ses">
      <div class="row-flex mb16">
        <h3 id="st-ses" class="sec-h grow m0">{t("sesH")}</h3>
        <button class="btn" onclick={() => end("others")} disabled={sessions.length < 2}>{t("sesAll")}</button>
      </div>
      <ul class="row-list">
        {#each sessions as s (s.id)}
          <li>
            <span class="mark {s.current ? 'ok' : 'off'}" aria-hidden="true"></span>
            <div class="grow bk-main"><b class="ltr">{s.ip ?? "?"}</b><span class="muted small">{t("sesAge", duration(Math.max(60, s.age_sec)), duration(Math.max(60, s.idle_sec)))}</span></div>
            {#if s.current}<span class="pill ok">{t("sesThis")}</span>{:else}<button class="btn ghost" onclick={() => end(s.id)}><Icon name="logout" />{t("sesEnd")}</button>{/if}
          </li>
        {/each}
      </ul>
    </section>
  </div>
  </div>

  <div class="tp-grid mt16">
    <section class="panel" aria-labelledby="st-mx">
      <h3 id="st-mx" class="sec-h">{t("mxH")}</h3>
      <p class="muted small">{t("mxAbout")}</p>
      {#if metricsToken}
        <div class="note warn" role="note"><Icon name="lock" /><span>{t("mxOnce")}</span></div>
        <div class="code-box ltr mono mt12 copy-box"><span class="grow">curl -k -H "Authorization: Bearer {metricsToken}" {origin}/metrics</span><button type="button" class="btn ghost icon" onclick={() => copyText(`curl -k -H "Authorization: Bearer ${metricsToken}" ${origin}/metrics`)} title={t("copy")} aria-label={t("copy")}><Icon name="copy" /></button></div>
      {/if}
      <div class="row-flex mt12">
        {#if info.prefs.metrics}
          <span class="grow"><span class="pill ok">{t("mxIsOn")}</span></span>
          <button class="btn" onclick={() => metrics(false)}>{t("mxOff")}</button>
        {:else}
          <span class="grow"><span class="pill off">{t("mxIsOff")}</span></span>
          <button class="btn primary" onclick={() => metrics(true)}>{t("mxOn")}</button>
        {/if}
      </div>
    </section>

    <section class="panel" aria-labelledby="st-look">
      <h3 id="st-look" class="sec-h">{t("lookH")}</h3>
      <p class="muted small">{t("lookAbout")}</p>
      <div class="tabs" role="group" aria-labelledby="st-look">
        {#each ["dark", "light"] as th}
          <button aria-pressed={ui.theme === th} onclick={() => setTheme(th)}>{t(th)}</button>
        {/each}
      </div>
      <p class="muted small m0 mt12">{t("pwaNote")}</p>
    </section>
  </div>
{/if}
