<script>
  import Logo from "../lib/Logo.svelte";
  import Icon from "../lib/Icon.svelte";
  import { t, ui, setLang, setTheme, wait } from "../lib/i18n.svelte.js";
  import { login } from "../lib/api.js";

  let { onSignedIn } = $props();
  let password = $state("");
  let error = $state("");
  let busy = $state(false);
  let input;

  async function submit(event) {
    event.preventDefault();
    if (!password) {
      error = t("pwErr");
      input.focus();
      return;
    }
    busy = true;
    error = "";
    try {
      const { status, data } = await login(password);
      if (status === 200) {
        password = "";
        onSignedIn();
        return;
      }
      if (status === 429) error = t("locked", wait(data?.retry_after ?? 60));
      else if (status === 401) error = t("wrongPw");
      else error = t("signinFail");
    } catch {
      error = t("signinFail");
    } finally {
      busy = false;
    }
    input.focus();
  }

  $effect(() => {
    document.title = `${t("login")} · EZTunnel`;
  });
</script>

<main class="login">
  <section class="panel lbox" aria-labelledby="lg-h">
    <Logo id="l" />
    <h1 id="lg-h">{t("login")}</h1>
    <p class="muted small note-text">{t("pwNote")}</p>
    <div class="cmdline">eztunnel dashboard reset-password</div>
    <form onsubmit={submit} novalidate>
      <label class="flabel" for="pw">{t("pw")}</label>
      <input
        class="input ltr"
        id="pw"
        type="password"
        autocomplete="current-password"
        bind:value={password}
        bind:this={input}
        aria-invalid={error ? "true" : undefined}
        aria-describedby="pwe"
      />
      <div class="err" id="pwe" role="alert">{error}</div>
      <button class="btn primary" type="submit" disabled={busy}><Icon name="lock" />{t("signin")}</button>
    </form>
    <div class="row-flex">
      <button class="btn" type="button" onclick={() => setLang(ui.lang === "en" ? "fa" : "en")} aria-label="{t('langName')}: {t('lang')}">
        <Icon name="globe" /><span lang={ui.lang === "fa" ? "en" : "fa"}>{t("lang")}</span>
      </button>
      <button class="btn" type="button" onclick={() => setTheme(ui.theme === "dark" ? "light" : "dark")} aria-label="{t('theme')}: {ui.theme === 'dark' ? t('light') : t('dark')}">
        <Icon name="sun" />{ui.theme === "dark" ? t("light") : t("dark")}
      </button>
    </div>
  </section>
</main>
