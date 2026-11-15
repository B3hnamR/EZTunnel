<script>
  // Adding a server over SSH: the dashboard's own key goes into the server's authorized_keys
  // once; then the dashboard logs in and runs the one-time join command itself.
  import Icon from "./Icon.svelte";
  import { getSshKey, addOverSsh } from "./api.js";
  import { say } from "./actions.svelte.js";
  import { refreshFleet } from "./servers.svelte.js";
  import { t } from "./i18n.svelte.js";

  let key = $state("");
  let keyError = $state("");
  let f = $state({ host: "", port: "22", user: "root" });
  let adding = $state(false);
  let result = $state(null);

  async function showKey() {
    keyError = "";
    try {
      const { status, data } = await getSshKey();
      if (status === 200) key = data.key;
      else keyError = data?.detail ?? t("failedShort");
    } catch {
      keyError = t("slowShort");
    }
  }

  async function copyKey() {
    try {
      await navigator.clipboard.writeText(key);
      say(t("copied"));
    } catch {
      say(t("copyFail"), true);
    }
  }

  const valid = $derived(/^[A-Za-z0-9.:-]+$/.test(f.host.trim()) && /^\d+$/.test(f.port) && +f.port > 0 && +f.port < 65536 && /^[a-z_][a-z0-9_-]*$/.test(f.user.trim()));

  async function add() {
    adding = true;
    result = null;
    try {
      const { status, data } = await addOverSsh(f.host.trim(), +f.port, f.user.trim());
      result = status === 200 ? { ok: true, text: data.output } : { ok: false, text: data?.detail ?? t("failedShort") };
      if (status === 200) {
        say(t("sshJoined", f.host.trim()));
        refreshFleet();
      }
    } catch {
      result = { ok: false, text: t("slowShort") };
    } finally {
      adding = false;
    }
  }
  let opened = $state(false);
</script>

<details class="panel ssh-add mt16" bind:open={opened}>
  <summary>
    <span class="ct-ico"><Icon name="lock" /></span>
    <span class="ssh-t"><h2>{t("sshH")}</h2><span class="muted small">{t("sshSub")}</span></span>
    <span class="btn ssh-go" aria-hidden="true">{opened ? t("sshClose") : t("sshOpen")}<Icon name="chevron" cls="ssh-chev" /></span>
  </summary>
  <ol class="steps">
    <li>{t("sshStep1")}</li>
    <li>{t("sshStep2")}</li>
    <li>{t("sshStep3")}</li>
  </ol>
  {#if key}
    <div class="code-box ltr mono">{key}</div>
    <div class="row-flex mt12">
      <button class="btn" onclick={copyKey}><Icon name="copy" />{t("copy")}</button>
    </div>
    <div class="cmdline ltr mt12">echo '{key}' &gt;&gt; ~/.ssh/authorized_keys</div>
  {:else}
    <button class="btn" onclick={showKey}><Icon name="lock" />{t("sshShowKey")}</button>
    {#if keyError}<p class="small bad-t">{keyError}</p>{/if}
  {/if}
  <div class="erow mt12">
    <div class="grow">
      <label class="flabel" for="ssh-host">{t("sshHost")}</label>
      <input id="ssh-host" class="input ltr" bind:value={f.host} placeholder="203.0.113.5" autocomplete="off" spellcheck="false" />
    </div>
    <div class="eproto">
      <label class="flabel" for="ssh-port">{t("sshPort")}</label>
      <input id="ssh-port" class="input ltr" inputmode="numeric" bind:value={f.port} />
    </div>
    <div class="eproto">
      <label class="flabel" for="ssh-user">{t("sshUser")}</label>
      <input id="ssh-user" class="input ltr" bind:value={f.user} autocomplete="off" spellcheck="false" />
    </div>
  </div>
  <p class="muted small m0 ehelp">{t("sshHelp")}</p>
  <div class="row-flex mt12">
    <button class="btn primary" onclick={add} disabled={!valid || adding} aria-busy={adding}><Icon name="servers" />{adding ? t("sshAdding") : t("sshAdd")}</button>
  </div>
  {#if result}
    <div class="note {result.ok ? 'info' : 'bad'} mt12" role={result.ok ? "status" : "alert"}><Icon name={result.ok ? "check" : "warn"} /><span>{result.ok ? t("sshDone") : t("sshFailed")}</span></div>
    {#if result.text}<pre class="notes ltr">{result.text}</pre>{/if}
  {/if}
</details>
