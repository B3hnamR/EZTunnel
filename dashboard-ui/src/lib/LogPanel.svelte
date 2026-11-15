<script>
  // A tunnel's log over the page it was opened from (a native dialog: focus stays inside, Escape
  // closes it). The log stops streaming when the panel closes.
  import Icon from "./Icon.svelte";
  import LogView from "./LogView.svelte";
  import { t } from "./i18n.svelte.js";

  let { name = "", server = "local", onclose } = $props();
  let dialog = $state();

  $effect(() => {
    if (name && dialog && !dialog.open) dialog.showModal();
    if (!name && dialog?.open) dialog.close();
  });
  // Closes the panel and tells the page at once; some browsers deliver the dialog's own close
  // event late or not at all, which would leave the panel unable to open again.
  function shut() {
    if (dialog?.open) dialog.close();
    onclose?.();
  }
</script>

<dialog bind:this={dialog} class="log-panel" aria-labelledby="log-panel-title" onclose={() => onclose?.()} oncancel={(e) => { e.preventDefault(); shut(); }}>
  <div class="dlg-h">
    <span class="dlg-ico"><Icon name="logs" /></span>
    <h2 id="log-panel-title">{t("logs")} <span class="dlg-sub ltr">{name}</span></h2>
    <a class="btn ghost" href="#/logs?t={encodeURIComponent(name)}{server !== 'local' ? `&s=${encodeURIComponent(server)}` : ''}" onclick={shut}>{t("allLogs")}</a>
    <button class="btn icon ghost" onclick={shut} aria-label={t("close")}><Icon name="x" /></button>
  </div>
  <div class="dlg-b">
    {#if name}{#key name + server}<LogView {name} {server} uid="panel" />{/key}{/if}
  </div>
</dialog>
