<script>
  // The one confirm dialog: a native <dialog>, so focus stays inside and Escape closes it.
  import Icon from "./Icon.svelte";
  import { asking } from "./actions.svelte.js";
  import { t } from "./i18n.svelte.js";

  let dialog = $state();
  let cancelButton = $state();

  $effect(() => {
    if (!dialog) return;
    if (asking.open && !dialog.open) {
      dialog.showModal();
      // The safe choice has focus, so Enter never stops a tunnel by accident.
      cancelButton?.focus();
    } else if (!asking.open && dialog.open) {
      dialog.close();
    }
  });

  function answer(yes) {
    const run = asking.run;
    const ticked = asking.option?.checked ?? false;
    asking.open = false;
    asking.run = null;
    if (yes && run) run(ticked);
  }
</script>

<dialog bind:this={dialog} aria-labelledby="confirm-title" aria-describedby="confirm-text" onclose={() => (asking.open = false)} oncancel={(e) => { e.preventDefault(); answer(false); }}>
  <div class="dlg-h">
    <span class="dlg-ico {asking.safe ? '' : 'warn'}"><Icon name={asking.safe ? "play" : "warn"} /></span>
    <h2 id="confirm-title">{asking.title}</h2>
    <button class="btn icon ghost" onclick={() => answer(false)} aria-label={t("close")}><Icon name="x" /></button>
  </div>
  <div class="dlg-b">
    <p id="confirm-text" class="m0">{asking.text}</p>
    {#if asking.option}<label class="chk dlg-opt"><input type="checkbox" bind:checked={asking.option.checked} /><span>{asking.option.label}</span></label>{/if}
  </div>
  <div class="dlg-f">
    <button class="btn" bind:this={cancelButton} onclick={() => answer(false)}>{t("cancel")}</button>
    <button class="btn {asking.safe ? 'primary' : 'danger'}" onclick={() => answer(true)}>{asking.confirm}</button>
  </div>
</dialog>
