<script>
  import { t } from "../lib/i18n.svelte.js";
  let { mark, label } = $props();
</script>

<span class="state {mark}"><span class="mark {mark === 'off' ? '' : mark}"></span>{t("st")[label] ?? label}</span>
