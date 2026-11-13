<script>
  import Icon from "../lib/Icon.svelte";
  import { t } from "../lib/i18n.svelte.js";
</script>

<div class="panel empty-state">
  <Icon name="tunnels" />
  <h2>{t("emptyT")}</h2>
  <p>{t("emptyText")}</p>
  <div class="cmdline">sudo eztunnel</div>
</div>
