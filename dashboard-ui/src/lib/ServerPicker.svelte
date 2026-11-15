<script>
  // Which server a page shows: this one or a joined server. Changing it changes the address, so the
  // choice survives a reload and can be shared.
  import { fleet, LOCAL } from "./servers.svelte.js";
  import { t } from "./i18n.svelte.js";
  import Icon from "./Icon.svelte";

  let { value = LOCAL, route, extra = "" } = $props();

  function pick(id) {
    const query = new URLSearchParams(extra);
    if (id !== LOCAL) query.set("s", id);
    const text = query.toString();
    location.hash = `#/${route}${text ? `?${text}` : ""}`;
  }
</script>

<div class="row-flex mb16 srv-pick">
  <label class="picker" for="srv-pick-{route}">
  <Icon name="servers" />
  <span>{t("server")}</span>
  <i class="on" class:off={value !== LOCAL && !fleet.list.find((s) => s.id === value)?.online} aria-hidden="true"></i>
  <select id="srv-pick-{route}" value={value} onchange={(e) => pick(e.currentTarget.value)}>
    <option value={LOCAL}>{t("thisServer")}</option>
    {#each fleet.list as s (s.id)}
      <option value={s.id}>{s.name}{s.online ? "" : ` (${t("offline")})`}</option>
    {/each}
  </select>
  </label>
</div>
