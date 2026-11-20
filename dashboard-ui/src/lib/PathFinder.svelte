<script>
  // Before choosing a transport: is there a path at all between two servers, what the Iran
  // server can reach abroad, and which other managed server could relay between them.
  import { untrack } from "svelte";
  import Icon from "./Icon.svelte";
  import { findPath, cancelPath } from "./api.js";
  import { live } from "./live.svelte.js";
  import { fleet, LOCAL, localName } from "./servers.svelte.js";
  import { t, num, list } from "./i18n.svelte.js";

  const places = $derived([
    { id: LOCAL, name: t("thisServerIs", localName(live.snapshot?.host?.hostname)), address: live.snapshot?.host?.address ?? "", address6: live.snapshot?.host?.address6 ?? "", online: true },
    ...fleet.list.map((s) => ({ id: s.id, name: s.name, address: s.snapshot?.host?.address ?? "", address6: s.snapshot?.host?.address6 ?? "", online: s.online })),
  ]);
  const placeOf = (id) => places.find((p) => p.id === id);
  let f = $state({ iran: LOCAL, foreign: "", iranIp: "", foreignIp: "", iranIpTouched: false, foreignIpTouched: false });
  $effect(() => {
    if (!f.foreign) {
      const first = places.find((p) => p.id !== LOCAL);
      if (first) untrack(() => (f.foreign = first.id));
    }
  });
  $effect(() => {
    const a = placeOf(f.iran)?.address ?? "";
    const b = placeOf(f.foreign)?.address ?? "";
    untrack(() => {
      if (!f.iranIpTouched) f.iranIp = a;
      if (!f.foreignIpTouched) f.foreignIp = b;
    });
  });

  function pickEnd(field, value) {
    f[field] = value;
    const ipField = field === "iran" ? "iranIp" : "foreignIp";
    f[`${ipField}Touched`] = false;
    f[ipField] = placeOf(value)?.address ?? "";
  }

  let result = $state(null);
  let running = $state(false);
  let problem = $state("");
  async function run() {
    running = true;
    problem = "";
    result = null;
    try {
      // The servers' IPv6 addresses go along: the direct path is tried over IPv6 as well.
      const { status, data } = await findPath({ iran: f.iran, foreign: f.foreign, iran_ip: f.iranIp.trim(), foreign_ip: f.foreignIp.trim(),
        iran_ip6: placeOf(f.iran)?.address6 || undefined, foreign_ip6: placeOf(f.foreign)?.address6 || undefined });
      if (status === 200 && data?.cancelled) problem = t("pfCancelled");
      else if (status === 200) result = data;
      else problem = data?.detail ?? t("failedShort");
    } catch {
      problem = t("slowShort");
    } finally {
      running = false;
    }
  }

  // Cancel stops the search on the dashboard; its answer then comes back as "cancelled".
  let cancelling = $state(false);
  async function cancel() {
    if (cancelling) return;
    cancelling = true;
    try {
      const { status, data } = await cancelPath();
      if (status !== 200) problem = data?.detail ?? t("failedShort");
    } catch {
      problem = t("slowShort");
    } finally {
      cancelling = false;
    }
  }

  const tcpWord = (r) => t("pfTcp")[r] ?? r;
  const works = (x) => x?.ok === true;
  const relaysOk = $derived((result?.relays ?? []).filter(works));
  const knownOpen = $derived((result?.known ?? []).filter((k) => k.result === "open" || k.result === "refused"));
  const verdict = $derived.by(() => {
    if (!result) return null;
    if (works(result.iran_to_foreign) || works(result.foreign_to_iran)) return ["ok", t("pfDirect")];
    if (works(result.iran_to_foreign_v6) || works(result.foreign_to_iran_v6)) return ["ok", t("pfDirect6")];
    if (relaysOk.length) return ["warn", t("pfRelay", list(relaysOk.map((r) => r.name)))];
    return ["bad", t("pfNone")];
  });
</script>

<section class="panel mb16 ct-sec" aria-labelledby="pf-h">
  <div class="sec-row"><span class="ct-ico"><Icon name="route" /></span><h3 id="pf-h" class="sec-h grow m0">{t("pfH")}</h3></div>
  <p class="muted small">{t("pfAbout")}</p>
  <div class="ct-route">
    <div class="ct-end">
      <span class="eyebrow"><span class="mark ok"></span>{t("iranEnd")}</span>
      <label class="sr" for="pf-iran">{t("iranEnd")}</label>
       <select id="pf-iran" class="input" value={f.iran} onchange={(e) => pickEnd("iran", e.currentTarget.value)}>{#each places as p (p.id)}<option value={p.id} disabled={!p.online}>{p.name}</option>{/each}</select>
      <label class="flabel m0" for="pf-iip">{t("ctIranIp")}</label>
       <input id="pf-iip" class="input ltr" bind:value={f.iranIp} oninput={() => (f.iranIpTouched = true)} spellcheck="false" autocomplete="off" />
    </div>
    <div class="ct-wire link {result ? (works(result.iran_to_foreign) ? 'ok' : 'down') : running ? 'live' : 'warn'}" aria-hidden="true"><span class="wire"><i></i>{#if result && works(result.iran_to_foreign)}<span class="mono ltr">{num(result.iran_to_foreign.ms ?? 0)} ms</span>{/if}<i></i></span></div>
    <div class="ct-end">
      <span class="eyebrow"><span class="mark {placeOf(f.foreign)?.online === false ? 'off' : 'ok'}"></span>{t("foreignEnd")}</span>
      <label class="sr" for="pf-foreign">{t("foreignEnd")}</label>
       <select id="pf-foreign" class="input" value={f.foreign} onchange={(e) => pickEnd("foreign", e.currentTarget.value)}>{#each places as p (p.id)}<option value={p.id}>{p.name}{p.online ? "" : ` (${t("offline")})`}</option>{/each}</select>
      <label class="flabel m0" for="pf-fip">{t("ctForeignIp")}</label>
       <input id="pf-fip" class="input ltr" bind:value={f.foreignIp} oninput={() => (f.foreignIpTouched = true)} spellcheck="false" autocomplete="off" />
    </div>
  </div>
  <p class="muted small m0">{t("pfOfflineNote")}</p>
  {#if problem}<div class="note bad mt12" role="alert"><Icon name="warn" /><span class="ltr">{problem}</span></div>{/if}
  <div class="row-flex mt16">
    <button class="btn primary ct-go" onclick={run} disabled={running || !f.iranIp || !f.foreignIp || f.iran === f.foreign} aria-busy={running}>
      <Icon name="route" />{running ? t("pfRunning") : t("pfStart")}
    </button>
    {#if running}<button class="btn danger" onclick={cancel} disabled={cancelling} aria-busy={cancelling}><Icon name="stop" />{cancelling ? t("pfCancelling") : t("pfCancel")}</button>{/if}
  </div>

  {#if result}
    <div class="note {verdict[0] === 'ok' ? 'info' : verdict[0]} mt16" role="status"><Icon name={verdict[0] === "ok" ? "check" : "warn"} /><span>{verdict[1]}</span></div>
    <div class="pf-grid">
      <div class="pf-box">
        <h4 class="mt-sub m0">{t("pfIranToForeign")}</h4>
        <span class="pill {works(result.iran_to_foreign) ? 'ok' : 'bad'}">{works(result.iran_to_foreign) ? t("pfWorks", num(result.iran_to_foreign.ms ?? 0)) : t("pfBlocked")}</span>
        {#if result.foreign_asked}
          <h4 class="mt-sub">{t("pfForeignToIran")}</h4>
          <span class="pill {works(result.foreign_to_iran) ? 'ok' : 'bad'}">{works(result.foreign_to_iran) ? t("pfWorks", num(result.foreign_to_iran.ms ?? 0)) : t("pfBlocked")}</span>
        {/if}
        {#each [["pfIranToForeign6", result.iran_to_foreign_v6], ["pfForeignToIran6", result.foreign_to_iran_v6]] as [label, way] (label)}
          {#if way}
            <h4 class="mt-sub">{t(label)}</h4>
            <span class="pill {works(way) ? 'ok' : 'bad'}">{works(way) ? t("pfWorks", num(way.ms ?? 0)) : t("pfBlocked")}</span>
          {/if}
        {/each}
      </div>
      {#each [["pfFromIran", result.from_iran], ["pfFromForeign", result.from_foreign]] as [label, side] (label)}
        {#if side}
          <div class="pf-box">
            <h4 class="mt-sub m0">{t(label)}</h4>
            <div class="pf-ports">
              <span class="pill {side.ping === true ? 'ok' : side.ping === false ? 'bad' : 'off'}">{t("ping")} {side.ping === true ? t("pfAnswers") : side.ping === false ? t("pfSilent") : "-"}</span>
              {#each side.tcp ?? [] as [port, r]}<span class="pill {r === 'open' || r === 'refused' ? 'ok' : 'bad'} ltr">{port} {tcpWord(r)}</span>{/each}
            </div>
          </div>
        {/if}
      {/each}
    </div>

    <h4 class="mt-sub">{t("pfRelays")}</h4>
    {#if result.relays?.length}
      <ul class="row-list">
        {#each result.relays as r (r.server)}
          <li>
            <span class="mark {works(r) ? 'ok' : 'bad'}" aria-hidden="true"></span>
            <div class="grow bk-main"><b>{r.name}</b><span class="muted small">{works(r) ? t("pfRelayWorks", num(r.ms ?? 0)) : `${t("pfRelayFails")} ${r.error ?? ""}`}</span></div>
          </li>
        {/each}
      </ul>
      {#if relaysOk.length}<p class="muted small mt8 m0">{t("pfRelayHow")}</p>{/if}
    {:else}
      <p class="muted small m0">{t("pfNoRelays")}</p>
    {/if}

    <h4 class="mt-sub">{t("pfKnown")}</h4>
    <p class="muted small m0">{knownOpen.length === (result.known ?? []).length ? t("pfKnownAll") : knownOpen.length ? t("pfKnownSome", num(knownOpen.length), num(result.known.length)) : t("pfKnownNone")}</p>
    <div class="pf-known mt12">
      {#each result.known ?? [] as k (k.ip)}
        <span class="pf-chip {k.result === 'open' || k.result === 'refused' ? 'ok' : ''}"><span class="mark {k.result === 'open' || k.result === 'refused' ? 'ok' : 'bad'}" aria-hidden="true"></span>{k.name} <span class="ltr muted">{k.ip}</span></span>
      {/each}
    </div>
  {/if}
</section>
