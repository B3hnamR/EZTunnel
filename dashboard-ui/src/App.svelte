<script>
  import Logo from "./lib/Logo.svelte";
  import Icon from "./lib/Icon.svelte";
  import Blocks from "./lib/Blocks.svelte";
  import Login from "./pages/Login.svelte";
  import Overview from "./pages/Overview.svelte";
  import Tunnels from "./pages/Tunnels.svelte";
  import Soon from "./pages/Soon.svelte";
  import { t, ui, num, setLang, setTheme, clock } from "./lib/i18n.svelte.js";
  import { live, connect, reset } from "./lib/live.svelte.js";
  import { getSession, logout } from "./lib/api.js";

  // Screens with their title, subtitle and, for those not built yet, the phase they arrive in.
  const ROUTES = {
    "": { title: "overview", sub: "ovSub", icon: "overview" },
    tunnels: { title: "tunnels", sub: "tunSub", icon: "tunnels" },
    servers: { title: "servers", icon: "servers", phase: 1 },
    conntest: { title: "conntest", icon: "conntest", phase: 3 },
    alerts: { title: "alerts", icon: "alerts", phase: 5 },
    health: { title: "health", icon: "health", phase: 3 },
    maintenance: { title: "maintenance", icon: "maintenance", phase: 4 },
    settings: { title: "settings", icon: "settings", phase: 1 },
  };

  let session = $state("checking"); // checking, in, out
  let version = $state("");
  let route = $state(readRoute());
  let menuOpen = $state(false);
  let firstLink = $state();

  const page = $derived(ROUTES[route] ?? ROUTES[""]);
  const issueCount = $derived(live.snapshot?.issues?.length ?? 0);

  function readRoute() {
    const r = location.hash.replace(/^#\/?/, "");
    return r in ROUTES ? r : "";
  }

  async function check() {
    try {
      const { data } = await getSession();
      version = data?.version ?? "";
      if (data?.signed_in) signedIn();
      else session = "out";
    } catch {
      session = "out";
    }
  }

  function signedIn() {
    session = "in";
    connect(() => {
      reset();
      session = "out";
    });
  }

  async function signOut() {
    try {
      await logout();
    } finally {
      reset();
      session = "out";
    }
  }

  function setMenu(open) {
    menuOpen = open;
    if (open) queueMicrotask(() => firstLink?.focus());
  }

  $effect(() => {
    if (session === "in") document.title = `${t(page.title)} · EZTunnel`;
  });

  check();
</script>

<svelte:window
  onhashchange={() => {
    route = readRoute();
    menuOpen = false;
    window.scrollTo(0, 0);
  }}
  onkeydown={(e) => {
    if (e.key === "Escape" && menuOpen) setMenu(false);
  }}
/>

{#if session === "out"}
  <div class="login-wrap">
    <Login onSignedIn={signedIn} />
    <footer class="login-foot"><span class="ltr">EZTunnel {version} · AGPL-3.0</span></footer>
  </div>
{:else if session === "in"}
  <div class="app" class:menu={menuOpen}>
    <nav class="side" aria-label={t("dash")} id="side">
      <div class="row-flex">
        <a class="brandbox grow" href="#/" aria-label="EZTunnel {t('overview')}">
          <Logo id="s" />
          <small>{t("dash")}</small>
        </a>
        <button class="btn icon side-close" onclick={() => setMenu(false)} aria-label={t("closeMenu")}><Icon name="x" /></button>
      </div>
      <div class="nav">
        {#each Object.entries(ROUTES) as [path, r], index}
          {#if index === 0}
            <a href="#/{path}" aria-current={route === path ? "page" : undefined} bind:this={firstLink}><Icon name={r.icon} /><span>{t(r.title)}</span></a>
          {:else}
            <a href="#/{path}" aria-current={route === path ? "page" : undefined}>
              <Icon name={r.icon} /><span>{t(r.title)}</span>
              {#if r.phase}<span class="phase">{t("phase")} {num(r.phase)}</span>{/if}
              {#if path === "tunnels" && issueCount}<span class="count" aria-label="{num(issueCount)}">{num(issueCount)}</span>{/if}
            </a>
          {/if}
        {/each}
      </div>
      <div class="side-foot">
        <button class="btn ghost" onclick={signOut}><Icon name="logout" />{t("signout")}</button>
      </div>
    </nav>
    <div class="scrim" onclick={() => setMenu(false)} aria-hidden="true"></div>

    <main class="main" id="main">
      <header class="top">
        <button class="btn icon menu-btn" onclick={() => setMenu(true)} aria-label={t("menu")} aria-controls="side" aria-expanded={menuOpen}><Icon name="menu" /></button>
        <div>
          <h1>{t(page.title)}</h1>
          {#if page.sub}<p class="sub">{t(page.sub)}</p>{/if}
        </div>
        <div class="grow"></div>
        <button class="btn" onclick={() => setLang(ui.lang === "en" ? "fa" : "en")} aria-label="{t('langName')}: {t('lang')}">
          <Icon name="globe" /><span lang={ui.lang === "fa" ? "en" : "fa"}>{t("lang")}</span>
        </button>
        <button class="btn" onclick={() => setTheme(ui.theme === "dark" ? "light" : "dark")} aria-label="{t('theme')}: {ui.theme === 'dark' ? t('light') : t('dark')}">
          <Icon name="sun" />{ui.theme === "dark" ? t("light") : t("dark")}
        </button>
      </header>

      {#if live.snapshot?.demo}
        <div class="banner"><b>{t("demo")}</b></div>
      {/if}
      {#if live.link === "lost"}
        <div class="note bad mb16" role="alert">
          <Icon name="warn" />
          <div class="grow"><b>{t("lostT")}</b><div>{t("lostText", clock(live.lastAt))}</div></div>
        </div>
      {/if}

      {#if page.phase}
        <Soon key={page.title} phase={page.phase} />
      {:else if !live.snapshot}
        <div class="panel loading" role="status"><Blocks value={30} /><span>{t("loadingT")}</span></div>
      {:else if route === "tunnels"}
        <Tunnels />
      {:else}
        <Overview />
      {/if}
      <footer class="foot"><span class="ltr">EZTunnel {version} · AGPL-3.0</span></footer>
    </main>
  </div>
{/if}
