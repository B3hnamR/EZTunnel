<script>
  import Logo from "./lib/Logo.svelte";
  import Footer from "./lib/Footer.svelte";
  import Icon from "./lib/Icon.svelte";
  import Blocks from "./lib/Blocks.svelte";
  import Login from "./pages/Login.svelte";
  import Overview from "./pages/Overview.svelte";
  import Tunnels from "./pages/Tunnels.svelte";
  import Soon from "./pages/Soon.svelte";
  import Logs from "./pages/Logs.svelte";
  import Servers from "./pages/Servers.svelte";
  import Tunnel from "./pages/Tunnel.svelte";
  import Health from "./pages/Health.svelte";
  import ConnTest from "./pages/ConnTest.svelte";
  import Maintenance from "./pages/Maintenance.svelte";
  import Alerts from "./pages/Alerts.svelte";
  import Settings from "./pages/Settings.svelte";
  import { startFleet, stopFleet } from "./lib/servers.svelte.js";
  import Confirm from "./lib/Confirm.svelte";
  import { toast } from "./lib/actions.svelte.js";
  import { t, ui, num, setLang, setTheme, clock } from "./lib/i18n.svelte.js";
  import { live, connect, reset } from "./lib/live.svelte.js";
  import { getSession, logout } from "./lib/api.js";

  // Screens with their title, subtitle and, for those not built yet, the phase they arrive in.
  const ROUTES = {
    "": { title: "overview", sub: "ovSub", icon: "overview" },
    tunnels: { title: "tunnels", sub: "tunSub", icon: "tunnels" },
    tunnel: { title: "tunnels", sub: "tunSub", icon: "tunnels", hidden: true },
    logs: { title: "logs", sub: "logsSub", icon: "logs" },
    servers: { title: "servers", sub: "srvSub", icon: "servers" },
    conntest: { title: "conntest", sub: "ctSub", icon: "conntest" },
    alerts: { title: "alerts", sub: "alSub", icon: "alerts" },
    health: { title: "health", sub: "hcSub", icon: "health" },
    maintenance: { title: "maintenance", sub: "mtSub", icon: "maintenance" },
    settings: { title: "settings", sub: "stSub", icon: "settings" },
  };

  let session = $state("checking"); // checking, in, out
  let version = $state("");
  let route = $state(readRoute());
  let routeTunnel = $state(readTunnel());
  let routeSource = $state(readParam("v"));
  let routeServer = $state(readParam("s") || "local");
  let menuOpen = $state(false);
  let firstLink = $state();
  let side = $state();
  let main = $state();
  let mobile = $state(matchMedia("(max-width: 860px)").matches);

  const page = $derived(ROUTES[route] ?? ROUTES[""]);
  const issueCount = $derived(live.snapshot?.issues?.length ?? 0);

  function readRoute() {
    const r = location.hash.replace(/^#\/?/, "").split("?")[0];
    return r in ROUTES ? r : "";
  }

  /** A parameter of the address, as `t` in #/logs?t=game-fec. */
  function readParam(key) {
    const query = location.hash.split("?")[1] ?? "";
    return new URLSearchParams(query).get(key) ?? "";
  }

  function readTunnel() {
    return readParam("t");
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
    startFleet();
    connect(() => {
      reset();
      stopFleet();
      menuOpen = false;
      session = "out";
    });
  }

  async function signOut() {
    try {
      await logout();
    } finally {
      reset();
      stopFleet();
      menuOpen = false;
      session = "out";
    }
  }

  function setMenu(open) {
    menuOpen = open;
    queueMicrotask(() => {
      if (menuOpen && mobile) firstLink?.focus();
      else if (mobile) main?.querySelector(".menu-btn")?.focus();
    });
  }

  function containMenuFocus(event) {
    if (!menuOpen || !mobile || event.key !== "Tab" || !side) return;
    const focusable = [...side.querySelectorAll("a[href],button:not(:disabled)")].filter((node) => node.getClientRects().length);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!side.contains(document.activeElement)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  $effect(() => {
    const media = matchMedia("(max-width: 860px)");
    const resize = () => {
      mobile = media.matches;
      if (!mobile) menuOpen = false;
    };
    media.addEventListener("change", resize);
    return () => media.removeEventListener("change", resize);
  });

  $effect(() => {
    if (session === "in") document.title = `${t(page.title)} · EZTunnel`;
  });

  check();
</script>

<svelte:window
  onhashchange={() => {
    route = readRoute();
    routeTunnel = readTunnel();
    routeSource = readParam("v");
    routeServer = readParam("s") || "local";
    if (menuOpen) setMenu(false);
    window.scrollTo(0, 0);
  }}
  onkeydown={(e) => {
    if (e.key === "Escape" && menuOpen) setMenu(false);
    containMenuFocus(e);
  }}
/>

{#if session === "out"}
  <div class="login-wrap">
    <Login onSignedIn={signedIn} />
    <div class="login-foot"><Footer {version} status={false} /></div>
  </div>
{:else if session === "in"}
  <div class="app" class:menu={menuOpen}>
    <nav class="side" aria-label={t("dash")} id="side" bind:this={side} inert={mobile && !menuOpen}>
      <div class="row-flex">
        <a class="brandbox grow" href="#/" aria-label="EZTunnel {t('overview')}">
          <Logo id="s" />
          <small><span class="mark ok"></span>{t("dash")}<span class="ver ltr">v{version}</span></small>
        </a>
        <button class="btn icon side-close" onclick={() => setMenu(false)} aria-label={t("closeMenu")}><Icon name="x" /></button>
      </div>
      <div class="nav">
        {#each Object.entries(ROUTES).filter(([, r]) => !r.hidden) as [path, r], index}
          {#if index === 0}
            <a href="#/{path}" aria-current={route === path ? "page" : undefined} bind:this={firstLink}><Icon name={r.icon} /><span>{t(r.title)}</span></a>
          {:else}
            <a href="#/{path}" aria-current={route === path || (path === "tunnels" && route === "tunnel") ? "page" : undefined}>
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

    <main class="main" id="main" bind:this={main} inert={mobile && menuOpen}>
      <header class="top">
        <button class="btn icon menu-btn" onclick={() => setMenu(true)} aria-label={t("menu")} aria-controls="side" aria-expanded={menuOpen}><Icon name="menu" /></button>
        <div>
          <h1>{t(page.title)}</h1>
          {#if page.sub}<p class="sub">{t(page.sub)}</p>{/if}
        </div>
        <div class="grow"></div>
        <button class="btn ghost" onclick={() => setLang(ui.lang === "en" ? "fa" : "en")} aria-label="{t('langName')}: {t('lang')}">
          <Icon name="globe" /><span lang={ui.lang === "fa" ? "en" : "fa"}>{t("lang")}</span>
        </button>
        <button class="btn ghost" onclick={() => setTheme(ui.theme === "dark" ? "light" : "dark")} aria-label="{t('theme')}: {ui.theme === 'dark' ? t('light') : t('dark')}">
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

      {#key route}<div class="page">
      {#if page.phase}
        <Soon key={page.title} phase={page.phase} />
      {:else if !live.snapshot}
        <div class="panel loading" role="status"><Blocks value={30} /><span>{t("loadingT")}</span></div>
      {:else if route === "tunnels"}
        {#key routeServer}<Tunnels server={routeServer} />{/key}
      {:else if route === "tunnel"}
        {#key routeTunnel + routeServer}<Tunnel name={routeTunnel} server={routeServer} />{/key}
      {:else if route === "health"}
        {#key routeServer}<Health server={routeServer} />{/key}
      {:else if route === "conntest"}
        <ConnTest />
      {:else if route === "maintenance"}
        <Maintenance />
      {:else if route === "alerts"}
        <Alerts />
      {:else if route === "settings"}
        <Settings />
      {:else if route === "servers"}
        <Servers />
      {:else if route === "logs"}
        {#key routeTunnel + routeServer}<Logs tunnel={routeTunnel} source={routeSource} server={routeServer} />{/key}
      {:else}
        <Overview />
      {/if}
      </div>{/key}
      <Footer {version} />
    </main>
  </div>
  <Confirm />
  <div class="toast" class:show={toast.shown} class:bad={toast.bad} role={toast.bad ? "alert" : "status"} aria-live={toast.bad ? "assertive" : "polite"}>{toast.shown ? toast.text : ""}</div>
{/if}
