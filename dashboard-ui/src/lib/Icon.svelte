<script>
  // Simple stroke icons, each tied to its meaning. Shapes are data, so no HTML is injected.
  const I = {
    overview: [["rect", { x: 4, y: 4, width: 7, height: 7, rx: 1 }], ["rect", { x: 13, y: 4, width: 7, height: 4, rx: 1 }], ["rect", { x: 13, y: 10, width: 7, height: 10, rx: 1 }], ["rect", { x: 4, y: 13, width: 7, height: 7, rx: 1 }]],
    tunnels: [["path", { d: "M3 17V11a9 9 0 0 1 18 0v6" }], ["path", { d: "M7 17v-6a5 5 0 0 1 10 0v6" }]],
    servers: [["rect", { x: 4, y: 4, width: 16, height: 7, rx: 1.5 }], ["rect", { x: 4, y: 13, width: 16, height: 7, rx: 1.5 }], ["path", { d: "M8 7.5h.01M8 16.5h.01" }]],
    conntest: [["path", { d: "M4 18 9 9l4 6 3-4 4 7" }]],
    alerts: [["path", { d: "M12 4a5 5 0 0 0-5 5v3l-2 3h14l-2-3V9a5 5 0 0 0-5-5zM10 19a2 2 0 0 0 4 0" }]],
    health: [["path", { d: "M3 12h4l2-5 4 10 2-5h6" }]],
    maintenance: [["path", { d: "M14 6a4 4 0 0 0-5 5L4 16l4 4 5-5a4 4 0 0 0 5-5l-3 3-3-1-1-3z" }]],
    settings: [["circle", { cx: 12, cy: 12, r: 3 }], ["path", { d: "M12 3v2m0 14v2m9-9h-2M5 12H3m15.4-6.4-1.4 1.4M7 17l-1.4 1.4m12.8 0L17 17M7 7 5.6 5.6" }]],
    play: [["path", { d: "M8 5v14l11-7z" }]],
    pause: [["path", { d: "M8 5v14M16 5v14" }]],
    x: [["path", { d: "M6 6l12 12M18 6 6 18" }]],
    warn: [["path", { d: "M12 4 2.5 20h19zM12 10v4m0 3h.01" }]],
    menu: [["path", { d: "M4 7h16M4 12h16M4 17h16" }]],
    globe: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" }]],
    sun: [["circle", { cx: 12, cy: 12, r: 4 }], ["path", { d: "M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5" }]],
    logout: [["path", { d: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10" }]],
    route: [["path", { d: "M4 12h12m-4-5 5 5-5 5" }]],
    lock: [["rect", { x: 5, y: 11, width: 14, height: 9, rx: 2 }], ["path", { d: "M8 11V8a4 4 0 0 1 8 0v3" }]],
  };
  let { name, cls = "" } = $props();
</script>

<svg class="i {cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
  {#each I[name] as [tag, attrs]}
    {#if tag === "rect"}<rect {...attrs} />{:else if tag === "circle"}<circle {...attrs} />{:else}<path {...attrs} />{/if}
  {/each}
</svg>
