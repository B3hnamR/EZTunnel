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
    stop: [["rect", { x: 6, y: 6, width: 12, height: 12, rx: 2 }]],
    restart: [["path", { d: "M4 12a8 8 0 1 0 3-6.2M4 4v4h4" }]],
    logs: [["path", { d: "M5 5h14M5 10h14M5 15h9M5 20h6" }]],
    copy: [["rect", { x: 8, y: 8, width: 12, height: 12, rx: 2 }], ["path", { d: "M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3" }]],
    check: [["path", { d: "m5 12 4 4 10-10" }]],
    edit: [["path", { d: "M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4" }]],
    undo: [["path", { d: "M9 14 4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3" }]],
    plus: [["path", { d: "M12 5v14M5 12h14" }]],
    trash: [["path", { d: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" }]],
    search: [["circle", { cx: 11, cy: 11, r: 6 }], ["path", { d: "m20 20-4.5-4.5" }]],
    github: [["path", { d: "M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21" }]],
    telegram: [["path", { d: "M21.5 4.5 2.8 11.7c-.9.4-.9 1.1 0 1.4l4.6 1.4 1.8 5.6c.2.6.9.8 1.4.4l2.6-2.2 4.7 3.5c.6.4 1.3.1 1.5-.6l3.2-15.2c.2-.9-.4-1.4-1.1-1.1z" }], ["path", { d: "m7.4 14.5 10.4-6.6-7.6 7.6" }]],
    lock: [["rect", { x: 5, y: 11, width: 14, height: 9, rx: 2 }], ["path", { d: "M8 11V8a4 4 0 0 1 8 0v3" }]],
    download: [["path", { d: "M12 4v11m-4.5-4.5L12 15l4.5-4.5M5 19h14" }]],
    dice: [["rect", { x: 4, y: 4, width: 16, height: 16, rx: 3 }], ["circle", { cx: 8.5, cy: 8.5, r: 1.5, fill: "currentColor", stroke: "none" }], ["circle", { cx: 15.5, cy: 8.5, r: 1.5, fill: "currentColor", stroke: "none" }], ["circle", { cx: 12, cy: 12, r: 1.5, fill: "currentColor", stroke: "none" }], ["circle", { cx: 8.5, cy: 15.5, r: 1.5, fill: "currentColor", stroke: "none" }], ["circle", { cx: 15.5, cy: 15.5, r: 1.5, fill: "currentColor", stroke: "none" }]],
    chevron: [["path", { d: "m9 6 6 6-6 6" }]],
    grid: [["rect", { x: 4, y: 4, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 13, y: 4, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 4, y: 13, width: 7, height: 7, rx: 1.5 }], ["rect", { x: 13, y: 13, width: 7, height: 7, rx: 1.5 }]],
    rows: [["rect", { x: 4, y: 5, width: 16, height: 4, rx: 1.5 }], ["rect", { x: 4, y: 11, width: 16, height: 4, rx: 1.5 }], ["path", { d: "M4 19h16" }]],
    filter: [["path", { d: "M4 6h16M7 12h10M10 18h4" }]],
  };
  let { name, cls = "" } = $props();
</script>

<svg class="i {cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" data-i={name} stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
  {#each I[name] as [tag, attrs]}
    {#if tag === "rect"}<rect {...attrs} />{:else if tag === "circle"}<circle {...attrs} />{:else}<path {...attrs} />{/if}
  {/each}
</svg>
