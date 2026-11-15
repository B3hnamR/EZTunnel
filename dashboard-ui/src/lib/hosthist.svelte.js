// The last few minutes of this server's own figures, kept while the page is open so the strip can
// draw short trends. Survives moving between pages; starts empty after a reload.
const KEEP = 90;

export const hostHist = $state({ at: 0, cpu: [], mem: [], rx: [], tx: [] });

function push(list, value) {
  list.push(value ?? 0);
  if (list.length > KEEP) list.splice(0, list.length - KEEP);
}

/** Records one snapshot's host figures (once per snapshot). */
export function record(at, host) {
  if (!host || at === hostHist.at) return;
  hostHist.at = at;
  push(hostHist.cpu, host.cpu_pct);
  push(hostHist.mem, host.mem_pct);
  push(hostHist.rx, host.rx_bps);
  push(hostHist.tx, host.tx_bps);
}
