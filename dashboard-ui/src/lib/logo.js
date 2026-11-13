// The manager's block logo (src/manager/ui.rs), drawn from the same letter grid.
const LETTERS = [
  ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
  ["███████╗", "╚══███╔╝", "  ███╔╝ ", " ███╔╝  ", "███████╗", "╚══════╝"],
  ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
  ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
  ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
  ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
  ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
  ["██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"],
];
const LINKS = { "═": "LR", "║": "UD", "╗": "LD", "╔": "RD", "╝": "LU", "╚": "RU" };
const CW = 10;
const CH = 20;

function build() {
  const rows = [...Array(6)].map((_, r) => LETTERS.map((l) => l[r]).join(""));
  const width = [...rows[0]].length * CW;
  const height = 6 * CH;
  const rects = [];
  let path = "";
  rows.forEach((row, r) => {
    const cells = [...row];
    let c = 0;
    while (c < cells.length) {
      if (cells[c] === "█") {
        const s = c;
        while (c < cells.length && cells[c] === "█") c++;
        rects.push({ x: s * CW, y: r * CH - 0.5, w: (c - s) * CW, h: CH + 1 });
      } else {
        const k = LINKS[cells[c]];
        if (k) {
          const x = c * CW;
          const y = r * CH;
          const cx = x + CW / 2;
          const cy = y + CH / 2;
          const e = { L: [x, cy], R: [x + CW, cy], U: [cx, y], D: [cx, y + CH] };
          path += `M${e[k[0]]}L${cx} ${cy}L${e[k[1]]}`;
        }
        c++;
      }
    }
  });
  return { width, height, rects, path };
}

export const LOGO = build();
