// Smooth area paths for the charts.
export function areaPaths(values, width, height, max) {
  const pad = 6;
  const top = max > 0 ? max * 1.15 : 1;
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values.map((v, i) => [i * step, height - pad - (v / top) * (height - pad * 2)]);
  if (points.length === 0) return { line: "", fill: "" };
  if (points.length === 1) points.push([width, points[0][1]]);
  let d = `M${points[0][0]},${points[0][1]}`;
  for (let i = 1; i < points.length; i++) {
    const [x0, y0] = points[i - 1];
    const [x1, y1] = points[i];
    const cx = (x0 + x1) / 2;
    d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`;
  }
  const last = points[points.length - 1][0];
  return { line: d, fill: `${d} L${last},${height} L${points[0][0]},${height}Z` };
}
