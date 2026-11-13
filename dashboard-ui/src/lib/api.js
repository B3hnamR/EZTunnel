// Calls to the dashboard's JSON API. Every request carries the x-eztunnel header; the server
// refuses state-changing requests without it.

async function call(method, path, body) {
  const headers = { "x-eztunnel": "1" };
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    // A server that stops answering must end in an error the screen can show, not a spinner.
    signal: AbortSignal.timeout(10_000),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try {
    data = await response.json();
  } catch {
    // empty body
  }
  return { status: response.status, data };
}

export const getSession = () => call("GET", "/api/session");
export const getSnapshot = () => call("GET", "/api/snapshot");
export const getHistory = (range, series) =>
  call("GET", `/api/history?range=${encodeURIComponent(range)}&series=${encodeURIComponent(series)}&tz=${-new Date().getTimezoneOffset()}`);
export const login = (password) => call("POST", "/api/login", { password });
export const logout = () => call("POST", "/api/logout", {});
