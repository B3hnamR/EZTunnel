// Copying text and saving a file from the page, for result lists and exports.
import { say } from "./actions.svelte.js";
import { t } from "./i18n.svelte.js";

export async function copyText(text, what = "") {
  const done = () => {
    say(what ? `${t("copied")}: ${what}` : t("copied"));
    return true;
  };
  try {
    await navigator.clipboard.writeText(text);
    return done();
  } catch {}
  // Older or stricter browsers: copy from a hidden field. Inside an open dialog the field must be
  // in the dialog, since everything outside it is inert.
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.className = "sr";
  (document.querySelector("dialog[open]") ?? document.body).append(field);
  field.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {}
  field.remove();
  if (ok) return done();
  say(t("copyBlocked"), true);
  return false;
}

export function saveFile(name, text, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** One CSV line; fields with commas, quotes or line breaks are quoted. */
export const csvLine = (fields) => fields.map((f) => (/[",\n]/.test(String(f ?? "")) ? `"${String(f).replaceAll('"', '""')}"` : String(f ?? ""))).join(",");

/** A file-name stamp like 20261115-1216. */
export function stamp() {
  const d = new Date();
  const two = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${two(d.getMonth() + 1)}${two(d.getDate())}-${two(d.getHours())}${two(d.getMinutes())}`;
}
