import "./app.css";
import { mount } from "svelte";
import App from "./App.svelte";
import { applyDocument } from "./lib/i18n.svelte.js";

// Language, direction and theme are set before the first render.
applyDocument();
mount(App, { target: document.getElementById("root") });
