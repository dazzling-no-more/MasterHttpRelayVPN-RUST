// Svelte 5 mount point. `mount` replaces the Svelte 4 `new App({...})`
// constructor — same idea, different shape because Svelte 5's compiler
// produces components as plain functions instead of classes.
import "./app.css";
import App from "./App.svelte";
import { mount } from "svelte";

const target = document.getElementById("app");
if (!target) {
  // Should never happen — index.html always has #app — but failing
  // loud here beats a silent blank window if someone edits the HTML.
  throw new Error("Mount target '#app' missing from index.html");
}

const app = mount(App, { target });

export default app;
