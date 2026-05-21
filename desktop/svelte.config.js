// Svelte 5 + Vite. No SvelteKit — Tauri serves a static SPA into its
// webview, so we don't need SvelteKit's filesystem router or the SSR
// machinery. `vitePreprocess` handles TypeScript / Tailwind classes /
// scss-if-we-add-it inside `<script>` and `<style>` blocks.
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

export default {
  preprocess: vitePreprocess(),
};
