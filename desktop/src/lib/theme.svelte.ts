// Light / dark theme state + persistence.
//
// Mirrors the shape of `lib/i18n.svelte.ts`: module-scope rune for
// reactive consumers, localStorage for cross-launch persistence,
// graceful fallback to the OS preference when nothing's stored yet.
//
// The toggle effect is implemented in `App.svelte` by syncing
// `theme.current` onto `<html data-theme="...">`. The CSS in `app.css`
// has matching `[data-theme="light"]` overrides that swap the
// `--color-*` design tokens — Tailwind utility classes pick up the
// new values automatically via the CSS-variable cascade.

export type Theme = "light" | "dark";

const STORAGE_KEY = "rahgozar:theme";

function loadInitial(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    /* fall through to OS preference */
  }
  // No stored choice — defer to the OS. Most rahgozar users run dark
  // (the legacy egui binary was dark-only), but a fresh install on a
  // light-mode OS shouldn't surprise the user with a black window.
  try {
    if (window.matchMedia?.("(prefers-color-scheme: light)").matches) {
      return "light";
    }
  } catch {
    /* swallow — fall through to dark */
  }
  return "dark";
}

let _theme = $state<Theme>(loadInitial());

export const theme = {
  get current(): Theme {
    return _theme;
  },
  set(next: Theme): void {
    _theme = next;
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* swallow — won't persist */
    }
  },
  toggle(): void {
    this.set(_theme === "dark" ? "light" : "dark");
  },
};
