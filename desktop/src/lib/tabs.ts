// Single source of truth for the top-level tab set.
//
// Adding a tab is a one-line edit here + a new `<Tab*Component>.svelte`.
// Kept out of `App.svelte` so the tab list isn't tangled up in the
// header / dispatcher render code.

export type TabId = "status" | "tunnel" | "logs" | "advanced" | "about";

export interface TabDef {
  id: TabId;
  label: string;
}

/** Render order for the top tab bar. */
export const TABS: TabDef[] = [
  { id: "status", label: "Status" },
  { id: "tunnel", label: "Tunnel" },
  { id: "logs", label: "Logs" },
  { id: "advanced", label: "Advanced" },
  { id: "about", label: "About" },
];

export const DEFAULT_TAB: TabId = "status";
