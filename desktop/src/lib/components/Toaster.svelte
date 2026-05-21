<script lang="ts">
  // Global toast renderer. Mounted once in `App.svelte`; reads the
  // toast list from the module store and animates each entry in/out.
  //
  // Position: top-right (top-left in RTL — Tailwind logical-property
  // utilities flip automatically because <html dir="rtl"> is set).
  // Stack grows downward, newest on top. Each toast is clickable to
  // dismiss before the auto-expiry timer fires.

  import { fly } from "svelte/transition";
  import { quintOut } from "svelte/easing";

  import { toast, type Toast } from "../toast.svelte";

  // Visual style per kind. Lives next to the renderer (not in
  // toast.svelte.ts) so the model stays UI-agnostic.
  const STYLE: Record<Toast["kind"], string> = {
    success:
      "bg-success/15 border-success/40 text-success",
    error: "bg-error/15 border-error/40 text-error",
    info: "bg-accent/15 border-accent/40 text-accent",
  };

  // RTL-aware fly: in LTR we slide in from the right (positive x);
  // in RTL the toaster sits on the left, so we slide in from the
  // left (negative x). `document.dir` is set on <html> by App.svelte's
  // i18n effect so we can read it here without importing i18n.
  function flyX() {
    const rtl = typeof document !== "undefined" && document.documentElement.dir === "rtl";
    return { x: rtl ? -32 : 32, duration: 220, easing: quintOut };
  }
</script>

<!-- `pointer-events-none` on the outer container so the stack doesn't
     block clicks on the page underneath when there are no toasts. The
     toasts themselves re-enable pointer events for their hover/click. -->
<div
  class="pointer-events-none fixed inset-e-4 top-16 z-50 flex max-w-sm flex-col gap-2"
  aria-live="polite"
>
  {#each toast.list as t (t.id)}
    <button
      type="button"
      onclick={() => toast.dismiss(t.id)}
      in:fly={flyX()}
      out:fly={{ ...flyX(), duration: 160 }}
      class="pointer-events-auto cursor-pointer rounded-md border px-4 py-2.5 text-start text-sm shadow-lg backdrop-blur transition-transform hover:scale-[1.01] {STYLE[
        t.kind
      ]}"
    >
      {t.message}
    </button>
  {/each}
</div>
