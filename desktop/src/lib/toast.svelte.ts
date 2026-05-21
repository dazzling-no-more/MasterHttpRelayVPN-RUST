// Global toast store.
//
// One module owns the list of currently-visible toasts; the
// `<Toaster />` component renders them, and any feature module pushes
// new entries via `toast.success(...)` / `toast.error(...)`. Beats
// inline `let status = $state(null); setTimeout(...)` paths in every
// component that wants ephemeral feedback, and keeps the toast
// visual style in one place.
//
// Toasts auto-expire after `DEFAULT_TTL_MS`. Callers can override
// per-push for messages that need to linger (e.g. an error the user
// must read before retrying).

export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  /** Wall-clock ms when this toast should disappear. */
  expiresAt: number;
}

const DEFAULT_TTL_MS = 3500;
const ERROR_TTL_MS = 6500;

let _list = $state<Toast[]>([]);
let _seq = 0;

function pushInternal(kind: ToastKind, message: string, ttlMs?: number): void {
  const id = ++_seq;
  const ttl = ttlMs ?? (kind === "error" ? ERROR_TTL_MS : DEFAULT_TTL_MS);
  const expiresAt = Date.now() + ttl;
  _list = [..._list, { id, kind, message, expiresAt }];

  // Self-eviction: schedule a removal at expiry. We let the auto-remove
  // run even if the user dismisses manually before then — the
  // dismiss path just filters by id, so a stale timer becomes a no-op.
  setTimeout(() => {
    _list = _list.filter((t) => t.id !== id);
  }, ttl);
}

export const toast = {
  /** Live list of visible toasts, oldest-first. Read by `<Toaster />`. */
  get list(): readonly Toast[] {
    return _list;
  },
  success(message: string, ttlMs?: number): void {
    pushInternal("success", message, ttlMs);
  },
  error(message: string, ttlMs?: number): void {
    pushInternal("error", message, ttlMs);
  },
  info(message: string, ttlMs?: number): void {
    pushInternal("info", message, ttlMs);
  },
  dismiss(id: number): void {
    _list = _list.filter((t) => t.id !== id);
  },
  clear(): void {
    _list = [];
  },
};
