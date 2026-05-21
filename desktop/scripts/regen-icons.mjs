// Regenerate the platform icon set from `src-tauri/icons/icon.svg`.
//
// Run with:
//   node scripts/regen-icons.mjs        # via this wrapper
//   npm run icons                       # equivalent npm-script alias
//
// Why a wrapper instead of just `npx @tauri-apps/cli icon`?
//   - Pins the source to `icon.svg` so contributors don't have to
//     remember the path.
//   - Centralises the "this is how rahgozar icons are derived" docstring
//     in one place that lives next to the generated output.
//   - Leaves room for additional steps later (compress with oxipng,
//     copy a 512 px PNG into the egui binary's resource section, etc.)
//     without each contributor needing to learn a new manual command.
//
// The hand-rolled rasteriser this file replaced (commit before phase A
// landing) re-implemented the arch geometry in JS and approximated the
// cubic Bézier top with a half-ellipse — close, but not identical to
// the Android `ic_launcher_foreground.xml` source. Routing through
// Tauri's CLI uses resvg under the hood and matches the SVG exactly.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, "..");
const svg = join(projectRoot, "src-tauri", "icons", "icon.svg");

// Node 24 tightened spawn() on Windows: it no longer special-cases .cmd
// shims, so `spawn("npx.cmd", ...)` fails with EINVAL even though that
// was the documented Node 20 workaround. Routing through the system
// shell on Windows restores the prior behaviour. Linux/macOS keep
// shell: false to avoid the extra word-splitting layer.
const isWin = process.platform === "win32";
const child = spawn(
  isWin ? "npx.cmd" : "npx",
  ["@tauri-apps/cli", "icon", svg, "--output", join(projectRoot, "src-tauri", "icons")],
  { stdio: "inherit", cwd: projectRoot, shell: isWin },
);

child.on("exit", (code) => {
  process.exit(code ?? 0);
});
