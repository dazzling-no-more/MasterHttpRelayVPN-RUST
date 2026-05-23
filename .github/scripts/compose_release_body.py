"""Compose the GitHub Release body for a rahgozar tag.

Called from `.github/workflows/release.yml`'s `release` job after the
build matrix has populated `dist/`. Reads three env vars:

  VERSION         e.g. "2.7.0" (no leading v)
  REPO_PATH       e.g. "dazzling-no-more/rahgozar"
  CHANGELOG_PATH  path to docs/changelog/v<VERSION>.md

Prints the composed markdown to stdout. The shape mirrors astral-sh/uv:

  1. ## Install
       — quick-pick links per platform (Windows / macOS / Linux desktop
         installers, Android APK, Docker pull for exit-node).
       — sends CLI / router / per-ABI APK users down to the Download
         table below rather than dumping 40 assets at the top.

  2. The bilingual changelog from `docs/changelog/v<VERSION>.md`
       (Persian first, then `---`, then English). Leading HTML comments
       in the file are stripped.

  3. ## Download
       — single flat table of every non-signature asset, sorted into a
         human-friendly order (desktop installers → mobile → CLI →
         routers → exit-node bridge). One row per asset, with a "platform"
         description telling the user what hardware/OS each file targets.
       — uv-style: one table, not nested collapsibles, scannable in a
         glance.

  4. Signatures and the updater manifest are uploaded but intentionally
       NOT listed in the body. They're verification artifacts; surfacing
       them at the same visual weight as the binaries makes the page feel
       chaotic without giving users any useful choice to make. They're
       still attached to the release (look at the Assets accordion) and
       still referenced by the in-app updater.

The matching `softprops/action-gh-release` step appends GitHub's auto-
generated "What's Changed" + "Full Changelog: …" comparison link AFTER
this body.

Asset selection rule: each table row is described by an (regex, label)
pair below. `first()` returns the first dist/ filename that fully matches
the regex, or None. Missing assets — typical case is a tier-3 musl build
that ran with `continue-on-error: true` — silently drop their row, so
the rendered body never references a 404 download.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys


def main() -> int:
    ver = os.environ["VERSION"]
    repo = os.environ["REPO_PATH"]
    changelog_path = os.environ["CHANGELOG_PATH"]
    dist = pathlib.Path("dist")

    def asset_url(name: str) -> str:
        return f"https://github.com/{repo}/releases/download/v{ver}/{name}"

    # Flatten dist/ — actions/download-artifact preserves the Tauri bundle
    # subdirs (dist/msi/, dist/dmg/, dist/portable/, …) while CLI / APK
    # files arrive flat. We match on basenames so the same regex works
    # regardless of layout. Skip signature + manifest noise — those are
    # uploaded but never linked from the body.
    all_files = sorted({p.name for p in dist.rglob("*") if p.is_file()})
    binary_files = [
        f
        for f in all_files
        if not (f.endswith(".minisig") or f.endswith(".sig") or f == "latest.json")
    ]

    def first(pattern: str) -> str | None:
        rx = re.compile(pattern)
        for f in binary_files:
            if rx.fullmatch(f):
                return f
        return None

    # ── 1. Install ──────────────────────────────────────────────────
    # One `<details>` per platform — collapsed by default so the page
    # opens compact, but a click on (e.g.) "Windows" expands the right
    # options without scrolling past every other OS. uv-style spirit
    # ("pick your platform first") plus the desktop-app reality
    # ("there's no curl one-liner, just direct installer links").
    #
    # Inside each summary, recommended choices come first; alternates
    # (CLI tarballs, per-ABI APKs) are pushed to the Download table
    # at the bottom to keep the dropdown short.
    win_msi = first(r"rahgozar_.+_x64_en-US\.msi")
    win_portable = first(r"rahgozar-portable-windows-amd64\.exe")
    mac_arm_dmg = first(r"rahgozar_.+_aarch64\.dmg")
    mac_intel_dmg = first(r"rahgozar_.+_x64\.dmg")
    mac_app = first(r"rahgozar\.app\.tar\.gz")
    linux_deb = first(r"rahgozar_.+_amd64\.deb")
    linux_appimg = first(r"rahgozar_.+_amd64\.AppImage")
    linux_rpm = first(r"rahgozar-.+\.x86_64\.rpm")
    apk_universal = first(r"rahgozar-android-universal-v.+\.apk")
    owner = repo.split("/")[0]

    install: list[str] = ["## Install", ""]

    def add_details(summary: str, lines: list[str]) -> None:
        if not lines:
            return
        install.append(f"<details><summary><b>{summary}</b></summary>")
        install.append("")
        install.extend(lines)
        install.append("")
        install.append("</details>")
        install.append("")

    # Windows
    rows: list[str] = []
    if win_msi:
        rows.append(f"- [Installer (MSI)]({asset_url(win_msi)}) — standard install (most users)")
    if win_portable:
        rows.append(f"- [Portable .exe]({asset_url(win_portable)}) — single file, no install, no UAC")
    add_details("Windows", rows)

    # macOS
    rows = []
    if mac_arm_dmg:
        rows.append(f"- [Apple Silicon (.dmg)]({asset_url(mac_arm_dmg)}) — M1 / M2 / M3 / M4")
    if mac_intel_dmg:
        rows.append(f"- [Intel (.dmg)]({asset_url(mac_intel_dmg)}) — older Intel Macs")
    if (not mac_arm_dmg) and (not mac_intel_dmg) and mac_app:
        rows.append(f"- [.app bundle]({asset_url(mac_app)})")
    add_details("macOS", rows)

    # Linux desktop
    rows = []
    if linux_deb:
        rows.append(f"- [.deb]({asset_url(linux_deb)}) — Debian, Ubuntu, Mint")
    if linux_appimg:
        rows.append(f"- [.AppImage]({asset_url(linux_appimg)}) — any distro")
    if linux_rpm:
        rows.append(f"- [.rpm]({asset_url(linux_rpm)}) — Fedora, RHEL, openSUSE")
    add_details("Linux desktop", rows)

    # Android — universal APK is the recommended pick. Per-ABI APKs are
    # only worth surfacing for users on really tight connections, and
    # they're already listed in the Download table below.
    if apk_universal:
        add_details(
            "Android (phone / TV)",
            [
                f"- [Universal APK]({asset_url(apk_universal)}) — works on any device (~50 MB).",
                "",
                "Smaller per-ABI APKs (arm64-v8a ~15 MB, etc.) are in the Download table below.",
            ],
        )

    # Exit-node bridge — docker is the easy path, static binaries are
    # below the fence so the summary stays scannable.
    tunnel_amd64 = first(r"rahgozar-tunnel-node-linux-musl-amd64\.tar\.gz")
    tunnel_arm64 = first(r"rahgozar-tunnel-node-linux-musl-arm64\.tar\.gz")
    tunnel_rows: list[str] = [
        "```sh",
        f"docker pull ghcr.io/{owner}/rahgozar-tunnel-node:{ver}",
        "```",
    ]
    static_links: list[str] = []
    if tunnel_amd64:
        static_links.append(f"[amd64]({asset_url(tunnel_amd64)})")
    if tunnel_arm64:
        static_links.append(f"[arm64]({asset_url(tunnel_arm64)})")
    if static_links:
        tunnel_rows.append("")
        tunnel_rows.append("Or grab a static binary: " + " · ".join(static_links) + ".")
    add_details("Exit-node bridge (VPS)", tunnel_rows)

    install.append(
        "_CLI tarballs, OpenWRT router builds, and per-ABI Android APKs "
        "are listed in the [Download](#download) table at the bottom of this page._"
    )
    install_md = "\n".join(install) + "\n"

    # ── 2. Bilingual changelog ──────────────────────────────────────
    changelog = pathlib.Path(changelog_path).read_text(encoding="utf-8")
    changelog = re.sub(r"^\s*(?:<!--.*?-->\s*)+", "", changelog, count=1, flags=re.S)

    # ── 3. Download table ──────────────────────────────────────────
    # (regex matching the asset filename, platform-description column).
    # Order is the order users encounter them — desktop installers first,
    # then mobile, then CLI tarballs (most → least common platform),
    # then router / static-musl, then exit-node bridge.
    table_rows: list[tuple[str, str]] = [
        # Windows
        (r"rahgozar_.+_x64_en-US\.msi", "Windows desktop, MSI installer (most users)"),
        (r"rahgozar_.+_x64-setup\.exe", "Windows desktop, NSIS installer"),
        (r"rahgozar-portable-windows-amd64\.exe", "Windows desktop, portable .exe (no install, no UAC)"),
        # macOS
        (r"rahgozar_.+_aarch64\.dmg", "macOS desktop, Apple Silicon DMG"),
        (r"rahgozar_.+_x64\.dmg", "macOS desktop, Intel DMG"),
        (r"rahgozar\.app\.tar\.gz", "macOS desktop, .app bundle (drives in-app auto-update)"),
        # Linux desktop
        (r"rahgozar_.+_amd64\.deb", "Linux desktop, Debian / Ubuntu / Mint .deb"),
        (r"rahgozar_.+_amd64\.AppImage", "Linux desktop, universal AppImage"),
        (r"rahgozar-.+\.x86_64\.rpm", "Linux desktop, Fedora / RHEL / openSUSE .rpm"),
        # Android
        (r"rahgozar-android-universal-v.+\.apk", "Android phone / TV, universal APK (works on any device, ~50 MB)"),
        (r"rahgozar-android-arm64-v8a-v.+\.apk", "Android, arm64-v8a (modern 64-bit ARM phones, ~15 MB)"),
        (r"rahgozar-android-armeabi-v7a-v.+\.apk", "Android, armeabi-v7a (older 32-bit ARM phones)"),
        (r"rahgozar-android-x86_64-v.+\.apk", "Android, x86_64 (emulator on Intel Mac / Chromebook)"),
        (r"rahgozar-android-x86-v.+\.apk", "Android, x86 (legacy 32-bit Intel emulator)"),
        # CLI — desktop / server
        (r"rahgozar-windows-amd64\.zip", "Windows CLI, x86_64"),
        (r"rahgozar-windows-arm64\.zip", "Windows CLI, ARM64 (Snapdragon X, Surface Pro X+11)"),
        (r"rahgozar-macos-arm64\.tar\.gz", "macOS CLI, Apple Silicon"),
        (r"rahgozar-macos-amd64\.tar\.gz", "macOS CLI, Intel"),
        (r"rahgozar-linux-amd64\.tar\.gz", "Linux CLI, x86_64 glibc"),
        (r"rahgozar-linux-arm64\.tar\.gz", "Linux CLI, aarch64 glibc"),
        (r"rahgozar-raspbian-armhf\.tar\.gz", "Linux CLI, Raspberry Pi (armv7 hard-float)"),
        # OpenWRT / static-musl routers
        (r"rahgozar-linux-musl-amd64\.tar\.gz", "Static x86_64 musl (Alpine, libc-less containers)"),
        (r"rahgozar-linux-musl-arm64\.tar\.gz", "Static aarch64 musl"),
        (r"rahgozar-openwrt-armv7-musleabihf\.tar\.gz", "OpenWRT, armv7 hard-float (Archer C2600, WRT3200ACM, Brume/Beryl)"),
        (r"rahgozar-openwrt-mipsel-softfloat\.tar\.gz", "OpenWRT, MIPSEL soft-float (MT7621 chipsets)"),
        (r"rahgozar-openwrt-mips-softfloat\.tar\.gz", "OpenWRT, MIPS big-endian soft-float (Atheros AR71XX/AR9XXX)"),
        # Exit-node bridge (binary fallback for users who don't want Docker)
        (r"rahgozar-tunnel-node-linux-musl-amd64\.tar\.gz", "Exit-node bridge, static x86_64 (binary, alternative to docker)"),
        (r"rahgozar-tunnel-node-linux-musl-arm64\.tar\.gz", "Exit-node bridge, static aarch64 (binary, alternative to docker)"),
    ]

    download_lines: list[str] = [
        "## Download",
        "",
        f"All rahgozar v{ver} binaries. Click an asset name to download it.",
        "",
        "| Asset | Platform |",
        "|---|---|",
    ]
    matched_any = False
    for pat, description in table_rows:
        name = first(pat)
        if not name:
            continue
        matched_any = True
        download_lines.append(f"| [`{name}`]({asset_url(name)}) | {description} |")

    if not matched_any:
        # Defensive — every release has at least the universal APK + a CLI
        # tarball. If somehow the table is empty, fall back to a plain
        # "see Assets section" hint rather than rendering a header with
        # no rows.
        download_lines.append("| _(no binaries staged in dist/; see the Assets section below)_ | |")

    download_lines.append("")
    download_lines.append(
        "_Each binary is signed; matching `.minisig` (CLI / Android / portable) and "
        "`.sig` (Tauri-bundled desktop installer) files are attached to this release. "
        "The Tauri auto-updater consumes `latest.json`, also attached._"
    )
    download_md = "\n".join(download_lines)

    # `---` between each section so GitHub renders a visible horizontal
    # rule. Without it, the collapsed dropdowns at the end of Install
    # bleed straight into the Persian opening of the changelog, which
    # looks like one runaway block. The bilingual changelog ALREADY
    # uses an internal `---` between its Persian and English halves —
    # the outer separators here are different beasts (section dividers,
    # not language dividers).
    sys.stdout.write(install_md)
    sys.stdout.write("\n---\n\n")
    sys.stdout.write(changelog.rstrip())
    sys.stdout.write("\n\n---\n\n")
    sys.stdout.write(download_md)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
