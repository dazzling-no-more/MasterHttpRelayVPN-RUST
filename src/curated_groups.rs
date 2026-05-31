//! Curated fronting groups bundled with the binary.
//!
//! The JSON at `assets/fronting-groups/curated.json` ships a tested set
//! of (sni, edge IP, member-domain) tuples for Vercel, Fastly, AWS
//! CloudFront, and direct-to-GitHub paths — derived from
//! patterniha/MITM-DomainFronting. The UI exposes a button to install
//! these into the user's `fronting_groups` config in one click; CLI
//! users can copy `config.fronting-groups.example.json` (same data).
//!
//! Keep the asset in sync with the example file. `merge_into` is the
//! merge entry point: it appends groups whose `name` isn't already
//! present, leaving the user's hand-edited entries alone.
//!
//! Edge IPs rotate. The `sni` is the source of truth for re-resolution
//! (`nslookup <sni>`); see docs/fronting-groups.md.

use serde::Deserialize;

use crate::config::FrontingGroup;

/// Embedded JSON from `assets/fronting-groups/curated.json`. The path
/// is relative to the source file (`src/curated_groups.rs`), so the
/// `..` walks up to the crate root where `assets/` lives.
const CURATED_JSON: &str = include_str!("../assets/fronting-groups/curated.json");

#[derive(Debug, Deserialize)]
struct Bundle {
    fronting_groups: Vec<FrontingGroup>,
}

/// Parsed curated fronting groups. Returns the same list every call
/// — cheap enough that we don't bother caching across calls.
pub fn curated_fronting_groups() -> Result<Vec<FrontingGroup>, serde_json::Error> {
    let bundle: Bundle = serde_json::from_str(CURATED_JSON)?;
    Ok(bundle.fronting_groups)
}

/// Result of a `merge_into` call, surfaced to the UI for toast text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Groups newly appended to `existing`.
    pub added: usize,
    /// Groups skipped because a group with the same `name` was already
    /// present. The user's entry is left untouched (we never overwrite
    /// hand-edits).
    pub skipped: usize,
}

/// Append every curated group whose `name` isn't already in `existing`.
/// Skipped groups are counted in the report. Names compare
/// case-insensitively after trim, matching the way humans edit configs.
pub fn merge_into(existing: &mut Vec<FrontingGroup>) -> Result<MergeReport, serde_json::Error> {
    let curated = curated_fronting_groups()?;
    let mut report = MergeReport::default();
    for g in curated {
        let already = existing
            .iter()
            .any(|e| e.name.trim().eq_ignore_ascii_case(g.name.trim()));
        if already {
            report.skipped += 1;
        } else {
            existing.push(g);
            report.added += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_bundle_parses() {
        let groups = curated_fronting_groups().expect("curated.json must parse");
        assert!(
            !groups.is_empty(),
            "curated bundle should ship at least one group"
        );
        // The github-* groups must come before fastly, otherwise
        // fastly's `githubusercontent.com` suffix entry would eat their
        // requests under first-match-wins (`match_fronting_group`
        // returns the first matching group and never retries the rest
        // on dial failure). github-central owns
        // `objects-origin.githubusercontent.com`; github-uploads owns
        // `alambic-origin.githubusercontent.com` and
        // `camo-origin.githubusercontent.com`.
        let pos = |n: &str| groups.iter().position(|g| g.name == n);
        let fastly = pos("fastly").expect("fastly present");
        for gh in &["github-central", "github-uploads"] {
            let idx = pos(gh).unwrap_or_else(|| panic!("{} present", gh));
            assert!(
                idx < fastly,
                "{} must precede fastly for first-match-wins",
                gh
            );
        }
        // github-uploads must also precede the broad `github` group:
        // `github` lists bare `github.com` in its domains, and the
        // matcher's dot-anchored suffix rule means `github.com` matches
        // `uploads.github.com` too. If `github` ran first, the new
        // upload route would be dead code (see review of
        // patterniha-v20 sync, 2026-05-19).
        let github_uploads = pos("github-uploads").expect("github-uploads present");
        let github = pos("github").expect("github present");
        assert!(
            github_uploads < github,
            "github-uploads must precede github — bare `github.com` would otherwise \
             shadow the *.github.com upload subdomains under first-match-wins"
        );
    }

    /// Sentinel coverage test: each of these hostnames is a
    /// documented user-facing curated route. PR #1191's expansion
    /// accidentally dropped `pypi.org` from fastly's domain list (it
    /// stayed only as the group's `sni`), so users running through
    /// the curated bundle saw pypi.org fall back to the relay
    /// instead of the direct Fastly edge. Pin the routes here so a
    /// similar accidental drop fails CI loudly instead of shipping.
    #[test]
    fn curated_covers_user_facing_routes() {
        let groups = curated_fronting_groups().expect("curated.json parses");
        let all_domains: std::collections::HashSet<&str> = groups
            .iter()
            .flat_map(|g| g.domains.iter().map(String::as_str))
            .collect();
        for expected in &[
            // Fastly users
            "pypi.org",
            "www.python.org",
            "reddit.com",
            "github.io",
            "githubusercontent.com",
            // Vercel users
            "nextjs.org",
            "vercel.com",
            // GitHub-direct routes
            "gist.github.com",
            "github.com",
            "www.github.com",
            "objects-origin.githubusercontent.com",
            "collector.github.com",
            "alive.github.com",
            // GitHub uploads / release-asset paths (patterniha v20)
            "uploads.github.com",
            "alambic-origin.githubusercontent.com",
            "camo-origin.githubusercontent.com",
            // Other curated edges
            "netlify.app",
            "pmc.ncbi.nlm.nih.gov",
            // Camouflage (force_ip) routes — patterniha v22 parity.
            "googlevideo.com",
            "youtube.com",
            "youtubei.googleapis.com",
            "ytimg.com",
            "instagram.com",
            "whatsapp.com",
            "facebook.com",
        ] {
            assert!(
                all_domains.contains(expected),
                "curated bundle must cover `{}` — regressions here usually mean an edit dropped a domain (see PR #1191 / pypi.org)",
                expected,
            );
        }
    }

    /// First-match winner test. `curated_covers_user_facing_routes`
    /// only checks that a domain *appears somewhere* in the bundle —
    /// it would happily pass if a later group's domain was shadowed
    /// by an earlier group's broader suffix. This test exercises the
    /// real production matcher (`match_fronting_group` over
    /// `FrontingGroupResolved::from_config`) and pins which group
    /// actually wins for each host, catching ordering regressions
    /// like the patterniha-v20-sync bug where bare `github.com` in
    /// the `github` group shadowed `uploads.github.com` because
    /// `github` ran before `github-uploads`.
    #[test]
    fn curated_first_match_winners() {
        use crate::proxy_server::{match_fronting_group, FrontingGroupResolved};
        use std::sync::Arc;
        let curated = curated_fronting_groups().expect("curated.json parses");
        let resolved: Vec<Arc<FrontingGroupResolved>> = curated
            .iter()
            .map(|g| {
                Arc::new(
                    FrontingGroupResolved::from_config(g)
                        .unwrap_or_else(|e| panic!("group {} resolves: {}", g.name, e)),
                )
            })
            .collect();
        let cases: &[(&str, &str)] = &[
            // GitHub edge — explicit per-host routing under the broad
            // `github.com` suffix in the `github` group; ordering is
            // what makes this work.
            ("uploads.github.com", "github-uploads"),
            ("alambic-origin.githubusercontent.com", "github-uploads"),
            ("camo-origin.githubusercontent.com", "github-uploads"),
            ("alive.github.com", "github-alive"),
            ("live.github.com", "github-alive"),
            ("central.github.com", "github-central"),
            ("collector.github.com", "github-central"),
            ("objects-origin.githubusercontent.com", "github-central"),
            ("api.githubcopilot.com", "github-central"),
            ("gist.github.com", "github"),
            ("github.com", "github"),
            ("www.github.com", "github"),
            // Other curated edges.
            ("raw.githubusercontent.com", "fastly"),
            ("xtls.github.io", "fastly"),
            ("reddit.com", "fastly"),
            ("pypi.org", "fastly"),
            ("nextjs.org", "vercel"),
            ("vercel.com", "vercel"),
            ("netlify.app", "amazon-cloudfront"),
            ("pmc.ncbi.nlm.nih.gov", "pubmed"),
            // Camouflage (force_ip) routes.
            ("r1---sn-aigl6n7e.googlevideo.com", "google-video"),
            ("googlevideo.com", "google-video"),
            ("www.youtube.com", "youtube-web"),
            ("youtube.com", "youtube-web"),
            ("i.ytimg.com", "youtube-web"),
            ("youtubei.googleapis.com", "youtube-web"),
            ("scontent.cdninstagram.com", "meta"),
            ("www.instagram.com", "meta"),
            ("web.whatsapp.com", "meta"),
        ];
        for (host, expected) in cases {
            let got = match_fronting_group(host, &resolved).unwrap_or_else(|| {
                panic!("host `{}` matched no group, expected `{}`", host, expected)
            });
            assert_eq!(
                &got.name, expected,
                "host `{}` should route to `{}`, got `{}`",
                host, expected, got.name
            );
        }
    }

    #[test]
    fn merge_into_skips_existing_by_name() {
        let mut existing = vec![FrontingGroup {
            name: "vercel".into(),
            ip: "1.2.3.4".into(),
            sni: "user-edited.example".into(),
            domains: vec!["user.example".into()],
            force_ip: false,
            verify_names: vec![],
        }];
        let before_len = existing.len();
        let report = merge_into(&mut existing).expect("merge should succeed");
        // The user's vercel entry stays put.
        let user_vercel = existing
            .iter()
            .find(|g| g.name == "vercel")
            .expect("user vercel group preserved");
        assert_eq!(user_vercel.ip, "1.2.3.4");
        assert_eq!(user_vercel.sni, "user-edited.example");
        assert_eq!(report.skipped, 1, "vercel collision should be reported");
        assert_eq!(existing.len(), before_len + report.added);
    }

    #[test]
    fn merge_into_adds_all_when_empty() {
        let mut existing: Vec<FrontingGroup> = Vec::new();
        let report = merge_into(&mut existing).expect("merge should succeed");
        assert_eq!(report.skipped, 0);
        assert!(report.added > 0);
        assert_eq!(existing.len(), report.added);
    }

    /// The example config file at the repo root mirrors the curated
    /// asset bundle. Both files exist for different audiences (CLI
    /// users copy the example, UI users hit the button to load the
    /// asset) but their `fronting_groups` payloads must stay identical
    /// so the two paths can't drift. This test pins that property.
    /// Together with [example_file_loads_through_validate] it also
    /// confirms the asset is a valid input to the real load path.
    #[test]
    fn example_file_mirrors_curated_bundle() {
        use crate::config::Config;
        let curated = curated_fronting_groups().expect("curated.json parses");
        let example_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config.fronting-groups.example.json");
        let example_cfg = Config::load(&example_path).expect("example file must load + validate");
        assert_eq!(
            curated.len(),
            example_cfg.fronting_groups.len(),
            "curated.json and the example file must declare the same group count"
        );
        for (c, e) in curated.iter().zip(example_cfg.fronting_groups.iter()) {
            assert_eq!(c.name, e.name, "group name");
            assert_eq!(c.ip, e.ip, "group ip ({})", c.name);
            assert_eq!(c.sni, e.sni, "group sni ({})", c.name);
            assert_eq!(c.domains, e.domains, "group domains ({})", c.name);
            assert_eq!(c.force_ip, e.force_ip, "group force_ip ({})", c.name);
            assert_eq!(
                c.verify_names, e.verify_names,
                "group verify_names ({})",
                c.name
            );
        }
    }

    /// Run the curated bundle through the same `Config::load` path the
    /// CLI and UI use at startup — this exercises the SNI parse, the
    /// per-group field validators, and the duplicate-name check inside
    /// `validate()`. Catches the failure mode where curated.json and
    /// the validator drift apart (e.g. a future validator tightens
    /// what counts as a valid SNI but a curated entry slips through
    /// because it was only tested against `serde_json::from_str`).
    #[test]
    fn example_file_loads_through_validate() {
        use crate::config::Config;
        let example_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config.fronting-groups.example.json");
        let cfg = Config::load(&example_path)
            .expect("example file with curated groups must pass Config::validate");
        assert!(
            !cfg.fronting_groups.is_empty(),
            "example file should declare fronting groups"
        );
    }
}
