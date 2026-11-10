//! PeerHarness skills: strict `SKILL.md` handling, risk scanning, immutable bundles and
//! safe installation (specification section 9, architecture section 11, ADR-005).
//!
//! Format: the Agent Skills specification (<https://agentskills.io/specification>).
//! v0 distributes instruction-only skills: a bundle is exactly one `SKILL.md`.
//!
//! # Typical flows
//!
//! **Create a local skill** (from a candidate draft):
//! [`render_skill_md`] → [`build_bundle`] → [`BundleStore::put`] → show [`scan`] findings
//! and [`unified_diff`] → [`Installer::install`].
//!
//! **Propose**: put `bundle.digest()`, `bundle.size()`, `bundle.name()` and
//! `bundle.description()` into a `ph_protocol::ProposalBody`.
//!
//! **Serve `FetchBundle`**: [`BundleStore::get`] → [`to_wire_files`] →
//! `Response::Bundle { digest, files }`.
//!
//! **Receive a bundle**: [`from_wire_files`] with the digest from the PROPOSAL (and the
//! proposal's `skill_name` as `expected_name`) → [`BundleStore::put`].
//!
//! **Adopt / install**: [`BundleStore::get`] → [`Bundle::scan`]; if
//! [`has_high_risk`] require an extra explicit confirmation flag → show
//! [`unified_diff`] against the currently installed `SKILL.md` (if any) → human
//! confirmation → [`Installer::install`] with [`claude_installer`] → record the
//! [`InstallOutcome`] (path, digest, `previous_digest`) in the `installations` table.
//!
//! **Rollback**: [`BundleStore::get`]`(previous_digest)` → [`Installer::install`].
//!
//! **Uninstall**: [`Installer::uninstall`].
//!
//! # Security notes
//!
//! * The risk scanner is advisory. **Scanning never proves safety**; received Markdown
//!   is untrusted agent instructions.
//! * Error `Display` strings and `Debug` output never include skill content.
//! * Nothing in this crate executes skill content.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bundle;
pub mod diff;
pub mod error;
pub mod frontmatter;
mod fsutil;
pub mod install;
pub mod render;
pub mod scanner;
pub mod store;
pub mod validate;

pub use bundle::{
    build_bundle, check_bundle_path, check_instruction_only, digest_for_skill_md, from_wire_files,
    has_shell_injection, to_wire_files, validate_received, Bundle, SKILL_FILE_NAME,
};
pub use diff::{sanitize_for_display, unified_diff};
pub use error::{
    BundleError, InstallError, PathRejection, RenderError, SkillError, StoreError, SyntaxError,
    ValidationError,
};
pub use frontmatter::{parse_skill_md, Frontmatter, SkillDoc, MAX_FRONTMATTER_BYTES};
pub use install::{
    claude_installer, claude_skills_dir, resolve_claude_skills_dir, InstallMarker, InstallOptions,
    InstallOutcome, InstallState, Installer, SkillScope, UninstallOptions, UninstallOutcome,
    CLAUDE_SKILLS_DIR_ENV, MARKER_FILE_NAME,
};
pub use render::{normalize_body, render_skill_md};
pub use scanner::{has_high_risk, max_severity, scan, RiskFinding, Severity};
pub use store::{BundleStore, PutOutcome};
pub use validate::{check_skill_bytes, validate_skill, MAX_SKILL_FILE_BYTES};
