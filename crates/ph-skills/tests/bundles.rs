//! Bundle building, the spec example, and hostile-bundle rejection.

use ph_core::Digest;
use ph_protocol::wire::WireFile;
use ph_skills::*;

const PNPM: &str = include_str!("fixtures/pnpm-repository-convention/SKILL.md");
/// Computed independently (Python hashlib) from the fixture bytes and the manifest JCS.
const PNPM_DIGEST: &str = "sha256:b10cbaca70e81fd3451b9cbc6b476edf1c4be19b62dc0ade588f52171bbb22c7";
const PNPM_SHA256: &str = "sha256:0eae44733cd02d5d6331ee24a7ad8561e79274445f8ed925507b87fbbb3b4398";

fn pnpm() -> Bundle {
    build_bundle(PNPM, Some("pnpm-repository-convention")).unwrap()
}

#[test]
fn spec_example_parses_validates_and_has_stable_digest() {
    let doc = parse_skill_md(PNPM).unwrap();
    assert_eq!(doc.frontmatter.name, "pnpm-repository-convention");
    assert_eq!(
        doc.frontmatter.description,
        "Use pnpm when installing packages or running package scripts in the specified repository."
    );
    assert!(doc.body.starts_with("When working in this repository"));
    validate_skill(&doc, Some("pnpm-repository-convention")).unwrap();

    let b = pnpm();
    assert_eq!(b.digest().to_string(), PNPM_DIGEST);
    assert_eq!(b.manifest().files.len(), 1);
    assert_eq!(b.manifest().files[0].path, "SKILL.md");
    assert_eq!(b.manifest().files[0].sha256.to_string(), PNPM_SHA256);
    assert_eq!(b.size(), 357);
    assert_eq!(b.manifest().to_canonical_json().unwrap(), format!(
        "{{\"files\":[{{\"path\":\"SKILL.md\",\"sha256\":\"{PNPM_SHA256}\",\"size\":357}}],\"schema\":\"peerharness.bundle/0.1\"}}"
    ));
    assert!(b.scan().is_empty(), "{:?}", b.scan());

    // The renderer produces byte-identical output for the same inputs.
    let rendered = render_skill_md(
        &doc.frontmatter.name,
        &doc.frontmatter.description,
        &doc.body,
        None,
    )
    .unwrap();
    assert_eq!(rendered, PNPM);
}

#[test]
fn build_rejects_bad_input() {
    assert!(matches!(
        build_bundle(PNPM, Some("other-dir")),
        Err(BundleError::Invalid(e)) if e == vec![ValidationError::NameMismatch]
    ));
    assert!(matches!(
        build_bundle("no frontmatter", None),
        Err(BundleError::Parse(SkillError::MissingFrontmatter))
    ));
    assert!(matches!(
        build_bundle(&PNPM.replace("dependency", "a\0b"), None),
        Err(BundleError::Nul)
    ));
    let huge = format!("{PNPM}{}", "x".repeat(MAX_SKILL_FILE_BYTES));
    assert!(matches!(
        build_bundle(&huge, None),
        Err(BundleError::TooLarge { .. })
    ));
    let no_body = "---\nname: a\ndescription: b\n---\n\n   \n";
    assert!(matches!(
        build_bundle(no_body, None),
        Err(BundleError::Invalid(_))
    ));
}

fn recv(files: Vec<(&str, &[u8])>, d: &Digest) -> Result<Bundle, BundleError> {
    validate_received(
        files
            .into_iter()
            .map(|(p, c)| (p.to_owned(), c.to_vec()))
            .collect(),
        d,
        Some("pnpm-repository-convention"),
    )
}

#[test]
fn received_ok() {
    let b = pnpm();
    let r = recv(vec![("SKILL.md", PNPM.as_bytes())], &b.digest()).unwrap();
    assert_eq!(r, b);
}

#[test]
fn hostile_paths_rejected() {
    let d = pnpm().digest();
    let paths = [
        "./SKILL.md",
        "../SKILL.md",
        "../x",
        "a/../../SKILL.md",
        "/SKILL.md",
        "/etc/passwd",
        "C:\\SKILL.md",
        "C:SKILL.md",
        "\\\\host\\share\\SKILL.md",
        "x\\SKILL.md",
        "skill.md",
        "Skill.md",
        "SKILL.MD",
        "sKILL.md",
        "\u{ff33}KILL.md",  // fullwidth S
        "\u{0405}KILL.md",  // Cyrillic DZE homoglyph
        "SK\u{0399}LL.md",  // Greek capital iota
        "SKILL\u{2024}md",  // one dot leader
        "S\u{200b}KILL.md", // zero-width space
        "SKILL.md\u{0301}", // combining mark (NFD trick)
        "\u{1e60}KILL.md",  // precomposed S with dot (NFC form)
        "S\u{0307}KILL.md", // decomposed S + combining dot (NFD form)
        "SKILL.md ",
        " SKILL.md",
        "SKILL.md/",
        "SKILL.md\0",
        ".SKILL.md",
        ".hidden",
        "scripts/install.sh",
        "references/REFERENCE.md",
        "",
    ];
    for p in paths {
        let r = recv(vec![(p, PNPM.as_bytes())], &d);
        assert!(
            matches!(r, Err(BundleError::Path { index: 0, .. })),
            "{p:?} -> {r:?}"
        );
    }
}

#[test]
fn extra_duplicate_empty_rejected() {
    let d = pnpm().digest();
    let c = PNPM.as_bytes();
    assert!(matches!(recv(vec![], &d), Err(BundleError::Empty)));
    assert!(matches!(
        recv(vec![("SKILL.md", c), ("README.md", b"x")], &d),
        Err(BundleError::Path {
            index: 1,
            reason: PathRejection::UnexpectedFile
        })
    ));
    assert!(matches!(
        recv(vec![("SKILL.md", c), ("scripts/run.sh", b"#!/bin/sh")], &d),
        Err(BundleError::Path {
            index: 1,
            reason: PathRejection::Nested
        })
    ));
    assert!(matches!(
        recv(vec![("SKILL.md", c), (".env", b"TOKEN=x")], &d),
        Err(BundleError::Path {
            index: 1,
            reason: PathRejection::Hidden
        })
    ));
    assert!(matches!(
        recv(vec![("SKILL.md", c), ("SKILL.md", c)], &d),
        Err(BundleError::Duplicate)
    ));
    let many: Vec<(&str, &[u8])> = (0..100).map(|_| ("SKILL.md", c)).collect();
    assert!(matches!(
        recv(many, &d),
        Err(BundleError::TooManyFiles { count: 100 })
    ));
}

#[test]
fn content_rejections() {
    // oversize
    let big = vec![b'a'; MAX_SKILL_FILE_BYTES + 1];
    let d = digest_for_skill_md(&big).unwrap();
    assert!(matches!(
        recv(vec![("SKILL.md", &big)], &d),
        Err(BundleError::TooLarge { .. })
    ));

    // digest mismatch (including a correct digest for different content)
    let d = pnpm().digest();
    let tampered = PNPM.replace("pnpm instead of npm", "npm instead of pnpm");
    assert!(matches!(
        recv(vec![("SKILL.md", tampered.as_bytes())], &d),
        Err(BundleError::DigestMismatch)
    ));
    assert!(matches!(
        recv(
            vec![("SKILL.md", PNPM.as_bytes())],
            &Digest::sha256(PNPM.as_bytes())
        ),
        Err(BundleError::DigestMismatch)
    ));

    // NUL (digest matches, content still refused)
    let nul = PNPM.replace("dependency", "depend\0ency").into_bytes();
    let d = digest_for_skill_md(&nul).unwrap();
    assert!(matches!(
        recv(vec![("SKILL.md", &nul)], &d),
        Err(BundleError::Nul)
    ));

    // invalid UTF-8
    let mut bad = PNPM.as_bytes().to_vec();
    bad.extend_from_slice(&[0xc3, 0x28, 0xff]);
    let d = digest_for_skill_md(&bad).unwrap();
    assert!(matches!(
        recv(vec![("SKILL.md", &bad)], &d),
        Err(BundleError::InvalidUtf8)
    ));

    // overlong UTF-8 encoding of '/'
    let mut overlong = PNPM.as_bytes().to_vec();
    overlong.extend_from_slice(&[0xc0, 0xaf]);
    let d = digest_for_skill_md(&overlong).unwrap();
    assert!(matches!(
        recv(vec![("SKILL.md", &overlong)], &d),
        Err(BundleError::InvalidUtf8)
    ));

    // valid digest but invalid skill
    let anchors = "---\nname: &a pnpm-repository-convention\ndescription: x\n---\nbody\n";
    let d = digest_for_skill_md(anchors.as_bytes()).unwrap();
    assert!(matches!(
        recv(vec![("SKILL.md", anchors.as_bytes())], &d),
        Err(BundleError::Parse(SkillError::Syntax {
            kind: SyntaxError::Anchor,
            ..
        }))
    ));
    let wrong_name = PNPM.replace("name: pnpm-repository-convention", "name: other-name");
    let d = digest_for_skill_md(wrong_name.as_bytes()).unwrap();
    assert!(matches!(
        recv(vec![("SKILL.md", wrong_name.as_bytes())], &d),
        Err(BundleError::Invalid(e)) if e == vec![ValidationError::NameMismatch]
    ));
}

#[test]
fn wire_roundtrip_and_hostile_wire() {
    let b = pnpm();
    let files = to_wire_files(&b);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "SKILL.md");
    assert_eq!(
        from_wire_files(&files, &b.digest(), Some(b.name())).unwrap(),
        b
    );

    let bad_b64 = vec![WireFile {
        path: "SKILL.md".into(),
        content_b64: "!!!!".into(),
    }];
    assert!(matches!(
        from_wire_files(&bad_b64, &b.digest(), None),
        Err(BundleError::Encoding)
    ));
    let traversal = vec![WireFile::new("../SKILL.md", PNPM.as_bytes())];
    assert!(matches!(
        from_wire_files(&traversal, &b.digest(), None),
        Err(BundleError::Path { .. })
    ));
    let huge = vec![WireFile {
        path: "SKILL.md".into(),
        content_b64: "A".repeat(4 * 1024 * 1024),
    }];
    assert!(matches!(
        from_wire_files(&huge, &b.digest(), None),
        Err(BundleError::TooLarge { .. })
    ));
    assert!(matches!(
        from_wire_files(&[], &b.digest(), None),
        Err(BundleError::Empty)
    ));
    let two = vec![
        WireFile::new("SKILL.md", PNPM.as_bytes()),
        WireFile::new("SKILL.md", PNPM.as_bytes()),
    ];
    assert!(matches!(
        from_wire_files(&two, &b.digest(), None),
        Err(BundleError::Duplicate)
    ));
}

#[test]
fn errors_never_echo_content() {
    let secret = "sk-SECRET-TOKEN-1234567890";
    let text = format!("---\nname: a\ndescription: {secret}: x\n---\nbody\n");
    let e = build_bundle(&text, None).unwrap_err();
    assert!(!e.to_string().contains("SECRET"), "{e}");
    assert!(!format!("{e:?}").contains("SECRET"), "{e:?}");
    let e = validate_received(
        vec![(format!("../{secret}"), vec![])],
        &Digest::sha256(b""),
        None,
    )
    .unwrap_err();
    assert!(!e.to_string().contains("SECRET"));
    assert!(!format!("{e:?}").contains("SECRET"));
}

#[test]
fn windows_and_encoding_path_tricks_rejected() {
    let d = pnpm().digest();
    for p in [
        "SKILL.md.",       // Windows strips trailing dots
        "SKILL.md::$DATA", // NTFS alternate data stream
        "SKILL~1.MD",      // 8.3 short name
        "%2e%2e/SKILL.md", // percent-encoded traversal
        "SKILL%2Emd",
        "SKILL.md\r",
        "\u{feff}SKILL.md",
        "SKILL.md\u{a0}",
        "SKILL.md\u{2028}",
        "\\\\?\\C:\\SKILL.md",
        "file:SKILL.md",
        "SKILL.md;",
        "*",
        ".",
        "..",
    ] {
        let r = recv(vec![(p, PNPM.as_bytes())], &d);
        assert!(
            matches!(r, Err(BundleError::Path { index: 0, .. })),
            "{p:?} -> {r:?}"
        );
    }
}

/// The digest commits to the path, the size and the content (architecture section 11).
#[test]
fn digest_covers_path_size_and_content() {
    let c = PNPM.as_bytes();
    let base = digest_for_skill_md(c).unwrap();
    let other_path =
        ph_protocol::bundle_digest(&ph_protocol::manifest_for_files(&[("skill.md", c)])).unwrap();
    assert_ne!(base, other_path);
    let mut longer = c.to_vec();
    longer.push(b'\n');
    assert_ne!(base, digest_for_skill_md(&longer).unwrap());
    let flipped = PNPM.replacen('p', "q", 1);
    assert_eq!(flipped.len(), PNPM.len());
    assert_ne!(base, digest_for_skill_md(flipped.as_bytes()).unwrap());
    // The digest is not the plain content hash and not the manifest's file hash.
    assert_ne!(base, Digest::sha256(c));
    assert_eq!(pnpm().manifest().files[0].sha256, Digest::sha256(c));
    // A manifest listing an extra file changes the digest, so a peer cannot add files
    // under the same digest.
    let two = ph_protocol::bundle_digest(&ph_protocol::manifest_for_files(&[
        ("SKILL.md", c),
        ("run.sh", b"#!/bin/sh"),
    ]))
    .unwrap();
    assert_ne!(base, two);
    assert!(matches!(
        recv(vec![("SKILL.md", c), ("run.sh", b"#!/bin/sh")], &two),
        Err(BundleError::Path { index: 1, .. })
    ));
}

#[test]
fn non_string_metadata_keys_rejected_everywhere() {
    let mut m = std::collections::BTreeMap::new();
    m.insert("1".to_owned(), "x".to_owned());
    assert!(matches!(
        render_skill_md("a", "d", "body", Some(&m)),
        Err(RenderError::Invalid(e)) if e == vec![ValidationError::InvalidMetadataKey]
    ));
    let t = "---\nname: a\ndescription: d\nmetadata:\n  true: x\n---\nbody\n";
    assert!(matches!(
        build_bundle(t, None),
        Err(BundleError::Parse(SkillError::Syntax {
            line: 5,
            kind: SyntaxError::NonStringScalar
        }))
    ));
}
