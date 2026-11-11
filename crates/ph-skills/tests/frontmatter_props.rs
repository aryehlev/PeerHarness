//! Property tests: the parser never panics, render/parse round-trips, and hostile
//! frontmatter is rejected.

use std::collections::BTreeMap;

use ph_skills::*;
use proptest::prelude::*;

fn valid_name() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,8}(-[a-z0-9]{1,8}){0,3}"
}

/// Arbitrary text of mixed ASCII, YAML-significant characters, controls and Unicode.
fn wild_text(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            4 => prop::char::range(' ', '~'),
            2 => prop::sample::select(vec![
                ':', '#', '\'', '"', '\\', '&', '*', '!', '|', '>', '{', '[', '-', '?', '%', '@', '`', ' ', '\n', '\t', '\r',
            ]),
            1 => any::<char>(),
        ],
        0..max,
    )
    .prop_map(|v| v.into_iter().collect())
}

fn lines(multi: bool) -> ph_protocol::text::Lines {
    if multi {
        ph_protocol::text::Lines::Multi
    } else {
        ph_protocol::text::Lines::Single
    }
}

fn is_valid_text(s: &str, max: usize, multi: bool) -> bool {
    let n = s.chars().count();
    n >= 1
        && n <= max
        && !s.trim().is_empty()
        && !s
            .chars()
            .any(|c| validate::is_forbidden_field_char(c, lines(multi)))
}

fn replace_forbidden(s: &str, multi: bool) -> String {
    s.chars()
        .map(|c| {
            if validate::is_forbidden_field_char(c, lines(multi)) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn is_valid_meta_value(s: &str) -> bool {
    s.chars().count() <= 1024
        && !s
            .chars()
            .any(|c| validate::is_forbidden_field_char(c, lines(false)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn parser_never_panics_on_arbitrary_input(s in "\\PC*") {
        let _ = parse_skill_md(&s);
        let _ = parse_skill_md(&format!("---\n{s}"));
        let _ = parse_skill_md(&format!("---\n{s}\n---\nbody\n"));
        let _ = scan(&s);
        let _ = sanitize_for_display(&s);
    }

    #[test]
    fn parser_never_panics_on_yamlish_input(lines in prop::collection::vec(wild_text(40), 0..20)) {
        let fm = lines.join("\n");
        let doc = format!("---\n{fm}\n---\nbody\n");
        if let Ok(d) = parse_skill_md(&doc) {
            let _ = validate_skill(&d, None);
        }
        let _ = build_bundle(&doc, None);
        let _ = scan(&doc);
    }

    #[test]
    fn parser_never_panics_on_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = parse_skill_md(s);
        }
        let _ = validate_received(vec![("SKILL.md".into(), bytes)], &ph_core::Digest::sha256(b""), None);
    }

    #[test]
    fn render_parse_roundtrip(
        name in valid_name(),
        description in wild_text(120).prop_map(|s| replace_forbidden(&s, true)),
        body in wild_text(300).prop_map(|s| s.replace('\0', "?")),
        meta in prop::collection::btree_map(
            "[A-Za-z0-9._-]{1,12}".prop_filter("YAML string key", |k| validate::is_valid_metadata_key(k)),
            wild_text(30).prop_map(|s| replace_forbidden(&s, false)),
            0..4,
        ),
    ) {
        prop_assume!(is_valid_text(&description, 1024, true));
        prop_assume!(!normalize_body(&body).trim().is_empty());
        prop_assert!(meta.values().all(|v| is_valid_meta_value(v)));
        let meta: BTreeMap<String, String> = meta;
        let out = render_skill_md(&name, &description, &body, Some(&meta));
        let out = match out {
            Ok(o) => o,
            Err(e) => return Err(TestCaseError::fail(format!("render failed: {e}"))),
        };
        let doc = parse_skill_md(&out).unwrap();
        prop_assert_eq!(&doc.frontmatter.name, &name);
        prop_assert_eq!(&doc.frontmatter.description, &description);
        prop_assert_eq!(&doc.frontmatter.metadata, &meta);
        prop_assert_eq!(&doc.body, &normalize_body(&body));
        prop_assert!(validate_skill(&doc, Some(&name)).is_ok());
        // Deterministic.
        prop_assert_eq!(render_skill_md(&name, &description, &body, Some(&meta)).unwrap(), out.clone());
        // Bundle digest is stable for the same output. A random body can contain the
        // shell-injection syntax that every bundle refuses (architecture 10.10); then
        // that, and only that, is the reason it is refused.
        // The syntax is looked for in the whole file, the frontmatter included.
        let has_trigger = ph_skills::has_shell_injection(&out);
        match build_bundle(&out, Some(&name)) {
            Ok(b) => {
                prop_assert!(!has_trigger);
                prop_assert_eq!(b.digest(), digest_for_skill_md(out.as_bytes()).unwrap());
            }
            Err(
                ph_skills::BundleError::ShellInjection { .. }
                | ph_skills::BundleError::ShellInjectionInFrontmatter,
            ) => prop_assert!(has_trigger),
            Err(e) => return Err(TestCaseError::fail(format!("unexpected refusal: {e}"))),
        }
    }

    #[test]
    fn crlf_and_lf_parse_identically(name in valid_name(), desc in "[a-zA-Z ,.]{1,60}") {
        prop_assume!(!desc.trim().is_empty());
        let desc = desc.trim().to_owned();
        let lf = format!("---\nname: '{name}'\ndescription: \"{desc}\"\n---\n\nbody\n");
        let crlf = lf.replace('\n', "\r\n");
        prop_assert_eq!(parse_skill_md(&lf).unwrap(), parse_skill_md(&crlf).unwrap());
    }
}

fn syntax_kind(fm: &str) -> SyntaxError {
    match parse_skill_md(&format!("---\n{fm}---\nbody\n")) {
        Err(SkillError::Syntax { kind, .. }) => kind,
        other => panic!("expected syntax error for {fm:?}, got {other:?}"),
    }
}

#[test]
fn frontmatter_attacks() {
    let cases: &[(&str, SyntaxError)] = &[
        ("name: &anchor evil\ndescription: x\n", SyntaxError::Anchor),
        ("name: a\ndescription: *anchor\n", SyntaxError::Alias),
        (
            "name: !!python/object:os.system a\ndescription: x\n",
            SyntaxError::Tag,
        ),
        (
            "name: a\ndescription: !<tag:yaml.org,2002:str> x\n",
            SyntaxError::Tag,
        ),
        (
            "name: a\ndescription: {a: 1}\n",
            SyntaxError::FlowCollection,
        ),
        (
            "name: [a, b]\ndescription: x\n",
            SyntaxError::FlowCollection,
        ),
        (
            "name: a\ndescription: x\nname: b\n",
            SyntaxError::DuplicateKey,
        ),
        (
            "name: a\ndescription: x\ndescription: y\n",
            SyntaxError::DuplicateKey,
        ),
        (
            "name: a\ndescription: x\nmetadata:\n  k: 'v'\n  k: w\n",
            SyntaxError::DuplicateKey,
        ),
        (
            "name: a\ndescription: x\n--- !tag\n",
            SyntaxError::DocumentMarker,
        ),
        (
            "name: a\ndescription: x\n----\n",
            SyntaxError::DocumentMarker,
        ),
        (
            "name: a\ndescription: x\n...\n",
            SyntaxError::DocumentMarker,
        ),
        (
            "name: a\ndescription: x\n\tlicense: MIT\n",
            SyntaxError::Tab,
        ),
        (
            "name: a\ndescription: x\nmetadata:\n\tk: v\n",
            SyntaxError::Tab,
        ),
        (
            "name: a\ndescription: x\nhooks: rm -rf /\n",
            SyntaxError::UnknownKey,
        ),
        (
            "name: a\ndescription: x\n<<: *base\n",
            SyntaxError::InvalidKey,
        ),
        (
            "name: a\ndescription: x\n? complex\n",
            SyntaxError::InvalidKey,
        ),
        ("name: a\ndescription: x\n- item\n", SyntaxError::Sequence),
        (
            "name: a\ndescription: x\n%TAG ! tag:x\n",
            SyntaxError::Directive,
        ),
        (
            "name: a\ndescription: \"multi\n  line\"\n",
            SyntaxError::UnterminatedQuote,
        ),
        (
            "name: a\ndescription: plain\n  continuation\n",
            SyntaxError::UnexpectedIndentation,
        ),
        ("name: a\ndescription: yes\n", SyntaxError::NonStringScalar),
        (
            "name: a\ndescription: x\nmetadata:\n  nested:\n    deep: v\n",
            SyntaxError::EmptyValue,
        ),
    ];
    for (fm, want) in cases {
        assert_eq!(syntax_kind(fm), *want, "{fm:?}");
    }
}

#[test]
fn frontmatter_huge_rejected() {
    let big = format!(
        "name: a\ndescription: \"{}\"\n",
        "x".repeat(MAX_FRONTMATTER_BYTES)
    );
    assert_eq!(
        parse_skill_md(&format!("---\n{big}---\nbody\n")),
        Err(SkillError::FrontmatterTooLarge {
            max: MAX_FRONTMATTER_BYTES
        })
    );
    // Billion-laughs style input cannot expand: aliases are rejected outright.
    let laughs = "name: a\ndescription: x\nmetadata:\n  a: &a lol\n  b: *a\n";
    assert_eq!(syntax_kind(laughs), SyntaxError::Anchor);
}

#[test]
fn spec_examples_with_optional_fields() {
    let text = "---\nname: pdf-processing\ndescription: Extract PDF text, fill forms, merge files. Use when handling PDFs.\nlicense: Apache-2.0\ncompatibility: Requires git, docker, jq, and access to the internet\nallowed-tools: Bash(git:*) Bash(jq:*) Read\nmetadata:\n  author: example-org\n  version: \"1.0\"\n---\n\n# PDF\n";
    let d = parse_skill_md(text).unwrap();
    assert_eq!(d.frontmatter.license.as_deref(), Some("Apache-2.0"));
    assert_eq!(
        d.frontmatter.compatibility.as_deref(),
        Some("Requires git, docker, jq, and access to the internet")
    );
    assert_eq!(
        d.frontmatter.allowed_tools.as_deref(),
        Some("Bash(git:*) Bash(jq:*) Read")
    );
    assert_eq!(d.frontmatter.metadata["version"], "1.0");
    validate_skill(&d, Some("pdf-processing")).unwrap();
    let findings = scan(text);
    assert!(findings
        .iter()
        .any(|f| f.rule == "allowed-tools" && f.severity == Severity::Warning && f.line == 6));
    let license = "---\nname: a\ndescription: b\nlicense: Proprietary. LICENSE.txt has complete terms\n---\nx\n";
    assert!(parse_skill_md(license).is_ok());
}
