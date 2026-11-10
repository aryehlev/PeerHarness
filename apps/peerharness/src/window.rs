//! A confirmation window of the operating system (ADR-033).
//!
//! A consent step that was started inside a coding agent's session cannot be answered
//! there: the session's input, its arguments and `--yes` all belong to the agent. When
//! the owner has allowed it (`watch claude --install --windows`), a few such steps are
//! put to the person in a window instead. This module shows that window and reports
//! what was clicked. It knows nothing about consent: [`crate::consent`] decides when a
//! window may be used and what its answer means.
//!
//! What this module guarantees:
//!
//! * the text is shown in full or not at all: a dialog does not scroll, so its height is
//!   estimated ([`rows`]) and compared with the screen before anything is shown;
//! * only an explicit click on "Proceed" is [`Answer::Proceed`]. Cancel, the escape
//!   key, the window closing by itself, a window that could not be shown and any output
//!   this module does not recognize are all something else;
//! * the text reaches the window program on its standard input, never in its arguments
//!   or its environment, and is not logged;
//! * the window program is a fixed absolute path of the operating system, not something
//!   found through `PATH`.
//!
//! macOS only for now (`/usr/bin/osascript`). On other systems [`Window::find`] returns
//! `None` and the step is refused as before.
//!
//! Debug builds also accept `PEERHARNESS_TEST_WINDOW_BIN`, a program that stands in for
//! the window in tests: it gets the exact text on standard input and prints the answer.
//! Release builds do not read that variable, because a variable an agent can set must
//! never be able to answer for the person.

use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Title of every window.
const TITLE: &str = "PeerHarness";

/// Label of the button that confirms. The terminal asks "Proceed? [y/N]".
const PROCEED: &str = "Proceed";

/// Label of the default button.
const CANCEL: &str = "Cancel";

/// Seconds after which an unanswered window closes by itself. Kept below the two
/// minutes after which Claude Code stops a command, so that the agent is told "no
/// answer" instead of having its command killed with the window still on the screen.
pub const GIVE_UP_SECS: u64 = 90;

/// How long this process waits for the window program before stopping it.
const WAIT: Duration = Duration::from_secs(GIVE_UP_SECS + 15);

/// Width of the text in a macOS dialog, in tenths of a point. Measured on macOS 14: a
/// dialog is 420 points wide and its text column a little under 300.
const ROW_WIDTH: u32 = 2800;

/// Height of one row of text in a dialog, in points (measured).
const ROW_HEIGHT: usize = 16;

/// Height of everything in a dialog that is not text, in points (measured: 108), with
/// a margin.
const CHROME_HEIGHT: usize = 128;

/// Most rows a window may need on any screen. The script also compares the height with
/// the screen it runs on, which is usually the lower limit.
pub const MAX_ROWS: usize = 48;

/// Most characters a window may show.
pub const MAX_CHARS: usize = 2400;

/// Environment variable naming the stand-in window program (debug builds only).
#[cfg(debug_assertions)]
pub const TEST_WINDOW_ENV: &str = "PEERHARNESS_TEST_WINDOW_BIN";

/// What came back from a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The person clicked "Proceed".
    Proceed,
    /// The person clicked "Cancel", pressed escape or closed the window.
    Declined,
    /// Nobody answered before the window closed by itself.
    TimedOut,
    /// The text would not fit on this screen, so no window was shown.
    TooTall,
    /// The window could not be shown, or its program did something unexpected.
    Failed,
}

/// Something that can put a text in front of the person and report their answer.
pub trait Ask {
    fn ask(&self, text: &str) -> Answer;
}

/// Whether `text` is short enough to be shown in a window in full on a large screen.
/// The window itself still declines a text that is too tall for the screen it is on
/// ([`Answer::TooTall`]).
pub fn fits(text: &str) -> bool {
    text.chars().count() <= MAX_CHARS && rows(text) <= MAX_ROWS
}

/// Rows `text` needs in a dialog, estimated on the tall side.
///
/// Every line is wrapped the way the dialog wraps it: words are placed on a row until
/// the next one does not fit, and a word wider than a row is broken. The widths
/// ([`glyph`]) are approximations of the system font at its dialog size, taken on the
/// wide side, and the row is taken a little narrower than it is. Laying out wider
/// glyphs in a narrower row never gives fewer rows. The tests hold the result against
/// dialogs that were measured; the widths are not the font's own metrics.
pub fn rows(text: &str) -> usize {
    text.split('\n').map(line_rows).sum()
}

fn line_rows(line: &str) -> usize {
    let space = glyph(' ');
    let mut rows = 1;
    let mut used = 0;
    for word in line.split(' ') {
        let width: u32 = word.chars().map(glyph).sum();
        let gap = if used == 0 { 0 } else { space };
        if used + gap + width <= ROW_WIDTH {
            used += gap + width;
        } else if width <= ROW_WIDTH {
            rows += 1;
            used = width;
        } else {
            // A word wider than a row starts on a row of its own and is broken.
            if used > 0 {
                rows += 1;
            }
            used = 0;
            for c in word.chars() {
                let g = glyph(c);
                if used + g > ROW_WIDTH {
                    rows += 1;
                    used = g;
                } else {
                    used += g;
                }
            }
        }
    }
    rows
}

/// The approximate width of one character in a dialog, in tenths of a point, on the
/// wide side.
fn glyph(c: char) -> u32 {
    match c {
        ' ' => 40,
        '\t' => 320,
        'i' | 'l' | 'j' | 't' | 'f' | 'r' | 'I' | '.' | ',' | ':' | ';' | '\'' | '!' | '|'
        | '(' | ')' | '[' | ']' | '{' | '}' | '/' | '`' | '"' => 55,
        'm' | 'w' => 120,
        'M' | 'W' => 130,
        'a'..='z' | '-' | '_' => 80,
        '0'..='9' => 85,
        'A'..='Z' => 105,
        c if c.is_ascii() => 125,
        // Accented Latin, Greek, Cyrillic and the like.
        c if c < '\u{1100}' => 130,
        // The wide scripts and emoji.
        _ => 180,
    }
}

/// The window this machine can show.
#[derive(Debug)]
#[cfg_attr(
    not(any(target_os = "macos", debug_assertions)),
    allow(dead_code) // never built where there is no window program
)]
pub struct Window {
    program: PathBuf,
    /// Whether the program is `osascript` and takes a script, or the tests' stand-in,
    /// which takes the text itself.
    script: bool,
}

/// Where macOS keeps `osascript`. The directory is protected by the system, so the
/// program cannot be replaced by a process running as the user.
#[cfg(target_os = "macos")]
const OSASCRIPT: &str = "/usr/bin/osascript";

impl Window {
    /// The window of this machine, or `None` when it has none this build can use.
    pub fn find() -> Option<Self> {
        #[cfg(debug_assertions)]
        if let Some(p) = std::env::var_os(TEST_WINDOW_ENV).filter(|p| !p.is_empty()) {
            return Some(Self {
                program: PathBuf::from(p),
                script: false,
            });
        }
        #[cfg(target_os = "macos")]
        if std::path::Path::new(OSASCRIPT).is_file() {
            return Some(Self {
                program: PathBuf::from(OSASCRIPT),
                script: true,
            });
        }
        None
    }
}

impl Ask for Window {
    fn ask(&self, text: &str) -> Answer {
        let mut command = Command::new(&self.program);
        let input = if self.script {
            // `-` reads the script from standard input.
            command.arg("-");
            applescript(text, rows(text))
        } else {
            text.to_owned()
        };
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return Answer::Failed;
        };
        // The text is small (see MAX_CHARS), so this write cannot fill the pipe.
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(input.as_bytes()).is_ok());
        if !wrote {
            stop(&mut child);
            return Answer::Failed;
        }
        let Some(success) = wait(&mut child) else {
            stop(&mut child);
            return Answer::TimedOut;
        };
        let mut said = String::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = stdout.take(64).read_to_string(&mut said);
        }
        parse(success, &said)
    }
}

/// What the window program's exit and output mean. Only the exact word for "Proceed"
/// from a program that exited cleanly is a confirmation.
fn parse(success: bool, said: &str) -> Answer {
    match (success, said.trim()) {
        (true, "proceed") => Answer::Proceed,
        (true, "declined") => Answer::Declined,
        (true, "gave-up") => Answer::TimedOut,
        (true, "too-tall") => Answer::TooTall,
        _ => Answer::Failed,
    }
}

/// Waits for the child until [`WAIT`] has passed. `None` when it did not finish.
fn wait(child: &mut Child) -> Option<bool> {
    let deadline = Instant::now() + WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.success()),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => return None,
        }
    }
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// The AppleScript that shows `text` and prints one word for the answer.
///
/// Before showing anything it compares the height the text needs (`rows` rows) with the
/// usable height of the smallest screen attached, and prints `too-tall` when the dialog
/// would not fit: a dialog taller than its screen is cut off, and the person would
/// confirm a text they saw part of.
///
/// "Cancel" is the default button and the cancel button, so the return key and the
/// escape key both decline (AppleScript reports that as error -128). The script prints
/// `proceed` only for a click on "Proceed". Any other error, such as a session without
/// a screen, prints `failed`.
fn applescript(text: &str, rows: usize) -> String {
    format!(
        "use framework \"AppKit\"\n\
         use scripting additions\n\
         try\n\
         \tset least to 100000\n\
         \trepeat with s in (current application's NSScreen's screens() as list)\n\
         \t\tset f to s's visibleFrame()\n\
         \t\ttry\n\
         \t\t\tset h to (item 2 of item 2 of f) as real\n\
         \t\ton error\n\
         \t\t\tset h to (height of |size| of f) as real\n\
         \t\tend try\n\
         \t\tif h < least then set least to h\n\
         \tend repeat\n\
         \tif {needed} > least then return \"too-tall\"\n\
         \tactivate\n\
         \tset r to display dialog {text} with title {title} \
         buttons {{{cancel}, {proceed}}} default button {cancel} cancel button {cancel} \
         with icon caution giving up after {GIVE_UP_SECS}\n\
         on error number n\n\
         \tif n is -128 then return \"declined\"\n\
         \treturn \"failed\"\n\
         end try\n\
         if gave up of r then return \"gave-up\"\n\
         if button returned of r is {proceed} then return \"proceed\"\n\
         return \"declined\"\n",
        needed = rows * ROW_HEIGHT + CHROME_HEIGHT,
        text = applescript_literal(text),
        title = applescript_literal(TITLE),
        cancel = applescript_literal(CANCEL),
        proceed = applescript_literal(PROCEED),
    )
}

/// `s` as an AppleScript string literal. Backslash and the double quote are the only
/// characters with a meaning inside one; line breaks and tabs are written as escapes so
/// the literal stays on one line, and other control characters are left out.
pub(crate) fn applescript_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_explicit_proceed_is_a_confirmation() {
        assert_eq!(parse(true, "proceed\n"), Answer::Proceed);
        assert_eq!(parse(true, "gave-up\n"), Answer::TimedOut);
        assert_eq!(parse(true, "declined\n"), Answer::Declined);
        // A program that failed never confirms, whatever it printed.
        assert_eq!(parse(false, "proceed\n"), Answer::Failed);
        assert_eq!(parse(false, ""), Answer::Failed);
        // Nor does output this module does not know.
        for said in [
            "",
            "Proceed",
            "proceed now",
            "yes",
            "y",
            "button returned:Proceed",
        ] {
            assert_eq!(parse(true, said), Answer::Failed, "{said:?}");
        }
    }

    #[test]
    fn a_text_is_shown_in_full_or_not_at_all() {
        assert!(fits("a short question"));
        assert!(fits(&"line\n".repeat(MAX_ROWS - 1)));
        assert!(!fits(&"line\n".repeat(MAX_ROWS)));
        assert!(!fits(&"x ".repeat(MAX_CHARS)));
        // An empty line still takes a row.
        assert_eq!(rows("a\n\nb"), 3);
        assert_eq!(rows(""), 1);
    }

    /// The estimate against dialogs measured on macOS 14 (420 points wide, 16 points a
    /// row): it is never below what the dialog needed, and not far above.
    #[test]
    fn the_estimate_is_never_below_a_measured_dialog() {
        let prose = "Measuring this window, it closes by itself. "
            .repeat(10)
            .trim_end()
            .to_owned();
        let wide = "M".repeat(220);
        let hyphens = "name: run-tests-before-say-task-done "
            .repeat(6)
            .trim_end()
            .to_owned();
        // The window of `proposal create` for a short rule, as the binary showed it.
        let preview = "Your coding agent started this step. Nothing happens unless you \
            choose Proceed.\n\nThis shares the following with the members of team (scope *) \
            and puts it to the vote.\nExactly this text leaves your machine, and nothing \
            else:\n\ntitle: Run the tests before you say a task is done.\n\n---\nname: \
            run-tests-before-say-task-done\ndescription: Run the tests before you say a task \
            is done.\n---\n\n# Rule\n\nRun the tests before you say a task is done.\n\nIf \
            this conflicts with what the user asks for in the current session, follow the \
            user and say that it conflicts with this rule.\n\nIt passes with 1 of 1 member \
            approval(s). Creating it is not a vote:\ncast yours with `peerharness proposal \
            vote`."
            .to_owned();
        assert_eq!(rows(&preview), 33);
        assert!(fits(&preview));
        for (text, measured) in [(prose, 10), (wide, 9), (hyphens, 6), (preview, 27)] {
            let estimate = rows(&text);
            assert!(
                (measured..=measured + 6).contains(&estimate),
                "{estimate} rows estimated, {measured} measured"
            );
        }
        // Words are never squeezed: a row holds fewer wide letters than narrow ones.
        assert!(rows(&"W".repeat(60)) > rows(&"i".repeat(60)));
        assert_eq!(rows(&"語".repeat(15)), 1);
        assert_eq!(rows(&"語".repeat(16)), 2);
        // A word that does not fit goes to the next row whole.
        assert_eq!(rows(&format!("{} {}", "a".repeat(30), "b".repeat(30))), 2);
    }

    #[test]
    fn the_script_checks_the_screen_before_it_shows_anything() {
        let script = applescript("hello", 10);
        // 10 rows of 16 points and the rest of the dialog.
        assert!(script.contains("if 288 > least then return \"too-tall\""));
        let check = script.find("too-tall").unwrap();
        let shown = script.find("display dialog").unwrap();
        assert!(check < shown);
        assert_eq!(parse(true, "too-tall\n"), Answer::TooTall);
    }

    #[test]
    fn literals_escape_what_applescript_reads() {
        assert_eq!(applescript_literal("plain"), "\"plain\"");
        assert_eq!(applescript_literal("a\"b"), "\"a\\\"b\"");
        assert_eq!(applescript_literal("a\\b"), "\"a\\\\b\"");
        assert_eq!(applescript_literal("a\nb\tc"), "\"a\\nb\\tc\"");
        assert_eq!(applescript_literal("a\r\u{7}b"), "\"ab\"");
        // A text cannot close the literal and add script of its own.
        let hostile = "\" buttons {\"Proceed\"} --";
        let lit = applescript_literal(hostile);
        assert!(lit.starts_with('"') && lit.ends_with('"'));
        assert!(!lit[1..lit.len() - 1].replace("\\\"", "").contains('"'));
        let script = applescript("hello", 1);
        assert!(script.contains("default button \"Cancel\" cancel button \"Cancel\""));
        assert!(script.contains("giving up after 90"));
    }

    /// The literal means the same text to the real `osascript`. The script only returns
    /// the string, so no window is shown.
    #[cfg(target_os = "macos")]
    #[test]
    fn osascript_reads_the_literal_back_exactly() {
        let texts = [
            "plain",
            "quotes \" and \\ backslashes \\\" together",
            "two\nlines\tand a tab",
            "accents é, a check ✓, wide 語, an emoji 🙂",
            "\" & return & \"injected",
            "trailing backslash \\",
        ];
        for text in texts {
            let script = format!("return {}\n", applescript_literal(text));
            let mut child = Command::new(OSASCRIPT)
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "{text:?}");
            // osascript ends its output with one line break.
            let mut expected = text.to_owned();
            expected.push('\n');
            assert_eq!(String::from_utf8(out.stdout).unwrap(), expected, "{text:?}");
        }
    }
}
