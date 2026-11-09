//! [`Timestamp`]: RFC 3339 UTC timestamps with whole seconds and a `Z` suffix.
//!
//! The only accepted textual form is exactly `YYYY-MM-DDTHH:MM:SSZ` (20 ASCII bytes).
//! Lowercase `t`/`z`, numeric offsets (`+00:00`), fractional seconds, leap seconds
//! (`:60`) and surrounding whitespace are all rejected, so every timestamp has exactly
//! one encoding. The representable range is `0000-01-01T00:00:00Z` through
//! `9999-12-31T23:59:59Z`.

use std::fmt;
use std::str::FromStr;

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use crate::encoding::string_serde;
use crate::error::ParseError;

/// Seconds in one day.
pub const SECS_PER_DAY: i64 = 86_400;

/// A point in time with one-second resolution, always UTC.
///
/// Internally the number of seconds since the Unix epoch. `Ord` is chronological.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(i64);

const WHAT: &str = "timestamp";

impl Timestamp {
    /// Earliest representable timestamp, `0000-01-01T00:00:00Z`.
    pub const MIN: Timestamp = Timestamp(-62_167_219_200);
    /// Latest representable timestamp, `9999-12-31T23:59:59Z`.
    pub const MAX: Timestamp = Timestamp(253_402_300_799);

    /// The current system time, truncated to whole seconds.
    pub fn now() -> Self {
        Self::clamp(OffsetDateTime::now_utc().unix_timestamp())
    }

    /// Builds a timestamp from Unix seconds; fails outside [`Self::MIN`]..=[`Self::MAX`].
    pub fn from_unix_seconds(secs: i64) -> Result<Self, ParseError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&secs) {
            Ok(Self(secs))
        } else {
            Err(ParseError::new(WHAT, "out of range"))
        }
    }

    /// Seconds since the Unix epoch.
    pub const fn unix_seconds(&self) -> i64 {
        self.0
    }

    fn clamp(secs: i64) -> Self {
        Self(secs.clamp(Self::MIN.0, Self::MAX.0))
    }

    /// Adds `secs` (may be negative), returning `None` if the result is out of range.
    pub fn checked_add_secs(self, secs: i64) -> Option<Self> {
        self.0
            .checked_add(secs)
            .and_then(|s| Self::from_unix_seconds(s).ok())
    }

    /// Adds `secs` (may be negative), saturating at [`Self::MIN`] / [`Self::MAX`].
    pub fn plus_secs(self, secs: i64) -> Self {
        Self::clamp(self.0.saturating_add(secs))
    }

    /// Subtracts `secs`, saturating at [`Self::MIN`] / [`Self::MAX`].
    pub fn minus_secs(self, secs: i64) -> Self {
        Self::clamp(self.0.saturating_sub(secs))
    }

    /// Adds whole days, saturating at the range bounds.
    pub fn plus_days(self, days: i64) -> Self {
        self.plus_secs(days.saturating_mul(SECS_PER_DAY))
    }

    /// `self - earlier` in seconds (negative if `earlier` is later).
    pub fn secs_since(self, earlier: Timestamp) -> i64 {
        // Both values are within +-2^38, so this cannot overflow.
        self.0 - earlier.0
    }

    /// Converts to a `time::OffsetDateTime` in UTC.
    pub fn to_offset_date_time(self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    /// Converts from a `time::OffsetDateTime`, truncating sub-second precision.
    pub fn from_offset_date_time(t: OffsetDateTime) -> Result<Self, ParseError> {
        Self::from_unix_seconds(t.unix_timestamp())
    }
}

fn digits(b: &[u8]) -> Option<u32> {
    let mut v: u32 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    Some(v)
}

impl FromStr for Timestamp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let b = s.as_bytes();
        let bad = || ParseError::new(WHAT, "expected YYYY-MM-DDTHH:MM:SSZ");
        if b.len() != 20 {
            return Err(bad());
        }
        let sep_ok = b.get(4) == Some(&b'-')
            && b.get(7) == Some(&b'-')
            && b.get(10) == Some(&b'T')
            && b.get(13) == Some(&b':')
            && b.get(16) == Some(&b':')
            && b.get(19) == Some(&b'Z');
        if !sep_ok {
            return Err(bad());
        }
        let field = |r: std::ops::Range<usize>| b.get(r).and_then(digits).ok_or_else(bad);
        let year = field(0..4)?;
        let month = field(5..7)?;
        let day = field(8..10)?;
        let hour = field(11..13)?;
        let minute = field(14..16)?;
        let second = field(17..19)?;

        let invalid = || ParseError::new(WHAT, "invalid calendar date or time");
        let month = u8::try_from(month)
            .ok()
            .and_then(|m| Month::try_from(m).ok())
            .ok_or_else(invalid)?;
        let year = i32::try_from(year).map_err(|_| invalid())?;
        let day = u8::try_from(day).map_err(|_| invalid())?;
        let date = Date::from_calendar_date(year, month, day).map_err(|_| invalid())?;
        let to_u8 = |v: u32| u8::try_from(v).map_err(|_| invalid());
        let time =
            Time::from_hms(to_u8(hour)?, to_u8(minute)?, to_u8(second)?).map_err(|_| invalid())?;
        let secs = PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp();
        Self::from_unix_seconds(secs)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.to_offset_date_time();
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        )
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({self})")
    }
}

string_serde!(
    Timestamp,
    "an RFC 3339 UTC timestamp like 2026-11-09T18:10:00Z"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let t: Timestamp = "2026-11-09T18:10:00Z".parse().unwrap();
        assert_eq!(t.to_string(), "2026-11-09T18:10:00Z");
        assert_eq!(t.unix_seconds(), 1_794_247_800);
        assert_eq!(
            "1970-01-01T00:00:00Z".parse::<Timestamp>().unwrap(),
            Timestamp::from_unix_seconds(0).unwrap()
        );
        assert_eq!(
            Timestamp::MIN.to_string(),
            "0000-01-01T00:00:00Z".to_string()
        );
        assert_eq!(Timestamp::MAX.to_string(), "9999-12-31T23:59:59Z");
        assert_eq!(
            "2024-02-29T23:59:59Z"
                .parse::<Timestamp>()
                .unwrap()
                .to_string(),
            "2024-02-29T23:59:59Z"
        );
    }

    #[test]
    fn rejects_other_formats() {
        for bad in [
            "2026-11-09T18:10:00+00:00",
            "2026-11-09T18:10:00.000Z",
            "2026-11-09t18:10:00Z",
            "2026-11-09T18:10:00z",
            "2026-11-09 18:10:00Z",
            "2026-11-09T18:10Z",
            " 2026-11-09T18:10:00Z",
            "2026-11-09T18:10:00Z ",
            "2026-13-09T18:10:00Z",
            "2026-02-30T18:10:00Z",
            "2025-02-29T00:00:00Z",
            "2026-11-09T24:00:00Z",
            "2026-11-09T23:60:00Z",
            "2026-11-09T23:59:60Z",
            "+026-11-09T18:10:00Z",
            "2026-1a-09T18:10:00Z",
            "",
            "２０２６-11-09T18:10:00Z",
        ] {
            assert!(bad.parse::<Timestamp>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn arithmetic() {
        let t: Timestamp = "2026-11-09T18:10:00Z".parse().unwrap();
        assert_eq!(t.plus_days(1).to_string(), "2026-11-10T18:10:00Z");
        assert_eq!(t.plus_secs(300).to_string(), "2026-11-09T18:15:00Z");
        assert_eq!(t.minus_secs(600).to_string(), "2026-11-09T18:00:00Z");
        assert_eq!(t.plus_days(30).secs_since(t), 30 * SECS_PER_DAY);
        assert_eq!(Timestamp::MAX.plus_secs(1), Timestamp::MAX);
        assert_eq!(Timestamp::MAX.checked_add_secs(1), None);
        assert_eq!(Timestamp::MIN.plus_secs(i64::MIN), Timestamp::MIN);
        assert!(Timestamp::from_unix_seconds(i64::MAX).is_err());
        assert!(t < t.plus_secs(1));
    }

    #[test]
    fn serde_roundtrip() {
        let t: Timestamp = "2026-11-09T18:10:00Z".parse().unwrap();
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(j, "\"2026-11-09T18:10:00Z\"");
        assert_eq!(serde_json::from_str::<Timestamp>(&j).unwrap(), t);
        assert!(serde_json::from_str::<Timestamp>("\"2026-11-09T18:10:00+01:00\"").is_err());
        assert!(serde_json::from_str::<Timestamp>("1794247800").is_err());
    }

    #[test]
    fn more_rejections() {
        for bad in [
            "2026-11-09T18:10:00+0000",
            "2026-11-09T18:10:00.5Z",
            "2026-11-09T18:10:00,5Z",
            "2026-11-09T18:10:00ZZ",
            "2026-11-09T18:10:00Z\n",
            "2026-11-09T18:10:00\u{0}",
            "2026-11-0918:10:00Z ",
            "20261109T181000Z",
            "-2026-11-09T18:10:00Z",
            "2026-00-09T18:10:00Z",
            "2026-11-00T18:10:00Z",
            "2026-11-31T18:10:00Z",
            "1900-02-29T00:00:00Z",
        ] {
            assert!(bad.parse::<Timestamp>().is_err(), "accepted {bad:?}");
        }
        assert!("2000-02-29T00:00:00Z".parse::<Timestamp>().is_ok());
        let e = "2026-11-09T18:10:00SECRET"
            .parse::<Timestamp>()
            .unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }

    proptest::proptest! {
        #[test]
        fn display_parse_roundtrip(secs in Timestamp::MIN.0..=Timestamp::MAX.0) {
            let t = Timestamp::from_unix_seconds(secs).unwrap();
            let s = t.to_string();
            proptest::prop_assert_eq!(s.len(), 20);
            proptest::prop_assert_eq!(s.parse::<Timestamp>().unwrap(), t);
        }

        #[test]
        fn parse_never_panics(s in "\\PC{0,24}") {
            let _ = s.parse::<Timestamp>();
        }
    }

    #[test]
    fn now_is_reasonable() {
        let n = Timestamp::now();
        assert!(n > "2020-01-01T00:00:00Z".parse().unwrap());
    }
}
