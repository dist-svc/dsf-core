use std::fmt;
use std::time::SystemTime;

use chrono::{TimeZone, Utc};

/// New DateTime type because rust doesn't have second or millisecond sized versions
#[derive(PartialEq, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DateTime(u64);

impl DateTime {
    pub fn now() -> Self {
        SystemTime::now().into()
    }

    pub fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    pub fn as_secs(&self) -> u64 {
        let u = Utc.timestamp(self.0 as i64, 0);
        u.timestamp() as u64
    }
}

impl fmt::Debug for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let u = Utc.timestamp(self.0 as i64, 0);
        write!(f, "{}", u.to_string())
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let u = Utc.timestamp(self.0 as i64, 0);
        write!(f, "{}", u.to_string())
    }
}

impl Into<SystemTime> for DateTime {
    fn into(self) -> SystemTime {
        let u = Utc.timestamp(self.0 as i64, 0);
        u.into()
    }
}

impl From<SystemTime> for DateTime {
    fn from(s: SystemTime) -> Self {
        let when = s.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        Self(when.as_secs())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn date_time_system_conversions() {
        let d = DateTime::now();

        let s: SystemTime = d.clone().into();

        let d2: DateTime = s.clone().into();

        assert_eq!(d, d2);
    }

    #[test]
    fn date_time_second_conversions() {
        let d = DateTime(1553238684);

        assert_eq!(1553238684, d.as_secs());

        let d1 = DateTime::from_secs(1553238684);

        assert_eq!(d, d1);
    }
}
