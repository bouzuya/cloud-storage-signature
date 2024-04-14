use crate::private::utils::UnixTimestamp;

#[derive(Debug, thiserror::Error)]
#[error("error")]
pub struct Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActiveDatetime(UnixTimestamp);

impl ActiveDatetime {
    pub(crate) fn from_unix_timestamp_obj(unix_timestamp: UnixTimestamp) -> Self {
        Self(unix_timestamp)
    }
}

impl std::fmt::Display for ActiveDatetime {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.to_iso8601_basic_format_date_time().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> anyhow::Result<()> {
        let unix_timestamp = UnixTimestamp::from_rfc3339("2020-01-02T03:04:05+00:00")?;
        assert_eq!(
            ActiveDatetime::from_unix_timestamp_obj(unix_timestamp).to_string(),
            "20200102T030405Z"
        );
        Ok(())
    }
}
