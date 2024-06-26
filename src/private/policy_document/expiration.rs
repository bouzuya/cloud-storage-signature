use std::str::FromStr;

use crate::private::utils::UnixTimestamp;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("out of range")]
    OutOfRange(i64),
    #[error("rfc3339 format : {0}")]
    Rfc3339Format(String),
}

// <del>YYYYMMDD'T'HHMMSS'Z'</del>
// The document is wrong. The document says it is in the format of YYYYMMDD'T'HHMMSS'Z', but it is actually in RFC3339 format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Expiration(UnixTimestamp);

impl Expiration {
    pub(crate) fn from_unix_timestamp_obj(unix_timestamp: UnixTimestamp) -> Self {
        Self(unix_timestamp)
    }
}

impl std::fmt::Display for Expiration {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.to_rfc3339().fmt(f)
    }
}

impl std::str::FromStr for Expiration {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use crate::private::utils::unix_timestamp::Error as E;
        let unix_timestamp = UnixTimestamp::from_rfc3339(s).map_err(|e| match e {
            E::InvalidIso8601Format(_) => unreachable!(),
            E::InvalidRfc3339Format(s) => Error::Rfc3339Format(s),
            E::OutOfRange(n) => Error::OutOfRange(n),
        })?;
        Ok(Expiration(unix_timestamp))
    }
}

impl<'de> serde::Deserialize<'de> for Expiration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Expiration;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string in the format of YYYY-MM-DD'T'HH:MM:SS'Z'")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Self::Value::from_str(value).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl serde::Serialize for Expiration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> anyhow::Result<()> {
        fn assert_impls<
            T: Clone
                + Copy
                + std::fmt::Debug
                + Eq
                + PartialEq
                + std::str::FromStr
                + serde::Deserialize<'static>
                + serde::Serialize,
        >() {
        }
        assert_impls::<Expiration>();

        let s = "2020-06-16T11:11:11Z";
        let expiration = Expiration::from_str(s)?;
        assert_eq!(expiration.to_string(), s);
        assert_eq!(
            serde_json::from_str::<Expiration>(&format!("\"{}\"", s))?,
            expiration
        );
        assert_eq!(serde_json::to_string(&expiration)?, format!("\"{}\"", s));
        Ok(())
    }
}
