/// <https://cloud.google.com/storage/docs/authentication/signatures?hl=ja#credential-scope>
#[derive(Debug, thiserror::Error)]
#[error("invalid location")]
pub struct Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Location(String);

impl std::convert::TryFrom<&str> for Location {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Self(s.to_string()))
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
