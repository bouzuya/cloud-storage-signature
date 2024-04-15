use crate::private::{BoundToken, SigningKeyInner};

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] ErrorKind);

#[allow(clippy::enum_variant_names)]
#[derive(Debug, thiserror::Error)]
enum ErrorKind {
    #[error("service account file open error: {0}")]
    ServiceAccountFileOpen(#[source] std::io::Error),
    #[error("service account file open error: {0}")]
    ServiceAccountFileRead(#[source] std::io::Error),
    #[error("service account json client_email is not found")]
    ServiceAccountJsonClientEmailIsNotFound,
    #[error("service account json client_email is not string")]
    ServiceAccountJsonClientEmailIsNotString,
    #[error("service account json deserialize error")]
    ServiceAccountJsonDeserialize(#[source] serde_json::Error),
    #[error("service account json private_key is not found")]
    ServiceAccountJsonPrivateKeyIsNotFound,
    #[error("service account json private_key is not string")]
    ServiceAccountJsonPrivateKeyIsNotString,
    #[error("service account json root is not object")]
    ServiceAccountJsonRootIsNotObject,
}

#[derive(Clone)]
pub struct SigningKey(pub(crate) SigningKeyInner);

impl SigningKey {
    pub fn bound_token() -> Self {
        Self(SigningKeyInner::BoundToken(BoundToken::new()))
    }

    pub fn hmac(access_id: String, secret: String) -> Self {
        Self(SigningKeyInner::Hmac { access_id, secret })
    }

    pub fn service_account(client_email: String, private_key: String) -> Self {
        Self(SigningKeyInner::ServiceAccount {
            client_email,
            private_key,
        })
    }

    pub fn service_account_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let mut file = std::fs::File::open(path).map_err(ErrorKind::ServiceAccountFileOpen)?;
        let mut s = String::new();
        std::io::Read::read_to_string(&mut file, &mut s)
            .map_err(ErrorKind::ServiceAccountFileRead)?;
        Self::service_account_from_str(s)
    }

    pub fn service_account_from_str<S: AsRef<str>>(s: S) -> Result<Self, Error> {
        let json_value: serde_json::Value =
            serde_json::from_str(s.as_ref()).map_err(ErrorKind::ServiceAccountJsonDeserialize)?;
        let json_object = json_value
            .as_object()
            .ok_or_else(|| ErrorKind::ServiceAccountJsonRootIsNotObject)?;
        let client_email = json_object
            .get("client_email")
            .ok_or_else(|| ErrorKind::ServiceAccountJsonClientEmailIsNotFound)?
            .as_str()
            .ok_or_else(|| ErrorKind::ServiceAccountJsonClientEmailIsNotString)?
            .to_string();
        let private_key = json_object
            .get("private_key")
            .ok_or_else(|| ErrorKind::ServiceAccountJsonPrivateKeyIsNotFound)?
            .as_str()
            .ok_or_else(|| ErrorKind::ServiceAccountJsonPrivateKeyIsNotString)?
            .to_string();
        Ok(Self::service_account(client_email, private_key))
    }
}
