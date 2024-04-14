use crate::private::{BoundToken, SigningKeyInner};

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
}
