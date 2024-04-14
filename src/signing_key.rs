use crate::private::{BoundToken, SigningAlgorithm};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("bound token authorizer error: {0}")]
    BoundTokenAuthorizer(#[source] crate::private::bound_token::BoundTokenError),
    #[error("bound token signing error: {0}")]
    BoundTokenSigning(#[source] crate::private::bound_token::BoundTokenError),
    #[error("service account private key pem parsing error: {0}")]
    ServiceAccountPrivateKeyPemParsing(#[source] pem::PemError),
    #[error("service account private key pkcs8 parsing error: {0}")]
    ServiceAccountPrivateKeyPkcs8Parsing(ring::error::KeyRejected),
    #[error("service account signing error: {0}")]
    ServiceAccountSigning(ring::error::Unspecified),
}

#[derive(Clone)]
pub struct SigningKey(KeyInner);

impl SigningKey {
    pub fn bound_token() -> Self {
        Self(KeyInner::BoundToken(BoundToken::new()))
    }

    pub fn hmac(access_id: String, secret: String) -> Self {
        Self(KeyInner::Hmac { access_id, secret })
    }

    pub fn service_account(client_email: String, private_key: String) -> Self {
        Self(KeyInner::ServiceAccount {
            client_email,
            private_key,
        })
    }

    pub(crate) async fn authorizer(&self) -> Result<String, Error> {
        Ok(match &self.0 {
            KeyInner::BoundToken(bound_token) => {
                bound_token
                    .get_email_and_token()
                    .await
                    .map_err(Error::BoundTokenAuthorizer)?
                    .0
            }
            KeyInner::Hmac { access_id, .. } => access_id.to_string(),
            KeyInner::ServiceAccount { client_email, .. } => client_email.to_string(),
        })
    }

    pub(crate) async fn sign(&self, use_sign_blob: bool, message: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.0 {
            KeyInner::BoundToken(bound_token) => {
                if use_sign_blob {
                    Ok(bound_token
                        .sign(message)
                        .await
                        .map_err(Error::BoundTokenSigning)?)
                } else {
                    todo!()
                }
            }
            KeyInner::Hmac { .. } => todo!(),
            KeyInner::ServiceAccount { private_key, .. } => {
                if use_sign_blob {
                    todo!()
                } else {
                    let pkcs8 = pem::parse(private_key.as_bytes())
                        .map_err(Error::ServiceAccountPrivateKeyPemParsing)?;
                    let signing_key = pkcs8.contents();
                    let key_pair = ring::signature::RsaKeyPair::from_pkcs8(signing_key)
                        .map_err(Error::ServiceAccountPrivateKeyPkcs8Parsing)?;
                    let mut signature = vec![0; key_pair.public().modulus_len()];
                    key_pair
                        .sign(
                            &ring::signature::RSA_PKCS1_SHA256,
                            &ring::rand::SystemRandom::new(),
                            message,
                            &mut signature,
                        )
                        .map_err(Error::ServiceAccountSigning)?;
                    Ok(signature)
                }
            }
        }
    }

    pub(crate) fn x_goog_algorithm(&self) -> SigningAlgorithm {
        match self.0 {
            KeyInner::BoundToken(_) | KeyInner::ServiceAccount { .. } => {
                SigningAlgorithm::Goog4RsaSha256
            }
            KeyInner::Hmac { .. } => SigningAlgorithm::Goog4HmacSha256,
        }
    }
}

#[derive(Clone)]
enum KeyInner {
    BoundToken(BoundToken),
    Hmac {
        access_id: String,
        // TODO: unused
        #[allow(unused)]
        secret: String,
    },
    ServiceAccount {
        client_email: String,
        private_key: String,
    },
}
