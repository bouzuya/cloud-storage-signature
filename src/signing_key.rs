use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use crate::html_form_data::Error;

#[derive(Clone)]
pub struct SigningKey(KeyInner);

impl SigningKey {
    pub fn bound_token() -> Self {
        Self(KeyInner::BoundToken(BoundedToken::new()))
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

    pub(crate) async fn authorizer(&self) -> Result<String, crate::html_form_data::Error> {
        Ok(match &self.0 {
            KeyInner::BoundToken(bounded_token) => bounded_token.get_email_and_token().await?.0,
            KeyInner::Hmac { access_id, .. } => access_id.to_string(),
            KeyInner::ServiceAccount { client_email, .. } => client_email.to_string(),
        })
    }

    pub(crate) async fn sign(
        &self,
        use_sign_blob: bool,
        message: &[u8],
    ) -> Result<Vec<u8>, crate::html_form_data::Error> {
        match &self.0 {
            KeyInner::BoundToken(bounded_token) => {
                if use_sign_blob {
                    Ok(bounded_token.sign(message).await?)
                } else {
                    todo!()
                }
            }
            KeyInner::Hmac { .. } => todo!(),
            KeyInner::ServiceAccount { private_key, .. } => {
                if use_sign_blob {
                    todo!()
                } else {
                    let pkcs8 = pem::parse(private_key.as_bytes()).map_err(|_| {
                        crate::html_form_data::ErrorKind::ServiceAccountPrivateKeyParsing
                    })?;
                    let signing_key = pkcs8.contents();
                    let message_digest = crate::private::sign(
                        crate::private::SigningAlgorithm::Goog4RsaSha256,
                        signing_key,
                        message,
                    )
                    .map_err(crate::html_form_data::ErrorKind::Sign)?;
                    Ok(message_digest)
                }
            }
        }
    }

    pub(crate) fn x_goog_algorithm(&self) -> &'static str {
        match self.0 {
            KeyInner::BoundToken(_) | KeyInner::ServiceAccount { .. } => "GOOG4-RSA-SHA256",
            KeyInner::Hmac { .. } => "GOOG4-HMAC-SHA256",
        }
    }
}

#[derive(Clone)]
enum KeyInner {
    BoundToken(BoundedToken),
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

#[derive(Clone, Debug, serde::Deserialize)]
struct AccessToken {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Clone)]
pub struct BoundedToken {
    cache: Arc<tokio::sync::Mutex<Option<(String, String, SystemTime)>>>,
    client: reqwest::Client,
}

impl BoundedToken {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(tokio::sync::Mutex::new(None)),
            client: reqwest::Client::new(),
        }
    }

    async fn get_email_and_token(&self) -> Result<(String, String), Error> {
        let mut cache = self.cache.lock().await;
        Ok(match cache.clone() {
            Some((email, access_token, expires))
                if expires
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("expires to be after unix_epoch")
                    > SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("SystemTime::now() to be after unix_epoch")
                        + Duration::from_secs(30) =>
            {
                (email, access_token)
            }
            Some(_) | None => {
                // FIXME: handle error
                // email
                // <https://cloud.google.com/compute/docs/metadata/predefined-metadata-keys>
                let url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email";
                let request = self
                    .client
                    .request(reqwest::Method::GET, url)
                    .header("Metadata-Flavor", "Google")
                    .build()
                    .unwrap();
                let response = self.client.execute(request).await.unwrap();
                println!("status: {:?}", response.status());
                if !response.status().is_success() {
                    let response_body = response.text().await.unwrap();
                    println!("response_body: {:?}", response_body);
                    todo!()
                }
                let response_body = response.text().await.unwrap();
                println!("response_body: {:?}", response_body);
                let email = response_body;

                // token
                // <https://google.aip.dev/auth/4115>
                let url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
                let request = self
                    .client
                    .request(reqwest::Method::GET, url)
                    .header("Metadata-Flavor", "Google")
                    .build()
                    .unwrap();
                let response = self.client.execute(request).await.unwrap();
                println!("status: {:?}", response.status());
                if !response.status().is_success() {
                    let response_body = response.text().await.unwrap();
                    println!("response_body: {:?}", response_body);
                    todo!()
                }
                let response_body = response.text().await.unwrap();
                println!("response_body: {:?}", response_body);

                let access_token = serde_json::from_str::<'_, AccessToken>(&response_body).unwrap();

                let expires = SystemTime::now() + Duration::from_secs(access_token.expires_in);
                *cache = Some((email.clone(), access_token.access_token.clone(), expires));
                (email, access_token.access_token)
            }
        })
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let (email, token) = self.get_email_and_token().await?;

        // <https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signBlob>
        #[derive(Debug, serde::Serialize)]
        struct SignBlobRequestBody {
            #[serde(skip_serializing_if = "Option::is_none")]
            delegates: Option<Vec<String>>,
            payload: String,
        }
        #[derive(Debug, serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SignBlobResponseBody {
            key_id: String,
            signed_blob: String,
        }
        let url = format!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:signBlob",
            email
        );
        let request = self
            .client
            .request(reqwest::Method::POST, url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_string(&SignBlobRequestBody {
                    delegates: None,
                    payload: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        message,
                    ),
                })
                .unwrap(),
            )
            .build()
            .unwrap();
        let response = self.client.execute(request).await.unwrap();
        println!("status: {:?}", response.status());
        if !response.status().is_success() {
            let response_body = response.text().await.unwrap();
            println!("response_body: {:?}", response_body);
            todo!()
        }
        let response_body = response.text().await.unwrap();
        println!("response_body: {:?}", response_body);

        let response_body =
            serde_json::from_str::<'_, SignBlobResponseBody>(&response_body).unwrap();
        println!("response_body: {:?}", response_body);

        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            response_body.signed_blob,
        )
        .unwrap();

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        fn assert_impls<T: Clone + Send + Sync>() {}
        assert_impls::<BoundedToken>();
    }
}
