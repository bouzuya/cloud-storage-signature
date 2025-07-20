use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

#[derive(Clone, Debug, serde::Deserialize)]
struct AccessToken {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum BoundTokenError {
    #[error("bound token / email request / build error: {0}")]
    EmailRequestBuild(#[source] reqwest::Error),
    #[error("bound token / email request / error response error: {0}")]
    EmailRequestErrorResponse(#[source] reqwest::Error),
    #[error("bound token / email request / execute error: {0}")]
    EmailRequestExecute(#[source] reqwest::Error),
    #[error("bound token / email request / status error: {0} {1}")]
    EmailRequestStatus(u16, String),
    #[error("bound token / email request / success response error: {0}")]
    EmailRequestSuccessResponse(#[source] reqwest::Error),
    #[error("bound token / signBlob request / build error: {0}")]
    SignBlobRequestBuild(#[source] reqwest::Error),
    #[error("bound token / signBlob request / error response error: {0}")]
    SignBlobRequestErrorResponse(#[source] reqwest::Error),
    #[error("bound token / signBlob request / execute error: {0}")]
    SignBlobRequestExecute(#[source] reqwest::Error),
    #[error("bound token / signBlob request / serialize error: {0}")]
    SignBlobRequestSerialize(#[source] serde_json::Error),
    #[error("bound token / signBlob request / status error: {0} {1}")]
    SignBlobRequestStatus(u16, String),
    #[error("bound token / signBlob request / success response error: {0}")]
    SignBlobRequestSuccessResponse(#[source] reqwest::Error),
    #[error("bound token / signBlob request / success response base64 decode error: {0}")]
    SignBlobRequestSuccessResponseBase64Decode(#[source] base64::DecodeError),
    #[error("bound token / signBlob request / success response deserialize error: {0}")]
    SignBlobRequestSuccessResponseDeserialize(#[source] serde_json::Error),
    #[error("bound token / token request / build error: {0}")]
    TokenRequestBuild(#[source] reqwest::Error),
    #[error("bound token / token request / error response error: {0}")]
    TokenRequestErrorResponse(#[source] reqwest::Error),
    #[error("bound token / token request / execute error: {0}")]
    TokenRequestExecute(#[source] reqwest::Error),
    #[error("bound token / token request / invalid token_type error: {0}")]
    TokenRequestInvalidTokenType(String),
    #[error("bound token / token request / status error: {0} {1}")]
    TokenRequestStatus(u16, String),
    #[error("bound token / token request / success response error: {0}")]
    TokenRequestSuccessResponse(#[source] reqwest::Error),
    #[error("bound token / token request / success response deserialize error: {0}")]
    TokenRequestSuccessResponseDeserialize(#[source] serde_json::Error),
}

#[derive(Clone)]
pub(crate) struct BoundToken {
    base_url: String,
    cache: Arc<tokio::sync::Mutex<Option<(String, String, SystemTime)>>>,
    client: reqwest::Client,
}

impl BoundToken {
    pub fn new() -> Self {
        Self {
            base_url: format!(
                "http://{}",
                std::env::var("GCE_METADATA_HOST")
                    .ok()
                    .unwrap_or_else(|| "metadata.google.internal".to_string())
            ),
            cache: Arc::new(tokio::sync::Mutex::new(None)),
            client: reqwest::Client::new(),
        }
    }

    pub(crate) async fn get_email_and_token(&self) -> Result<(String, String), BoundTokenError> {
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
                // email
                // <https://cloud.google.com/compute/docs/metadata/predefined-metadata-keys>
                let url = format!(
                    "{}/computeMetadata/v1/instance/service-accounts/default/email",
                    self.base_url
                );
                let request = self
                    .client
                    .request(reqwest::Method::GET, url)
                    .header("Metadata-Flavor", "Google")
                    .build()
                    .map_err(BoundTokenError::EmailRequestBuild)?;
                let response = self
                    .client
                    .execute(request)
                    .await
                    .map_err(BoundTokenError::EmailRequestExecute)?;
                let status = response.status();
                if !status.is_success() {
                    let response_body = response
                        .text()
                        .await
                        .map_err(BoundTokenError::EmailRequestErrorResponse)?;
                    return Err(BoundTokenError::EmailRequestStatus(
                        status.as_u16(),
                        response_body,
                    ));
                }
                let response_body = response
                    .text()
                    .await
                    .map_err(BoundTokenError::EmailRequestSuccessResponse)?;
                let email = response_body;

                // token
                // <https://google.aip.dev/auth/4115>
                let url = format!(
                    "{}/computeMetadata/v1/instance/service-accounts/default/token",
                    self.base_url
                );
                let request = self
                    .client
                    .request(reqwest::Method::GET, url)
                    .header("Metadata-Flavor", "Google")
                    .build()
                    .map_err(BoundTokenError::TokenRequestBuild)?;
                let response = self
                    .client
                    .execute(request)
                    .await
                    .map_err(BoundTokenError::TokenRequestExecute)?;
                let status = response.status();
                if !status.is_success() {
                    let response_body = response
                        .text()
                        .await
                        .map_err(BoundTokenError::TokenRequestErrorResponse)?;
                    return Err(BoundTokenError::TokenRequestStatus(
                        status.as_u16(),
                        response_body,
                    ));
                }
                let response_body = response
                    .text()
                    .await
                    .map_err(BoundTokenError::TokenRequestSuccessResponse)?;
                let access_token = serde_json::from_str::<'_, AccessToken>(&response_body)
                    .map_err(BoundTokenError::TokenRequestSuccessResponseDeserialize)?;
                if access_token.token_type != "Bearer" {
                    return Err(BoundTokenError::TokenRequestInvalidTokenType(
                        access_token.token_type,
                    ));
                }
                let expires = SystemTime::now() + Duration::from_secs(access_token.expires_in);
                *cache = Some((email.clone(), access_token.access_token.clone(), expires));
                (email, access_token.access_token)
            }
        })
    }

    pub(crate) async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, BoundTokenError> {
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
            #[allow(unused)]
            key_id: String,
            signed_blob: String,
        }
        let url = format!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{email}:signBlob"
        );
        let request = self
            .client
            .request(reqwest::Method::POST, url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_string(&SignBlobRequestBody {
                    delegates: None,
                    payload: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        message,
                    ),
                })
                .map_err(BoundTokenError::SignBlobRequestSerialize)?,
            )
            .build()
            .map_err(BoundTokenError::SignBlobRequestBuild)?;
        let response = self
            .client
            .execute(request)
            .await
            .map_err(BoundTokenError::SignBlobRequestExecute)?;
        let status = response.status();
        if !status.is_success() {
            let response_body = response
                .text()
                .await
                .map_err(BoundTokenError::SignBlobRequestErrorResponse)?;
            return Err(BoundTokenError::SignBlobRequestStatus(
                status.as_u16(),
                response_body,
            ));
        }
        let response_body = response
            .text()
            .await
            .map_err(BoundTokenError::SignBlobRequestSuccessResponse)?;
        let response_body = serde_json::from_str::<'_, SignBlobResponseBody>(&response_body)
            .map_err(BoundTokenError::SignBlobRequestSuccessResponseDeserialize)?;

        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            response_body.signed_blob,
        )
        .map_err(BoundTokenError::SignBlobRequestSuccessResponseBase64Decode)?;

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        fn assert_impls<T: Clone + Send + Sync>() {}
        assert_impls::<BoundToken>();
    }

    #[test]
    fn test_internal_gce_metadata_host() {
        let bound_token = temp_env::with_var("GCE_METADATA_HOST", Some("169.254.169.254"), || {
            BoundToken::new()
        });
        assert_eq!(bound_token.base_url, "http://169.254.169.254");
    }
}
