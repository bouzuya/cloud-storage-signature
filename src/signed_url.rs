use std::{str::FromStr as _, time::SystemTime};

use crate::{
    private::{
        utils::UnixTimestamp, ActiveDatetime, CredentialScope, Date, Expiration, HttpVerb,
        Location, RequestType, Service, SignedUrl,
    },
    SigningKey,
};

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] ErrorKind);

#[derive(Debug, thiserror::Error)]
enum ErrorKind {
    #[error(transparent)]
    CredentialScope(crate::private::credential_scope::Error),
    #[error(transparent)]
    Expiration(crate::private::expiration::Error),
    #[error("expiration out of range")]
    ExpirationOutOfRange,
    #[error(transparent)]
    HttpMethod(crate::private::http_verb::Error),
    #[error(transparent)]
    HttpRequest(http::Error),
    #[error(transparent)]
    InvalidHeaderName(http::header::InvalidHeaderName),
    #[error(transparent)]
    InvalidHeaderValue(http::header::InvalidHeaderValue),
    #[error(transparent)]
    InvalidQueryParameters(#[from] url::ParseError),
    #[error(transparent)]
    Location(crate::private::location::Error),
    #[error("now out of range")]
    Now,
    #[error(transparent)]
    SignedUrl(crate::private::signed_url::Error),
}

#[derive(Clone)]
pub struct BuildSignedUrlOptions {
    pub bucket_name: String,
    pub object_name: String,
    pub region: Option<String>,
    pub expires: SystemTime,
    pub http_method: String,
    pub accessible_at: Option<SystemTime>,
    pub signing_key: SigningKey,
    pub use_sign_blob: bool,
    pub headers: Vec<(String, String)>,
    pub query_parameters: Vec<(String, String)>,
}

pub async fn build_signed_url(
    BuildSignedUrlOptions {
        bucket_name,
        object_name,
        region,
        expires,
        http_method,
        accessible_at,
        signing_key,
        use_sign_blob,
        headers,
        query_parameters,
    }: BuildSignedUrlOptions,
) -> Result<String, Error> {
    let accessible_at = accessible_at.unwrap_or_else(SystemTime::now);
    let now = UnixTimestamp::from_system_time(accessible_at).map_err(|_| ErrorKind::Now)?;
    let region = region.unwrap_or_else(|| "auto".to_string());
    let expiration = i64::try_from(
        expires
            .duration_since(accessible_at)
            .map_err(|_| ErrorKind::ExpirationOutOfRange)?
            .as_secs(),
    )
    .map_err(|_| ErrorKind::ExpirationOutOfRange)?;

    let http_method = HttpVerb::from_str(http_method.as_str()).map_err(ErrorKind::HttpMethod)?;
    let mut url = url::Url::parse(
        format!(
            // TODO: escape bucket_name and object_name
            "https://storage.googleapis.com/{bucket_name}/{object_name}",
        )
        .as_str(),
    )
    .map_err(ErrorKind::InvalidQueryParameters)?;
    url.query_pairs_mut().extend_pairs(
        query_parameters
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
    );
    let mut request = http::Request::builder()
        .header("Host", "storage.googleapis.com")
        .method(http::Method::from(http_method))
        .uri(url.to_string())
        .body(())
        .map_err(ErrorKind::HttpRequest)?;
    request.headers_mut().extend(
        headers
            .iter()
            .map(
                |(k, v)| -> Result<(http::header::HeaderName, http::header::HeaderValue), Error> {
                    let key = http::header::HeaderName::from_bytes(k.as_bytes())
                        .map_err(ErrorKind::InvalidHeaderName)?;
                    let value = http::header::HeaderValue::from_str(v)
                        .map_err(ErrorKind::InvalidHeaderValue)?;
                    Ok((key, value))
                },
            )
            .collect::<Result<Vec<_>, Error>>()?,
    );
    let credential_scope = CredentialScope::new(
        Date::from_unix_timestamp_obj(now),
        Location::try_from(region.as_str()).map_err(ErrorKind::Location)?,
        Service::Storage,
        RequestType::Goog4Request,
    )
    .map_err(ErrorKind::CredentialScope)?;
    let signed_url = SignedUrl::new(
        &credential_scope,
        ActiveDatetime::from_unix_timestamp_obj(now),
        Expiration::try_from(expiration).map_err(ErrorKind::Expiration)?,
        request,
        signing_key,
        use_sign_blob,
    )
    .await
    .map_err(ErrorKind::SignedUrl)?;
    Ok(String::from(signed_url))
}
