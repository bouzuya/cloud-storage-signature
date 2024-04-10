pub mod html_form_data;
mod private;
mod service_account_credentials;

use std::str::FromStr;
use std::time::SystemTime;

use self::private::utils::UnixTimestamp;
use self::private::ActiveDatetime;
use self::private::CredentialScope;
use self::private::Date;
use self::private::Expiration;
use self::private::HttpVerb;
use self::private::Location;
use self::private::RequestType;
use self::private::Service;
use self::private::SignedUrl;

pub use self::html_form_data::{HtmlFormData, HtmlFormDataBuilder, PolicyDocumentSigningOptions};
pub use self::service_account_credentials::ServiceAccountCredentials;

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
    File(std::io::Error),
    #[error(transparent)]
    HttpMethod(crate::private::http_verb::Error),
    #[error(transparent)]
    HttpRequest(http::Error),
    #[error("invalid json")]
    InvalidServiceAccountJson(serde_json::Error),
    #[error(transparent)]
    Location(crate::private::location::Error),
    #[error("now out of range")]
    Now,
    #[error("client_email is not found")]
    ServiceAccountJsonClientEmailIsNotFound,
    #[error("client_email is not string")]
    ServiceAccountJsonClientEmailIsNotString,
    #[error("json root is not object")]
    ServiceAccountJsonRootIsNotObject,
    #[error("private_key is not found")]
    ServiceAccountJsonPrivateKeyIsNotFound,
    #[error("private_key is not string")]
    ServiceAccountJsonPrivateKeyIsNotString,
    #[error(transparent)]
    SignedUrl(crate::private::signed_url::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildSignedUrlOptions {
    pub service_account_client_email: String,
    pub service_account_private_key: String,
    pub bucket_name: String,
    pub object_name: String,
    pub region: Option<String>,
    pub expires: SystemTime,
    pub http_method: String,
    pub accessible_at: Option<SystemTime>,
}

pub fn build_signed_url(
    BuildSignedUrlOptions {
        service_account_client_email,
        service_account_private_key,
        bucket_name,
        object_name,
        region,
        expires,
        http_method,
        accessible_at,
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
    let request = http::Request::builder()
        .header("Host", "storage.googleapis.com")
        .method(http::Method::from(http_method))
        .uri(
            format!(
                "https://storage.googleapis.com/{}/{}",
                // TODO: escape bucket_name and object_name
                bucket_name,
                object_name
            )
            .as_str(),
        )
        .body(())
        .map_err(ErrorKind::HttpRequest)?;
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
        &service_account_client_email,
        &service_account_private_key,
        request,
    )
    .map_err(ErrorKind::SignedUrl)?;
    Ok(String::from(signed_url))
}
