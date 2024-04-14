use std::collections::BTreeSet;

use crate::SigningKey;

use super::ActiveDatetime;
use super::CredentialScope;
use super::Expiration;
use super::SigningAlgorithm;
use super::StringToSign;
use super::{canonical_query_string, CanonicalRequest};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    CanonicalRequest(crate::private::canonical_request::Error),
    #[error("host header not found")]
    HostHeaderNotFound,
    #[error("signing error: {0}")]
    Signing(crate::signing_key::Error),
}

pub struct SignedUrl(String);

impl SignedUrl {
    pub(crate) async fn new(
        credential_scope: &CredentialScope,
        active_datetime: ActiveDatetime,
        expiration: Expiration,
        mut request: http::Request<()>,
        signing_key: SigningKey,
        use_sign_blob: bool,
    ) -> Result<Self, Error> {
        let service_account_client_email =
            signing_key.authorizer().await.map_err(Error::Signing)?;
        let x_goog_algorithm = signing_key.x_goog_algorithm();
        add_signed_url_required_query_string_parameters(
            &mut request,
            service_account_client_email.as_str(),
            x_goog_algorithm,
            active_datetime,
            credential_scope,
            expiration,
        )?;
        let canonical_query_string = canonical_query_string(&request);
        let string_to_sign = StringToSign::new(
            x_goog_algorithm,
            active_datetime,
            credential_scope,
            CanonicalRequest::new(&request).map_err(Error::CanonicalRequest)?,
        );

        let message = string_to_sign.to_string();
        let message_digest = signing_key
            .sign(use_sign_blob, message.as_bytes())
            .await
            .map_err(Error::Signing)?;
        let request_signature = hex_encode(&message_digest);

        let hostname = "https://storage.googleapis.com";
        let path_to_resource = request.uri().path();
        let signed_url = [
            hostname,
            path_to_resource,
            "?",
            canonical_query_string.as_str(),
            "&X-Goog-Signature=",
            request_signature.as_str(),
        ]
        .join("");
        Ok(Self(signed_url))
    }
}

impl std::convert::From<SignedUrl> for String {
    fn from(value: SignedUrl) -> Self {
        value.0
    }
}

fn add_signed_url_required_query_string_parameters(
    request: &mut http::Request<()>,
    service_account_client_email: &str,
    x_goog_algorithm: SigningAlgorithm,
    x_goog_date: ActiveDatetime,
    credential_scope: &CredentialScope,
    expiration: Expiration,
) -> Result<(), Error> {
    if !request.headers().contains_key(http::header::HOST) {
        return Err(Error::HostHeaderNotFound);
    }
    let authorizer = service_account_client_email;
    let mut url1 = url::Url::parse(request.uri().to_string().as_str()).expect("uri to be valid");
    url1.query_pairs_mut()
        .append_pair("X-Goog-Algorithm", x_goog_algorithm.as_str())
        .append_pair(
            "X-Goog-Credential",
            format!("{authorizer}/{credential_scope}")
                .replace('/', "%2F")
                .as_str(),
        )
        .append_pair("X-Goog-Date", x_goog_date.to_string().as_str())
        .append_pair("X-Goog-Expires", expiration.to_string().as_str())
        .append_pair(
            "X-Goog-SignedHeaders",
            request
                .headers()
                .keys()
                .map(|k| k.to_string().to_ascii_lowercase())
                .collect::<BTreeSet<String>>()
                .into_iter()
                .collect::<Vec<String>>()
                .join(";")
                .as_str(),
        )
        .finish();
    *request.uri_mut() = http::Uri::try_from(url1.to_string()).expect("url to be valid");
    Ok(())
}

pub(crate) fn hex_encode(message_digest: &[u8]) -> String {
    use std::fmt::Write as _;
    message_digest.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{:02x}", b);
        s
    })
}

#[cfg(test)]
mod tests {
    use crate::private::{utils::UnixTimestamp, Date, Location, RequestType, Service};

    use super::*;

    #[test]
    fn test_add_signed_url_required_query_string_parameters() -> anyhow::Result<()> {
        let unix_timestamp = UnixTimestamp::from_rfc3339("2020-01-02T03:04:05Z")?;
        let expiration = Expiration::try_from(604800)?;
        let service_account_client_email = "service_account_name1";
        let mut request = http::Request::builder()
            .header("Host", "storage.googleapis.com")
            .header("Content-Type", "text/plain")
            .header("x-goog-meta-reviewer", "jane")
            .header("x-goog-meta-reviewer", "john")
            .method(http::Method::POST)
            .uri("https://storage.googleapis.com/example-bucket/cat-pics/tabby.jpeg?generation=1360887697105000&userProject=my-project")
            .body(())?;
        add_signed_url_required_query_string_parameters(
            &mut request,
            service_account_client_email,
            SigningAlgorithm::Goog4RsaSha256,
            ActiveDatetime::from_unix_timestamp_obj(unix_timestamp),
            &CredentialScope::new(
                Date::from_unix_timestamp_obj(unix_timestamp),
                Location::try_from("us-central1")?,
                Service::Storage,
                RequestType::Goog4Request,
            )?,
            expiration,
        )?;
        let s = CanonicalRequest::new(&request)?.to_string();
        assert!(s.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=service_account_name1%2F20200102%2Fus-central1%2Fstorage%2Fgoog4_request&X-Goog-Date=20200102T030405Z&X-Goog-Expires=604800&X-Goog-SignedHeaders=content-type%3Bhost%3Bx-goog-meta-reviewer&generation=1360887697105000&userProject=my-project"));
        Ok(())
    }

    #[test]
    fn test_request_header() -> anyhow::Result<()> {
        let request = http::Request::builder()
            .header("Content-Type", "text/plain")
            .body(())?;
        assert!(request.headers().contains_key("Content-Type"));
        assert!(request.headers().contains_key("content-type"));
        assert!(request.headers().contains_key(http::header::CONTENT_TYPE));
        Ok(())
    }
}
