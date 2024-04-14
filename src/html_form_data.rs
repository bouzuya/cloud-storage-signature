use std::time::SystemTime;

use crate::{
    private::{
        hex_encode, policy_document, utils::UnixTimestamp, CredentialScope, Date, Location,
        RequestType, Service,
    },
    signing_key::SigningKey,
};

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(#[from] ErrorKind);

#[derive(Debug, thiserror::Error)]
pub(crate) enum ErrorKind {
    #[error("accessible_at out of range")]
    AccessibleAtOutOfRange,
    #[error("bound token authorizer: {0}")]
    BoundTokenAuthorizer(#[source] crate::signing_key::BoundTokenError),
    #[error("bound token sign: {0}")]
    BoundTokenSign(#[source] crate::signing_key::BoundTokenError),
    #[error("bucket not found")]
    BucketNotFound,
    #[error("expiration before accessible_at")]
    ExpirationBeforeAccessibleAt,
    #[error("expiration out of range")]
    ExpirationOutOfRange,
    #[error("key not found")]
    KeyNotFound,
    #[error("policy document serialization")]
    PolicyDocumentSerialization,
    #[error("service account private key parsing")]
    ServiceAccountPrivateKeyParsing,
    #[error(transparent)]
    Sign(crate::private::signed_url::Error),
    #[error("x-goog-algorithm not supported")]
    XGoogAlgorithmNotSupported,
    #[error("x-goog-credential invalid")]
    XGoogCredentialInvalid(crate::private::credential_scope::Error),
    #[error("x-goog-meta-* field name is empty")]
    XGoogMetaNameEmpty,
}

/// HTML Form Data.
///
/// <https://cloud.google.com/storage/docs/xml-api/post-object-forms>
///
/// # Example (full)
///
/// ```rust
/// # async fn example_for_html_form_data_full() -> anyhow::Result<()> {
/// #     let service_account_client_email = "test@example.com";
/// #     let service_account_private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQChK9QyIk4mpcaO\nxXY+DIb8xsJKXfqAgzsboG/Ho8W9C6NZwM0+7kuV39QrP+UGo5GTpKfe3gZYQMoP\nHIAirNMa/K3/8oczucts+ZueWzCdElZ0+E04BLRkWNUM86hQ0TIL+jCi83JZHaGY\npjgMSUUDj+vJc5QjYmu2zGHAsWvBUfIQc6/Am+shtQG1gPpxTKlXS117pIzlAz8Z\nahRKJHn33fpBudYYDKm1fsyCFPS05rBBvjrvGNsGJn/6rRb8+ixVr6LOipSZ5KbS\n+/kvxQSTa7nKKqCoK1fUp+k489IL0XWW4z5PrBNNBjE0oQ3yfnkVW/LBNsrFjT6x\nAOKis8QZAgMBAAECggEABVuCHbqDM4iuLX/F2vEqqYtn2PX/xjbWh6gRHydEAvE4\nmFqu1+ku7Qf4MwnYMJzOUYSXKfLibhuVO+RcJArvp4V/uTLUKLWD3Bb+A8kPOCFs\na033ryWE45MKXfhZf3o8uiYyaLBD/E9eWEcqNMpYt3IYyeUEJxr17qkjlLaxGMd1\nixQdDSS8d48EyMg8RaA2q5l5sG5CoxeEFX7BR3SCjqNS8lzZcQ70mdJjtbmRd7st\nggbcZzd8C2XlT5QFSAEge0uRHEo2d48o09PkTAT4AfsjlYmAhAL1ph0fVPdnXSVk\ng/8u8BGM3WwBIL3jmV/uy5dDmLCv7XwsWxBEnmbwKQKBgQDTbq6QiA+lvLIlpUpA\nmRgWvpHRNv5axSmN77RDcrm96GUrXyLakDmZ/NiAp727RRMcsDkxhTnav/gcQwUC\nl9wCT8ItT32e23HxyQ4kkejrMGtsQyxqd3gN0QzkgAwWQPJMf4vgXOL50lB9Dos1\n5G2p7aUHTLVHqK602S5LbntFhQKBgQDDJPQrlpUhV6zb+B8ZhAJ6SyZUhQ0+81qk\nDxzXdMpUR6gYxzvB5thUqxP9dXuSW7b+L8Pa7ayOxXQqyS+HYKnFJfGkSG2kZMWB\n+zbZgPq1Nq6QyELGFQd3t7g6AOmTL6q7K/D2ghfIGwL2R3TuDrVOW/EQ8mMBAbZP\nLT1FKRvuhQKBgEnBnKfSrxK0BrlXNdXfEiYtCJUhSA3GJb7b1diJlv4GqfQ9Vd1E\n3rM3HxeSbH99kzM4zlrWDN6ghR7mykKjUx6DUEuaJUpbZx5fcs2TENuqom676Cyj\nzH+VY5f6izzgHyZMgDEedheMJIPbpPiB3TegLSekvMBoublg4eNygRI5AoGBALKo\nQmMlmaLNAhThNJfHo/0SkCURKu9XHMTWkTEwW4yNjfghbzQ2hBgACG0kAd4c2Ywd\nbtIghrqvS4tgZYMrnEJCWths9vRqzegSdkTrMJx3U5p5vahb2FpieOehrjZyjXyO\n3izRLbSmBjAze3n3PUZgJnO9daaWSrJyWIXY/RmBAoGBAJasPa2BUV5dg/huiLDE\nnjhWxr2ezceoSxNyhLgmpS2vrBtJWWE4pRVZgJPqbXwMsSfjQqSGp0QWWJ1KHpIv\nn32eCAbgj/9wrwoU9u3cEA4BhYHjg3p9empYdLMJgeLAvKpUbvKbEkZITDFtkWis\njI3VAsh2OHCsO8ToNwX3Kgku\n-----END PRIVATE KEY-----\n";
/// use cloud_storage_signature::HtmlFormData;
/// use cloud_storage_signature::PolicyDocumentSigningOptions;
/// use cloud_storage_signature::SigningKey;
/// let form_data = HtmlFormData::builder()
///     .acl("public-read")
///     .bucket("example-bucket")
///     .cache_control("max-age=3600")
///     .content_disposition("attachment")
///     .content_encoding("gzip")
///     .content_length(1024)
///     .content_type("application/octet-stream")
///     .expires("2022-01-04T00:00:00Z")
///     .key("example-object")
///     .success_action_redirect("https://example.com/success")
///     .success_action_status(201)
///     .x_goog_custom_time("2022-01-03T00:00:00Z")
///     .x_goog_meta("reviewer", "jane")
///     .x_goog_meta("project-manager", "john")
///     .policy_document_signing_options(PolicyDocumentSigningOptions {
///         accessible_at: None,
///         expiration: std::time::SystemTime::now() + std::time::Duration::from_secs(60 * 60),
///         region: None,
///         signing_key: SigningKey::service_account(
///             service_account_client_email.to_string(),
///             service_account_private_key.to_string(),
///         ),
///         use_sign_blob: false,
///     })
///     .build()
///     .await?;
/// assert_eq!(
///   form_data.into_vec().into_iter().map(|(n, _)| n).collect::<Vec<String>>(),
///   [
///     "acl",
///     "bucket",
///     "Cache-Control",
///     "Content-Disposition",
///     "Content-Encoding",
///     "Content-Length",
///     "Content-Type",
///     "Expires",
///     "key",
///     "policy",
///     "success_action_redirect",
///     "success_action_status",
///     "x-goog-algorithm",
///     "x-goog-credential",
///     "x-goog-custom-time",
///     "x-goog-date",
///     "x-goog-signature",
///     "x-goog-meta-reviewer",
///     "x-goog-meta-project-manager",
///   ].into_iter().map(|n| n.to_string()).collect::<Vec<String>>()
/// );
/// #     Ok(())
/// # }
/// ```
///
/// # Example (minimal)
///
/// ```rust
/// # async fn example_for_html_form_data_minimal() -> Result<(), cloud_storage_signature::html_form_data::Error>
/// # {
/// use cloud_storage_signature::HtmlFormData;
/// assert_eq!(
///     HtmlFormData::builder()
///         .key("object_name1")
///         .build()
///         .await?
///         .into_vec(),
///     vec![("key".to_string(), "object_name1".to_string())]
/// );
/// #     Ok(())
/// # }
/// ```
///
/// # Example (policy document minimal)
///
/// ```rust
/// # async fn example_for_html_form_data_with_policy_document() -> anyhow::Result<()> {
/// #     let service_account_client_email = "test@example.com";
/// #     let service_account_private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQChK9QyIk4mpcaO\nxXY+DIb8xsJKXfqAgzsboG/Ho8W9C6NZwM0+7kuV39QrP+UGo5GTpKfe3gZYQMoP\nHIAirNMa/K3/8oczucts+ZueWzCdElZ0+E04BLRkWNUM86hQ0TIL+jCi83JZHaGY\npjgMSUUDj+vJc5QjYmu2zGHAsWvBUfIQc6/Am+shtQG1gPpxTKlXS117pIzlAz8Z\nahRKJHn33fpBudYYDKm1fsyCFPS05rBBvjrvGNsGJn/6rRb8+ixVr6LOipSZ5KbS\n+/kvxQSTa7nKKqCoK1fUp+k489IL0XWW4z5PrBNNBjE0oQ3yfnkVW/LBNsrFjT6x\nAOKis8QZAgMBAAECggEABVuCHbqDM4iuLX/F2vEqqYtn2PX/xjbWh6gRHydEAvE4\nmFqu1+ku7Qf4MwnYMJzOUYSXKfLibhuVO+RcJArvp4V/uTLUKLWD3Bb+A8kPOCFs\na033ryWE45MKXfhZf3o8uiYyaLBD/E9eWEcqNMpYt3IYyeUEJxr17qkjlLaxGMd1\nixQdDSS8d48EyMg8RaA2q5l5sG5CoxeEFX7BR3SCjqNS8lzZcQ70mdJjtbmRd7st\nggbcZzd8C2XlT5QFSAEge0uRHEo2d48o09PkTAT4AfsjlYmAhAL1ph0fVPdnXSVk\ng/8u8BGM3WwBIL3jmV/uy5dDmLCv7XwsWxBEnmbwKQKBgQDTbq6QiA+lvLIlpUpA\nmRgWvpHRNv5axSmN77RDcrm96GUrXyLakDmZ/NiAp727RRMcsDkxhTnav/gcQwUC\nl9wCT8ItT32e23HxyQ4kkejrMGtsQyxqd3gN0QzkgAwWQPJMf4vgXOL50lB9Dos1\n5G2p7aUHTLVHqK602S5LbntFhQKBgQDDJPQrlpUhV6zb+B8ZhAJ6SyZUhQ0+81qk\nDxzXdMpUR6gYxzvB5thUqxP9dXuSW7b+L8Pa7ayOxXQqyS+HYKnFJfGkSG2kZMWB\n+zbZgPq1Nq6QyELGFQd3t7g6AOmTL6q7K/D2ghfIGwL2R3TuDrVOW/EQ8mMBAbZP\nLT1FKRvuhQKBgEnBnKfSrxK0BrlXNdXfEiYtCJUhSA3GJb7b1diJlv4GqfQ9Vd1E\n3rM3HxeSbH99kzM4zlrWDN6ghR7mykKjUx6DUEuaJUpbZx5fcs2TENuqom676Cyj\nzH+VY5f6izzgHyZMgDEedheMJIPbpPiB3TegLSekvMBoublg4eNygRI5AoGBALKo\nQmMlmaLNAhThNJfHo/0SkCURKu9XHMTWkTEwW4yNjfghbzQ2hBgACG0kAd4c2Ywd\nbtIghrqvS4tgZYMrnEJCWths9vRqzegSdkTrMJx3U5p5vahb2FpieOehrjZyjXyO\n3izRLbSmBjAze3n3PUZgJnO9daaWSrJyWIXY/RmBAoGBAJasPa2BUV5dg/huiLDE\nnjhWxr2ezceoSxNyhLgmpS2vrBtJWWE4pRVZgJPqbXwMsSfjQqSGp0QWWJ1KHpIv\nn32eCAbgj/9wrwoU9u3cEA4BhYHjg3p9empYdLMJgeLAvKpUbvKbEkZITDFtkWis\njI3VAsh2OHCsO8ToNwX3Kgku\n-----END PRIVATE KEY-----\n";
/// use cloud_storage_signature::HtmlFormData;
/// use cloud_storage_signature::PolicyDocumentSigningOptions;
/// use cloud_storage_signature::SigningKey;
/// let form_data = HtmlFormData::builder()
///     .bucket("example-bucket")
///     .key("example-object")
///     .policy_document_signing_options(PolicyDocumentSigningOptions {
///         accessible_at: None,
///         expiration: std::time::SystemTime::now() + std::time::Duration::from_secs(60 * 60),
///         region: None,
///         signing_key: SigningKey::service_account(
///             service_account_client_email.to_string(),
///             service_account_private_key.to_string()
///         ),
///         use_sign_blob: false,
///     })
///     .build()
///     .await?;
/// assert_eq!(
///   form_data.into_vec().into_iter().map(|(n, _)| n).collect::<Vec<String>>(),
///   [
///     "bucket",
///     "key",
///     "policy",
///     "x-goog-algorithm",
///     "x-goog-credential",
///     "x-goog-date",
///     "x-goog-signature",
///   ].into_iter().map(|n| n.to_string()).collect::<Vec<String>>()
/// );
/// #     Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct HtmlFormData(Vec<(String, String)>);

impl HtmlFormData {
    /// Returns a new `HtmlFormDataBuilder`.
    pub fn builder() -> HtmlFormDataBuilder {
        HtmlFormDataBuilder::default()
    }

    /// Converts `self` into a `Vec<(String, String)>`.
    /// The first element of each tuple is the field name, and the second
    /// element is the field value.
    pub fn into_vec(self) -> Vec<(String, String)> {
        self.0
    }
}

/// Policy Document Signing Options.
///
/// See [`HtmlFormData`] examples.
pub struct PolicyDocumentSigningOptions {
    pub accessible_at: Option<SystemTime>,
    pub expiration: SystemTime,
    pub region: Option<String>,
    pub signing_key: SigningKey,
    pub use_sign_blob: bool,
}

/// HTML Form Data Builder.
///
/// See [`HtmlFormData`] examples.
#[derive(Default)]
pub struct HtmlFormDataBuilder {
    acl: Option<String>,
    bucket: Option<String>,
    cache_control: Option<String>,
    content_disposition: Option<String>,
    content_encoding: Option<String>,
    // max content-length size is 5 TiB
    // <https://cloud.google.com/storage/quotas#objects>
    content_length: Option<u64>,
    content_type: Option<String>,
    expires: Option<String>,
    // `file` field is not included.
    key: Option<String>,
    // `policy_document_sining_options` is not HTML form data field.
    policy_document_signing_options: Option<PolicyDocumentSigningOptions>,
    success_action_redirect: Option<String>,
    success_action_status: Option<u16>,
    // `x-goog-algorithm` field is not included. It is calculated from the policy_document_signing_options.
    // `x-goog-credential` field is not included. It is calculated from the policy_document_signing_options.
    x_goog_custom_time: Option<String>,
    // `x-goog-date` field is not included. It is calculated from the policy_document_signing_options.
    // `x-goog-signature` field is not included. It is calculated from the policy_document_signing_options.
    x_goog_meta: Vec<(String, String)>,
}

impl HtmlFormDataBuilder {
    /// Sets the `acl` field.
    pub fn acl(mut self, acl: impl Into<String>) -> Self {
        self.acl = Some(acl.into());
        self
    }

    /// Sets the `bucket` field.
    pub fn bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    /// Builds the `HtmlFormData`.
    pub async fn build(self) -> Result<HtmlFormData, Error> {
        let (policy, x_goog_algorithm, x_goog_credential, x_goog_date, x_goog_signature) =
            self.build_policy_and_x_goog_signature().await?;

        let mut vec = vec![];
        if let Some(acl) = self.acl {
            vec.push(("acl".to_string(), acl));
        }
        if let Some(bucket) = self.bucket {
            vec.push(("bucket".to_string(), bucket));
        }
        if let Some(cache_control) = self.cache_control {
            vec.push(("Cache-Control".to_string(), cache_control));
        }
        if let Some(content_disposition) = self.content_disposition {
            vec.push(("Content-Disposition".to_string(), content_disposition));
        }
        if let Some(content_encoding) = self.content_encoding {
            vec.push(("Content-Encoding".to_string(), content_encoding));
        }
        if let Some(content_length) = self.content_length {
            vec.push(("Content-Length".to_string(), content_length.to_string()));
        }
        if let Some(content_type) = self.content_type {
            vec.push(("Content-Type".to_string(), content_type));
        }
        if let Some(expires) = self.expires {
            vec.push(("Expires".to_string(), expires));
        }
        vec.push(("key".to_string(), self.key.ok_or(ErrorKind::KeyNotFound)?));
        if let Some(policy) = policy {
            vec.push(("policy".to_string(), policy));
        }
        if let Some(success_action_redirect) = self.success_action_redirect {
            vec.push((
                "success_action_redirect".to_string(),
                success_action_redirect,
            ));
        }
        if let Some(success_action_status) = self.success_action_status {
            vec.push((
                "success_action_status".to_string(),
                success_action_status.to_string(),
            ));
        }
        if let Some(x_goog_algorithm) = x_goog_algorithm {
            vec.push(("x-goog-algorithm".to_string(), x_goog_algorithm));
        }
        if let Some(x_goog_credential) = x_goog_credential {
            vec.push(("x-goog-credential".to_string(), x_goog_credential));
        }
        if let Some(x_goog_custom_time) = self.x_goog_custom_time {
            vec.push(("x-goog-custom-time".to_string(), x_goog_custom_time));
        }
        if let Some(x_goog_date) = x_goog_date {
            vec.push(("x-goog-date".to_string(), x_goog_date));
        }
        if let Some(x_goog_signature) = x_goog_signature {
            vec.push(("x-goog-signature".to_string(), x_goog_signature));
        }
        for (key, value) in self.x_goog_meta {
            if key.is_empty() {
                return Err(Error::from(ErrorKind::XGoogMetaNameEmpty));
            }
            vec.push((format!("x-goog-meta-{}", key), value));
        }
        Ok(HtmlFormData(vec))
    }

    /// Sets the `Cache-Control` field.
    pub fn cache_control(mut self, cache_control: impl Into<String>) -> Self {
        self.cache_control = Some(cache_control.into());
        self
    }

    /// Sets the `Content-Disposition` field.
    pub fn content_disposition(mut self, content_disposition: impl Into<String>) -> Self {
        self.content_disposition = Some(content_disposition.into());
        self
    }

    /// Sets the `Content-Encoding` field.
    pub fn content_encoding(mut self, content_encoding: impl Into<String>) -> Self {
        self.content_encoding = Some(content_encoding.into());
        self
    }

    /// Sets the `Content-Length` field.
    pub fn content_length(mut self, content_length: u64) -> Self {
        self.content_length = Some(content_length);
        self
    }

    /// Sets the `Content-Type` field.
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Sets the `Expires` field.
    pub fn expires(mut self, expires: impl Into<String>) -> Self {
        self.expires = Some(expires.into());
        self
    }

    /// Sets the `key` field.
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Sets the `policy` field, `x-goog-algorithm` field, `x-goog-credential` field, `x-goog-date` field, and `x-goog-signature` field.
    pub fn policy_document_signing_options(
        mut self,
        policy_document_signing_options: PolicyDocumentSigningOptions,
    ) -> Self {
        self.policy_document_signing_options = Some(policy_document_signing_options);
        self
    }

    /// Sets the `success_action_redirect` field.
    pub fn success_action_redirect(mut self, success_action_redirect: impl Into<String>) -> Self {
        self.success_action_redirect = Some(success_action_redirect.into());
        self
    }

    /// Sets the `success_action_status` field.
    pub fn success_action_status(mut self, success_action_status: u16) -> Self {
        self.success_action_status = Some(success_action_status);
        self
    }

    /// Sets the `x-goog-custom-time` field.
    pub fn x_goog_custom_time(mut self, x_goog_custom_time: impl Into<String>) -> Self {
        self.x_goog_custom_time = Some(x_goog_custom_time.into());
        self
    }

    /// Sets the `x-goog-meta-*` field.
    pub fn x_goog_meta(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.x_goog_meta.push((name.into(), value.into()));
        self
    }

    // .0: policy
    // .1: x-goog-algorithm
    // .2: x-goog-credential
    // .3: x-goog-date
    // .4: x-goog-signature
    #[allow(clippy::type_complexity)]
    async fn build_policy_and_x_goog_signature(
        &self,
    ) -> Result<
        (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
        Error,
    > {
        match self.policy_document_signing_options.as_ref() {
            None => Ok((None, None, None, None, None)),
            Some(PolicyDocumentSigningOptions {
                accessible_at,
                expiration,
                region,
                signing_key,
                use_sign_blob,
            }) => {
                let accessible_at = accessible_at.unwrap_or_else(SystemTime::now);
                let expiration = *expiration;
                if expiration <= accessible_at {
                    return Err(Error::from(ErrorKind::ExpirationBeforeAccessibleAt));
                }
                let accessible_at = UnixTimestamp::from_system_time(accessible_at)
                    .map_err(|_| ErrorKind::AccessibleAtOutOfRange)?;
                let expiration = UnixTimestamp::from_system_time(expiration)
                    .map_err(|_| ErrorKind::ExpirationOutOfRange)?;
                let region = region.as_deref().unwrap_or("auto");
                let bucket = self.bucket.as_deref().ok_or(ErrorKind::BucketNotFound)?;
                let key = self.key.as_deref().ok_or(ErrorKind::KeyNotFound)?;
                let x_goog_algorithm = signing_key.x_goog_algorithm();
                // TODO: x_goog_algorithm "GOOG4-HMAC-SHA256" is not supported yet
                if x_goog_algorithm != "GOOG4-RSA-SHA256" {
                    // TODO: return an error if hmac and use_sign_blob
                    return Err(Error::from(ErrorKind::XGoogAlgorithmNotSupported));
                }

                let service_account_client_email = signing_key.authorizer().await?;

                let credential_scope = CredentialScope::new(
                    Date::from_unix_timestamp_obj(accessible_at),
                    Location::try_from(region).expect("region to be valid location"),
                    Service::Storage,
                    RequestType::Goog4Request,
                )
                .map_err(ErrorKind::XGoogCredentialInvalid)?;
                let x_goog_credential =
                    format!("{}/{}", service_account_client_email, credential_scope);
                let x_goog_date = accessible_at.to_iso8601_basic_format_date_time();
                let expiration = policy_document::Expiration::from_unix_timestamp_obj(expiration);

                let mut conditions = vec![];
                if let Some(acl) = self.acl.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("acl").expect("acl to be valid field name"),
                        policy_document::Value::new(acl),
                    ));
                }
                conditions.push(policy_document::Condition::ExactMatching(
                    policy_document::Field::new("bucket").expect("bucket to be valid field name"),
                    policy_document::Value::new(bucket),
                ));
                if let Some(cache_control) = self.cache_control.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("Cache-Control")
                            .expect("Cache-Control to be valid field name"),
                        policy_document::Value::new(cache_control),
                    ));
                }
                if let Some(content_disposition) = self.content_disposition.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("Content-Disposition")
                            .expect("Content-Disposition to be valid field name"),
                        policy_document::Value::new(content_disposition),
                    ));
                }
                if let Some(content_encoding) = self.content_encoding.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("Content-Encoding")
                            .expect("Content-Encoding to be valid field name"),
                        policy_document::Value::new(content_encoding),
                    ));
                }
                if let Some(content_length) = self.content_length {
                    conditions.push(policy_document::Condition::ContentLengthRange(
                        content_length,
                        content_length,
                    ));
                }
                if let Some(content_type) = self.content_type.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("Content-Type")
                            .expect("Content-Type to be valid field name"),
                        policy_document::Value::new(content_type),
                    ));
                }
                if let Some(expires) = self.expires.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("Expires")
                            .expect("Expires to be valid field name"),
                        policy_document::Value::new(expires),
                    ));
                }
                conditions.push(policy_document::Condition::ExactMatching(
                    policy_document::Field::new("key").expect("key to be valid field name"),
                    policy_document::Value::new(key),
                ));
                // `policy` field is not included in the policy document
                if let Some(success_action_redirect) = self.success_action_redirect.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("success_action_redirect")
                            .expect("success_action_redirect to be valid field name"),
                        policy_document::Value::new(success_action_redirect),
                    ));
                }
                if let Some(success_action_status) = self.success_action_status {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("success_action_status")
                            .expect("success_action_status to be valid field name"),
                        policy_document::Value::new(success_action_status.to_string()),
                    ));
                }
                conditions.push(policy_document::Condition::ExactMatching(
                    policy_document::Field::new("x-goog-algorithm")
                        .expect("x-goog-algorithm to be valid field name"),
                    policy_document::Value::new(x_goog_algorithm),
                ));
                conditions.push(policy_document::Condition::ExactMatching(
                    policy_document::Field::new("x-goog-credential")
                        .expect("x-goog-credential to be valid field name"),
                    policy_document::Value::new(x_goog_credential.clone()),
                ));
                if let Some(x_goog_custom_time) = self.x_goog_custom_time.as_ref() {
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new("x-goog-custom-time")
                            .expect("x-goog-custom-time to be valid field name"),
                        policy_document::Value::new(x_goog_custom_time),
                    ));
                }
                conditions.push(policy_document::Condition::ExactMatching(
                    policy_document::Field::new("x-goog-date")
                        .expect("x-goog-date to be valid field name"),
                    policy_document::Value::new(x_goog_date.clone()),
                ));
                // `x-goog-signature` field is not included in the policy document
                for (name, value) in &self.x_goog_meta {
                    if name.is_empty() {
                        return Err(Error::from(ErrorKind::XGoogMetaNameEmpty));
                    }
                    conditions.push(policy_document::Condition::ExactMatching(
                        policy_document::Field::new(format!("x-goog-meta-{}", name))
                            .expect("x-goog-meta-* to be valid field name"),
                        policy_document::Value::new(value),
                    ));
                }
                // `file` field is not included in the policy document
                let policy_document = policy_document::PolicyDocument {
                    conditions,
                    expiration,
                };

                let policy = serde_json::to_string(&policy_document)
                    .map_err(|_| ErrorKind::PolicyDocumentSerialization)?;
                let encoded_policy = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    policy.as_bytes(),
                );
                let message = encoded_policy.as_str();
                let message_digest = signing_key.sign(*use_sign_blob, message.as_bytes()).await?;
                let x_goog_signature = hex_encode(&message_digest);
                Ok((
                    Some(encoded_policy),
                    Some(x_goog_algorithm.to_string()),
                    Some(x_goog_credential),
                    Some(x_goog_date),
                    Some(x_goog_signature),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_only() -> Result<(), Error> {
        let form_data = HtmlFormData::builder()
            .key("example-object")
            .build()
            .await?;
        assert_eq!(
            form_data.into_vec(),
            vec![("key".to_string(), "example-object".to_string())]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_key_not_found() {
        assert_eq!(
            HtmlFormData::builder()
                .build()
                .await
                .unwrap_err()
                .to_string(),
            "key not found"
        );
    }

    #[tokio::test]
    async fn test_x_goog_meta_name_empty() {
        assert_eq!(
            HtmlFormData::builder()
                .key("example-object")
                .x_goog_meta("", "value")
                .build()
                .await
                .unwrap_err()
                .to_string(),
            "x-goog-meta-* field name is empty"
        );
    }

    #[tokio::test]
    async fn test_when_policy_is_false() -> anyhow::Result<()> {
        let form_data = HtmlFormData::builder()
            .acl("public-read")
            .bucket("example-bucket")
            .cache_control("max-age=3600")
            .content_disposition("attachment")
            .content_encoding("gzip")
            .content_length(1024)
            .content_type("application/octet-stream")
            .expires("2022-01-01T00:00:00Z")
            .key("example-object")
            //     .policy(true)
            .success_action_redirect("https://example.com/success")
            .success_action_status(201)
            //     .x_goog_algorithm("GOOG4-RSA-SHA256")
            //     .x_goog_credential("example-credential")
            .x_goog_custom_time("2022-01-01T00:00:00Z")
            //     .x_goog_date("2022-01-01T00:00:00Z")
            .x_goog_meta("reviewer", "jane")
            .x_goog_meta("project-manager", "john")
            .build()
            .await?;
        assert_eq!(
            form_data.into_vec(),
            vec![
                ("acl".to_string(), "public-read".to_string()),
                ("bucket".to_string(), "example-bucket".to_string()),
                ("Cache-Control".to_string(), "max-age=3600".to_string()),
                ("Content-Disposition".to_string(), "attachment".to_string()),
                ("Content-Encoding".to_string(), "gzip".to_string()),
                ("Content-Length".to_string(), "1024".to_string()),
                (
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string()
                ),
                ("Expires".to_string(), "2022-01-01T00:00:00Z".to_string()),
                ("key".to_string(), "example-object".to_string()),
                (
                    "success_action_redirect".to_string(),
                    "https://example.com/success".to_string()
                ),
                ("success_action_status".to_string(), "201".to_string()),
                (
                    "x-goog-custom-time".to_string(),
                    "2022-01-01T00:00:00Z".to_string()
                ),
                ("x-goog-meta-reviewer".to_string(), "jane".to_string()),
                (
                    "x-goog-meta-project-manager".to_string(),
                    "john".to_string()
                )
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_when_policy_is_true() -> anyhow::Result<()> {
        let client_email = "test@example.com".to_string();
        let private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQChK9QyIk4mpcaO\nxXY+DIb8xsJKXfqAgzsboG/Ho8W9C6NZwM0+7kuV39QrP+UGo5GTpKfe3gZYQMoP\nHIAirNMa/K3/8oczucts+ZueWzCdElZ0+E04BLRkWNUM86hQ0TIL+jCi83JZHaGY\npjgMSUUDj+vJc5QjYmu2zGHAsWvBUfIQc6/Am+shtQG1gPpxTKlXS117pIzlAz8Z\nahRKJHn33fpBudYYDKm1fsyCFPS05rBBvjrvGNsGJn/6rRb8+ixVr6LOipSZ5KbS\n+/kvxQSTa7nKKqCoK1fUp+k489IL0XWW4z5PrBNNBjE0oQ3yfnkVW/LBNsrFjT6x\nAOKis8QZAgMBAAECggEABVuCHbqDM4iuLX/F2vEqqYtn2PX/xjbWh6gRHydEAvE4\nmFqu1+ku7Qf4MwnYMJzOUYSXKfLibhuVO+RcJArvp4V/uTLUKLWD3Bb+A8kPOCFs\na033ryWE45MKXfhZf3o8uiYyaLBD/E9eWEcqNMpYt3IYyeUEJxr17qkjlLaxGMd1\nixQdDSS8d48EyMg8RaA2q5l5sG5CoxeEFX7BR3SCjqNS8lzZcQ70mdJjtbmRd7st\nggbcZzd8C2XlT5QFSAEge0uRHEo2d48o09PkTAT4AfsjlYmAhAL1ph0fVPdnXSVk\ng/8u8BGM3WwBIL3jmV/uy5dDmLCv7XwsWxBEnmbwKQKBgQDTbq6QiA+lvLIlpUpA\nmRgWvpHRNv5axSmN77RDcrm96GUrXyLakDmZ/NiAp727RRMcsDkxhTnav/gcQwUC\nl9wCT8ItT32e23HxyQ4kkejrMGtsQyxqd3gN0QzkgAwWQPJMf4vgXOL50lB9Dos1\n5G2p7aUHTLVHqK602S5LbntFhQKBgQDDJPQrlpUhV6zb+B8ZhAJ6SyZUhQ0+81qk\nDxzXdMpUR6gYxzvB5thUqxP9dXuSW7b+L8Pa7ayOxXQqyS+HYKnFJfGkSG2kZMWB\n+zbZgPq1Nq6QyELGFQd3t7g6AOmTL6q7K/D2ghfIGwL2R3TuDrVOW/EQ8mMBAbZP\nLT1FKRvuhQKBgEnBnKfSrxK0BrlXNdXfEiYtCJUhSA3GJb7b1diJlv4GqfQ9Vd1E\n3rM3HxeSbH99kzM4zlrWDN6ghR7mykKjUx6DUEuaJUpbZx5fcs2TENuqom676Cyj\nzH+VY5f6izzgHyZMgDEedheMJIPbpPiB3TegLSekvMBoublg4eNygRI5AoGBALKo\nQmMlmaLNAhThNJfHo/0SkCURKu9XHMTWkTEwW4yNjfghbzQ2hBgACG0kAd4c2Ywd\nbtIghrqvS4tgZYMrnEJCWths9vRqzegSdkTrMJx3U5p5vahb2FpieOehrjZyjXyO\n3izRLbSmBjAze3n3PUZgJnO9daaWSrJyWIXY/RmBAoGBAJasPa2BUV5dg/huiLDE\nnjhWxr2ezceoSxNyhLgmpS2vrBtJWWE4pRVZgJPqbXwMsSfjQqSGp0QWWJ1KHpIv\nn32eCAbgj/9wrwoU9u3cEA4BhYHjg3p9empYdLMJgeLAvKpUbvKbEkZITDFtkWis\njI3VAsh2OHCsO8ToNwX3Kgku\n-----END PRIVATE KEY-----\n".to_string();
        let form_data = HtmlFormData::builder()
            .acl("public-read")
            .bucket("example-bucket")
            .cache_control("max-age=3600")
            .content_disposition("attachment")
            .content_encoding("gzip")
            .content_length(1024)
            .content_type("application/octet-stream")
            .expires("2022-01-04T00:00:00Z")
            .key("example-object")
            .success_action_redirect("https://example.com/success")
            .success_action_status(201)
            .x_goog_custom_time("2022-01-03T00:00:00Z")
            .x_goog_meta("reviewer", "jane")
            .x_goog_meta("project-manager", "john")
            .policy_document_signing_options(PolicyDocumentSigningOptions {
                accessible_at: Some(
                    UnixTimestamp::from_rfc3339("2022-01-01T00:00:00Z")?.to_system_time(),
                ),
                expiration: UnixTimestamp::from_rfc3339("2022-01-02T00:00:00Z")?.to_system_time(),
                region: None,
                signing_key: SigningKey::service_account(client_email, private_key),
                use_sign_blob: false,
            })
            .build()
            .await?;
        assert_eq!(
          form_data.into_vec(),
          [
            ("acl", "public-read"),
            ("bucket", "example-bucket"),
            ("Cache-Control", "max-age=3600"),
            ("Content-Disposition", "attachment"),
            ("Content-Encoding", "gzip"),
            ("Content-Length", "1024"),
            ("Content-Type", "application/octet-stream"),
            ("Expires", "2022-01-04T00:00:00Z"),
            ("key", "example-object"),
            ("policy", "eyJjb25kaXRpb25zIjpbWyJlcSIsIiRhY2wiLCJwdWJsaWMtcmVhZCJdLFsiZXEiLCIkYnVja2V0IiwiZXhhbXBsZS1idWNrZXQiXSxbImVxIiwiJENhY2hlLUNvbnRyb2wiLCJtYXgtYWdlPTM2MDAiXSxbImVxIiwiJENvbnRlbnQtRGlzcG9zaXRpb24iLCJhdHRhY2htZW50Il0sWyJlcSIsIiRDb250ZW50LUVuY29kaW5nIiwiZ3ppcCJdLFsiY29udGVudC1sZW5ndGgtcmFuZ2UiLDEwMjQsMTAyNF0sWyJlcSIsIiRDb250ZW50LVR5cGUiLCJhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0iXSxbImVxIiwiJEV4cGlyZXMiLCIyMDIyLTAxLTA0VDAwOjAwOjAwWiJdLFsiZXEiLCIka2V5IiwiZXhhbXBsZS1vYmplY3QiXSxbImVxIiwiJHN1Y2Nlc3NfYWN0aW9uX3JlZGlyZWN0IiwiaHR0cHM6Ly9leGFtcGxlLmNvbS9zdWNjZXNzIl0sWyJlcSIsIiRzdWNjZXNzX2FjdGlvbl9zdGF0dXMiLCIyMDEiXSxbImVxIiwiJHgtZ29vZy1hbGdvcml0aG0iLCJHT09HNC1SU0EtU0hBMjU2Il0sWyJlcSIsIiR4LWdvb2ctY3JlZGVudGlhbCIsInRlc3RAZXhhbXBsZS5jb20vMjAyMjAxMDEvYXV0by9zdG9yYWdlL2dvb2c0X3JlcXVlc3QiXSxbImVxIiwiJHgtZ29vZy1jdXN0b20tdGltZSIsIjIwMjItMDEtMDNUMDA6MDA6MDBaIl0sWyJlcSIsIiR4LWdvb2ctZGF0ZSIsIjIwMjIwMTAxVDAwMDAwMFoiXSxbImVxIiwiJHgtZ29vZy1tZXRhLXJldmlld2VyIiwiamFuZSJdLFsiZXEiLCIkeC1nb29nLW1ldGEtcHJvamVjdC1tYW5hZ2VyIiwiam9obiJdXSwiZXhwaXJhdGlvbiI6IjIwMjItMDEtMDJUMDA6MDA6MDBaIn0="),
            ("success_action_redirect", "https://example.com/success"),
            ("success_action_status", "201"),
            ("x-goog-algorithm", "GOOG4-RSA-SHA256"),
            ("x-goog-credential", "test@example.com/20220101/auto/storage/goog4_request"),
            ("x-goog-custom-time", "2022-01-03T00:00:00Z"),
            ("x-goog-date", "20220101T000000Z"),
            ("x-goog-signature", "0ac0d149c7385dddd8abb7e002ccf35479409b858bedaed2378a87d714d4e68e28eb683c73a5a661372d834a658784a4ccc16f49a0cea8dbfb89e56dd53a98db6d9af0294bfde4a205c8686a3acd35d39ed1f35598ea61f4d339f9f0e6b10a5c26f64094f137e368e78739c837dbfbf6940ce55cf26b86f195bb7277292682cf2ad5b9a1dd452036f969e9c4260c5b0371439ef57f2cc4433354edccb7a71cee29ebfb4ead8b1fddc4faf598bde637f70936052fd37cd3bc1317e39a54381c8f65fb17493130abf3d98323a4c55cdc7f29b1d9a2f1eed08017c36202c8c48550c011a243c22724054ae32b82c86d426fe6db0053fe437fe0af0be44c2869f17f"),
            ("x-goog-meta-reviewer", "jane"),
            ("x-goog-meta-project-manager", "john")
          ].into_iter().map(|(n, v)| (n.to_string(), v.to_string())).collect::<Vec<(String, String)>>()
        );
        Ok(())
    }
}
