#[test]
fn test_signing_key_mod() {
    // Exports `signing_key` mod.
    use cloud_storage_signature::signing_key::Error;
    use cloud_storage_signature::signing_key::SigningKey;
    use cloud_storage_signature::SigningKey as ReExportedSigningKey;

    let _: Result<SigningKey, Error> = ReExportedSigningKey::service_account_from_str("");
}

#[tokio::test]
#[serial_test::serial]
async fn test_dont_panic_when_bound_token_and_use_sign_blob_is_false(
) -> Result<(), cloud_storage_signature::html_form_data::Error> {
    use cloud_storage_signature::signing_key::SigningKey;
    use cloud_storage_signature::HtmlFormData;
    use cloud_storage_signature::PolicyDocumentSigningOptions;

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/computeMetadata/v1/instance/service-accounts/default/email",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("info@example.com"))
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"access_token1","expires_in":3600,"token_type":"Bearer"}"#,
        ))
        .mount(&server)
        .await;

    let result = temp_env::with_var(
        "GCE_METADATA_HOST",
        Some(server.address().to_string()),
        || {
            HtmlFormData::builder()
                .bucket("bucket_name1")
                .key("object_name1")
                .policy_document_signing_options(PolicyDocumentSigningOptions {
                    accessible_at: None,
                    expiration: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                    region: None,
                    signing_key: SigningKey::bound_token(),
                    use_sign_blob: false,
                })
                .build()
        },
    )
    .await;

    assert_eq!(
        result.unwrap_err().to_string(),
        "bound token must use sign blob"
    );
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_gce_metadata_host_env() -> Result<(), cloud_storage_signature::html_form_data::Error>
{
    // Add `GCE_METADATA_HOST` environment variable.
    use cloud_storage_signature::signing_key::SigningKey;
    use cloud_storage_signature::HtmlFormData;
    use cloud_storage_signature::PolicyDocumentSigningOptions;

    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/computeMetadata/v1/instance/service-accounts/default/email",
        ))
        .respond_with(wiremock::ResponseTemplate::new(400).set_body_string("info@example.com"))
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"access_token1","expires_in":3600,"token_type":"Bearer"}"#,
        ))
        .mount(&server)
        .await;

    let result = temp_env::with_var(
        "GCE_METADATA_HOST",
        Some(server.address().to_string()),
        || {
            HtmlFormData::builder()
                .bucket("bucket_name1")
                .key("object_name1")
                .policy_document_signing_options(PolicyDocumentSigningOptions {
                    accessible_at: None,
                    expiration: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                    region: None,
                    signing_key: SigningKey::bound_token(),
                    use_sign_blob: true,
                })
                .build()
        },
    )
    .await;

    assert_eq!(result.unwrap_err().to_string(), "bound token authorizer: bound token authorizer error: bound token / email request / status error: 400 info@example.com");

    Ok(())
}

#[test]
fn test_build_signed_url_options_headers() {
    // Add `headers` field to `BuildSignedUrlOptions`.
    // TODO:
}

#[test]
fn test_build_signed_url_options_query_parameters() {
    // Add `query_parameters` field to `BuildSignedUrlOptions`.
    // TODO:
}
