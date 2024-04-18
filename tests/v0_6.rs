#[test]
fn test_signing_key_mod() {
    // Exports `signing_key` mod.
    use cloud_storage_signature::signing_key::Error;
    use cloud_storage_signature::signing_key::SigningKey;
    use cloud_storage_signature::SigningKey as ReExportedSigningKey;

    let _: Result<SigningKey, Error> = ReExportedSigningKey::service_account_from_str("");
}

#[tokio::test]
async fn test_dont_panic_when_bound_token_and_use_sign_blob_is_false(
) -> Result<(), cloud_storage_signature::html_form_data::Error> {
    use cloud_storage_signature::signing_key::SigningKey;
    use cloud_storage_signature::HtmlFormData;
    use cloud_storage_signature::PolicyDocumentSigningOptions;

    // FIXME: mock `metadata.google.internal`

    let _ = HtmlFormData::builder()
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
        .await?;
    Ok(())
}
