#[test]
fn test_signing_key_mod() {
    // Exports `signing_key` mod.
    use cloud_storage_signature::signing_key::Error;
    use cloud_storage_signature::signing_key::SigningKey;
    use cloud_storage_signature::SigningKey as ReExportedSigningKey;

    let _: Result<SigningKey, Error> = ReExportedSigningKey::service_account_from_str("");
}
