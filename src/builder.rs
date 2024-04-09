#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct Error(#[from] ErrorKind);

#[derive(Debug, thiserror::Error)]
enum ErrorKind {
    #[error("key not found")]
    KeyNotFound,
    #[error("x-goog-meta-* field name is empty")]
    XGoogMetaNameEmpty,
}

#[derive(Clone, Debug)]
struct HtmlFormData(Vec<(String, String)>);

impl HtmlFormData {
    pub fn builder() -> HtmlFormDataBuilder {
        HtmlFormDataBuilder::default()
    }

    pub fn into_vec(self) -> Vec<(String, String)> {
        self.0
    }
}

#[derive(Default)]
struct HtmlFormDataBuilder {
    acl: Option<String>,
    bucket: Option<String>,
    cache_control: Option<String>,
    content_disposition: Option<String>,
    content_encoding: Option<String>,
    content_length: Option<u64>,
    content_type: Option<String>,
    expires: Option<String>,
    // `file` field is not included.
    key: Option<String>,
    policy: bool,
    success_action_redirect: Option<String>,
    success_action_status: Option<u16>,
    x_goog_algorithm: Option<String>,
    x_goog_credential: Option<String>,
    x_goog_custom_time: Option<String>,
    x_goog_date: Option<String>,
    // `x-goog-signature` field is not included.
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
    pub fn build(self) -> Result<HtmlFormData, Error> {
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
        if self.policy {
            todo!("policy support")
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
        // TODO: x-goog-algorithm
        // TODO: x-goog-credential
        if let Some(x_goog_custom_time) = self.x_goog_custom_time {
            vec.push(("x-goog-custom-time".to_string(), x_goog_custom_time));
        }
        // TODO: x-goog-date
        // TODO: x-goog-signature
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

    /// Sets the `policy` field.
    pub fn policy(mut self, use_policy: bool) -> Self {
        self.policy = use_policy;
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

    /// Sets the `x-goog-algorithm` field.
    pub fn x_goog_algorithm(mut self, x_goog_algorithm: impl Into<String>) -> Self {
        self.x_goog_algorithm = Some(x_goog_algorithm.into());
        self
    }

    /// Sets the `x-goog-credential` field.
    pub fn x_goog_credential(mut self, x_goog_credential: impl Into<String>) -> Self {
        self.x_goog_credential = Some(x_goog_credential.into());
        self
    }

    /// Sets the `x-goog-custom-time` field.
    pub fn x_goog_custom_time(mut self, x_goog_custom_time: impl Into<String>) -> Self {
        self.x_goog_custom_time = Some(x_goog_custom_time.into());
        self
    }

    /// Sets the `x-goog-date` field.
    pub fn x_goog_date(mut self, x_goog_date: impl Into<String>) -> Self {
        self.x_goog_date = Some(x_goog_date.into());
        self
    }

    /// Sets the `x-goog-meta-*` field.
    pub fn x_goog_meta(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.x_goog_meta.push((name.into(), value.into()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_only() -> Result<(), Error> {
        let form_data = HtmlFormData::builder().key("example-object").build()?;
        assert_eq!(
            form_data.into_vec(),
            vec![("key".to_string(), "example-object".to_string())]
        );
        Ok(())
    }

    #[test]
    fn test_key_not_found() {
        assert_eq!(
            HtmlFormData::builder().build().unwrap_err().to_string(),
            "key not found"
        );
    }

    #[test]
    fn test_x_goog_meta_name_empty() {
        assert_eq!(
            HtmlFormData::builder()
                .key("example-object")
                .x_goog_meta("", "value")
                .build()
                .unwrap_err()
                .to_string(),
            "x-goog-meta-* field name is empty"
        );
    }

    #[test]
    fn test_no_policy() -> anyhow::Result<()> {
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
            .build()?;
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
}
