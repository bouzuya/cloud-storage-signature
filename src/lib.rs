//! A Cloud Storage signature utils
//!
//! # HTML Form Data
//!
//! [`HtmlFormData`] is a struct that represents a form data for a POST request
//! to upload an object to Google Cloud Storage.
//!
//! <https://cloud.google.com/storage/docs/xml-api/post-object-forms>
//!
//! ```rust
//! # async fn test_readme_html_form_data_example() -> Result<(), cloud_storage_signature::html_form_data::Error>
//! # {
//! use cloud_storage_signature::HtmlFormData;
//! assert_eq!(
//!     HtmlFormData::builder()
//!         .key("object_name1")
//!         .build()
//!         .await?
//!         .into_vec(),
//!     vec![("key".to_string(), "object_name1".to_string())]
//! );
//! #     Ok(())
//! # }
//! ```
//!
//! This form data does not include the `file` field, so you need to add the `file` field to upload a file.
//! See [image-uploader example](https://github.com/bouzuya/cloud-storage-signature/tree/master/examples/image-uploader).
//!
pub mod html_form_data;
mod private;
pub mod signed_url;
mod signing_key;

pub use self::html_form_data::{HtmlFormData, HtmlFormDataBuilder, PolicyDocumentSigningOptions};
pub use self::signed_url::{build_signed_url, BuildSignedUrlOptions};
pub use self::signing_key::SigningKey;
