#[derive(serde::Deserialize)]
struct CreateImageRequestBody {
    content_length: u64,
    content_type: String,
}

#[derive(serde::Serialize)]
struct CreateImageResponseBody {
    form_data: Vec<(String, String)>,
    method: String,
    url: String,
}

async fn create_image(
    axum::extract::State(AppState {
        config:
            Config {
                bucket_name,
                signing_key,
                use_sign_blob,
            },
        images,
    }): axum::extract::State<AppState>,
    axum::extract::Json(CreateImageRequestBody {
        content_length,
        content_type,
    }): axum::extract::Json<CreateImageRequestBody>,
) -> Result<axum::Json<CreateImageResponseBody>, axum::http::StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();

    // create form_data
    let method = "POST".to_string();
    let url = format!("https://storage.googleapis.com/{}", bucket_name);
    let form_data = cloud_storage_signature::HtmlFormData::builder()
        .bucket(bucket_name)
        .content_length(content_length)
        .content_type(content_type)
        .key(id.clone())
        .policy_document_signing_options(cloud_storage_signature::PolicyDocumentSigningOptions {
            accessible_at: None,
            expiration: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            region: None,
            signing_key,
            use_sign_blob,
        })
        .build()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .into_vec();

    // update AppState::images
    let mut images = images
        .lock()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    images.push(Image {
        id,
        uploaded: false,
    });

    Ok(axum::Json(CreateImageResponseBody {
        form_data,
        method,
        url,
    }))
}

async fn list_images(
    axum::extract::State(AppState {
        config:
            Config {
                bucket_name,
                signing_key,
                use_sign_blob,
            },
        images,
    }): axum::extract::State<AppState>,
) -> Result<axum::Json<Vec<String>>, axum::http::StatusCode> {
    let images = images
        .lock()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .clone();
    let mut signed_urls = vec![];
    for image in images {
        if !image.uploaded {
            continue;
        }
        let signed_url = cloud_storage_signature::build_signed_url(
            cloud_storage_signature::BuildSignedUrlOptions {
                bucket_name: bucket_name.clone(),
                object_name: image.id,
                region: None,
                expires: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                http_method: "GET".to_string(),
                accessible_at: None,
                signing_key: signing_key.clone(),
                use_sign_blob,
            },
        )
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        signed_urls.push(signed_url);
    }
    Ok(axum::Json(signed_urls))
}

#[derive(serde::Deserialize)]
struct UpdateImagePath {
    id: String,
}

async fn update_image(
    axum::extract::State(AppState { images, .. }): axum::extract::State<AppState>,
    axum::extract::Path(UpdateImagePath { id }): axum::extract::Path<UpdateImagePath>,
) -> Result<axum::http::StatusCode, axum::http::StatusCode> {
    let mut images = images
        .lock()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    for image in images.iter_mut() {
        if image.id == id {
            image.uploaded = true;
            break;
        }
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Clone)]
struct AppState {
    config: Config,
    images: std::sync::Arc<std::sync::Mutex<Vec<Image>>>,
}

#[derive(Clone)]
struct Config {
    bucket_name: String,
    signing_key: cloud_storage_signature::SigningKey,
    use_sign_blob: bool,
}

#[derive(Clone)]
struct Image {
    id: String,
    uploaded: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::str::FromStr as _;
    let use_sign_blob = bool::from_str(std::env::var("USE_SIGN_BLOB")?.as_str())?;
    let signing_key = if use_sign_blob {
        cloud_storage_signature::SigningKey::bound_token()
    } else {
        let service_account = cloud_storage_signature::ServiceAccountCredentials::load(
            std::env::var("GOOGLE_APPLICATION_CREDENTIALS")?,
        )?;
        cloud_storage_signature::SigningKey::service_account(
            service_account.client_email,
            service_account.private_key,
        )
    };
    let config = Config {
        bucket_name: std::env::var("BUCKET_NAME")?,
        signing_key,
        use_sign_blob,
    };
    let router = axum::Router::new()
        .route_service("/", tower_http::services::ServeFile::new("index.html"))
        .route(
            "/images",
            axum::routing::get(list_images).post(create_image),
        )
        .route("/images/:id", axum::routing::patch(update_image))
        .with_state(AppState {
            config,
            images: Default::default(),
        });
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
