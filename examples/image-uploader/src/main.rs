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
                service_account_client_email,
                service_account_private_key,
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
    let form_data = cloud_storage_signature::build_html_form_data(
        cloud_storage_signature::BuildHtmlFormDataOptions {
            service_account_client_email,
            service_account_private_key,
            bucket_name,
            object_name: id.clone(),
            region: None,
            expires: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            accessible_at: None,
            content_length: Some(content_length),
            content_type: Some(content_type),
        },
    )
    .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

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
                service_account_client_email,
                service_account_private_key,
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
                service_account_client_email: service_account_client_email.clone(),
                service_account_private_key: service_account_private_key.clone(),
                bucket_name: bucket_name.clone(),
                object_name: image.id,
                region: None,
                expires: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                http_method: "GET".to_string(),
                accessible_at: None,
            },
        )
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
    service_account_client_email: String,
    service_account_private_key: String,
}

#[derive(Clone)]
struct Image {
    id: String,
    uploaded: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service_account = cloud_storage_signature::ServiceAccountCredentials::load(std::env::var(
        "GOOGLE_APPLICATION_CREDENTIALS",
    )?)?;
    let config = Config {
        bucket_name: std::env::var("BUCKET_NAME")?,
        service_account_client_email: service_account.client_email,
        service_account_private_key: service_account.private_key,
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
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await?;
    Ok(())
}
