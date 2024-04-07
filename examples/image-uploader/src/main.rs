use cloud_storage_signature::BuildHtmlFormDataOptions;

#[derive(serde::Deserialize)]
struct CreateImageRequestBody {
    size: u32,
    r#type: String,
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
    }): axum::extract::State<AppState>,
    axum::extract::Json(CreateImageRequestBody { size, r#type }): axum::extract::Json<
        CreateImageRequestBody,
    >,
) -> Result<axum::Json<CreateImageResponseBody>, axum::http::StatusCode> {
    let method = "POST".to_string();
    let url = format!("https://storage.googleapis.com/{}", bucket_name);
    // TODO: Use the size and type to generate the form data.
    println!("size = {}, type = {}", size, r#type);
    let form_data = cloud_storage_signature::build_html_form_data(BuildHtmlFormDataOptions {
        service_account_client_email,
        service_account_private_key,
        bucket_name,
        object_name: uuid::Uuid::new_v4().to_string(),
        region: None,
        expires: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
        accessible_at: None,
    })
    .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::Json(CreateImageResponseBody {
        form_data,
        method,
        url,
    }))
}

#[derive(Clone)]
struct AppState {
    config: Config,
}

#[derive(Clone)]
struct Config {
    bucket_name: String,
    service_account_client_email: String,
    service_account_private_key: String,
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
        .route("/images", axum::routing::post(create_image))
        .with_state(AppState { config });
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await?;
    Ok(())
}
