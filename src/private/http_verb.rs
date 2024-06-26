#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid http verb: {0}")]
    InvalidHttpVerb(String),
}

pub(crate) enum HttpVerb {
    Delete,
    Get,
    Head,
    Post,
    Put,
}

// TODO: Remove this impl
impl std::convert::From<HttpVerb> for http::Method {
    fn from(http_verb: HttpVerb) -> Self {
        match http_verb {
            HttpVerb::Delete => http::Method::DELETE,
            HttpVerb::Get => http::Method::GET,
            HttpVerb::Head => http::Method::HEAD,
            HttpVerb::Post => http::Method::POST,
            HttpVerb::Put => http::Method::PUT,
        }
    }
}

impl std::str::FromStr for HttpVerb {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "DELETE" => Ok(Self::Delete),
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            _ => Err(Error::InvalidHttpVerb(s.to_string()))?,
        }
    }
}
