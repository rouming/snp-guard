use axum::{
    http::{header, StatusCode, HeaderMap, Request},
    middleware::Next,
    response::Response,
    body::Body,
};

pub async fn basic_auth_middleware(
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let username = std::env::var("SNPGUARD_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let password = std::env::var("SNPGUARD_PASSWORD").unwrap_or_else(|_| "secret".to_string());
    
    let auth_header = request.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    
    let authorized = if let Some(auth) = auth_header {
        if auth.starts_with("Basic ") {
            let encoded = &auth[6..];
            if let Ok(decoded) = base64::decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                    if parts.len() == 2 && parts[0] == username && parts[1] == password {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };
    
    if authorized {
        next.run(request).await
    } else {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"SnpGuard Management\"".parse().unwrap()
        );
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"SnpGuard Management\"")
            .body(Body::from("Unauthorized"))
            .unwrap()
    }
}
