use axum::{
    body::Body,
    extract::Extension,
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;
use std::sync::Arc;

use argon2::{password_hash::PasswordVerifier, Argon2, PasswordHash};

use crate::master_password::MasterAuth;

pub async fn master_auth_middleware(
    Extension(master): Extension<Arc<MasterAuth>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let authorized = if let Some(auth) = auth_header {
        if auth.starts_with("Basic ") {
            let encoded = &auth[6..];
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                    let supplied_password = if parts.len() == 2 { parts[1] } else { "" };
                    if let Ok(parsed_hash) = PasswordHash::new(&master.hash) {
                        let argon2 = Argon2::default();
                        argon2
                            .verify_password(supplied_password.as_bytes(), &parsed_hash)
                            .is_ok()
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
        // Explain that only the master password matters; username is ignored.
        headers.insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"SnpGuard Management (enter master password; username ignored)\""
                .parse()
                .unwrap(),
        );
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"SnpGuard Management\"")
            .body(Body::from("Unauthorized - use any username and the master password"))
            .unwrap()
    }
}
