//! The interface files, built from `dashboard-ui/` and compiled into the program so a server
//! needs nothing else. Every other path gets the page, which then shows the right screen.
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use std::sync::OnceLock;

struct File {
    path: &'static str,
    kind: &'static str,
    bytes: &'static [u8],
}

macro_rules! ui {
    ($path:literal, $kind:literal) => {
        File {
            path: concat!("/", $path),
            kind: $kind,
            bytes: include_bytes!(concat!("ui/", $path)),
        }
    };
}

const FILES: &[File] = &[
    ui!("index.html", "text/html; charset=utf-8"),
    ui!("app.js", "text/javascript; charset=utf-8"),
    ui!("app.css", "text/css; charset=utf-8"),
    ui!("favicon.svg", "image/svg+xml"),
    ui!("fonts/Vazirmatn-Regular.woff2", "font/woff2"),
    ui!("fonts/Vazirmatn-Medium.woff2", "font/woff2"),
    ui!("fonts/Vazirmatn-SemiBold.woff2", "font/woff2"),
    ui!("fonts/Vazirmatn-Bold.woff2", "font/woff2"),
];

/// Short content hashes, computed once, so browsers can ask "has it changed?".
fn tags() -> &'static Vec<String> {
    static TAGS: OnceLock<Vec<String>> = OnceLock::new();
    TAGS.get_or_init(|| {
        FILES
            .iter()
            .map(|file| format!("\"{}\"", &blake3::hash(file.bytes).to_hex()[..16]))
            .collect()
    })
}

pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not_found"}))).into_response();
    }
    let index = FILES
        .iter()
        .position(|file| file.path == path)
        .unwrap_or(0);
    let file = &FILES[index];
    let tag = &tags()[index];
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == tag));
    let mut response = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        file.bytes.into_response()
    };
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(file.kind));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(value) = HeaderValue::from_str(tag) {
        headers.insert(header::ETAG, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_comes_first_and_every_file_is_present() {
        assert_eq!(FILES[0].path, "/index.html");
        for file in FILES {
            assert!(!file.bytes.is_empty(), "{} is empty", file.path);
        }
        let page = std::str::from_utf8(FILES[0].bytes).unwrap();
        assert!(page.contains("/app.js") && page.contains("/app.css"));
        assert!(!page.contains("<script>"), "no inline script: the CSP forbids it");
    }
}
