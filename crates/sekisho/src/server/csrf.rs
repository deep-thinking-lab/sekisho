use argon2::password_hash::Output;
use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) fn matches(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (URL_SAFE_NO_PAD.decode(left), URL_SAFE_NO_PAD.decode(right))
    else {
        return false;
    };
    if left.len() != 32 || right.len() != 32 {
        return false;
    }
    match (Output::new(&left), Output::new(&right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
pub(super) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|s| s.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}
pub(super) fn set_cookie(name: &str, value: &str, path: &str, age: u32, loopback: bool) -> String {
    format!(
        "{name}={value}; HttpOnly; SameSite=Strict; Path={path}; Max-Age={age}{}",
        if loopback { "" } else { "; Secure" }
    )
}
