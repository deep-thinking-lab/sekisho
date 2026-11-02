use anyhow::{Context, Result, ensure};
use std::{net::IpAddr, path::Path, time::Duration};

pub(crate) fn url(home: &Path, path: &str) -> Result<reqwest::Url> {
    let address = crate::up::read_admin_file(&home.join("admin.url"))?;
    let mut url = reqwest::Url::parse(address.trim()).context("invalid local admin URL")?;
    let loopback = url
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    ensure!(
        url.scheme() == "http"
            && loopback
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "local admin URL must be numeric loopback HTTP"
    );
    url.set_path(path);
    Ok(url)
}

/// Read a TOTP code from stdin, prompting when stdin is a terminal. Never from
/// argv, which other processes of the same user can read.
pub(crate) fn read_totp() -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("TOTP code: ");
        std::io::stderr().flush()?;
    }
    let mut code = String::new();
    ensure!(
        stdin.lock().read_line(&mut code)? != 0,
        "a TOTP code from the admin's authenticator app is required on stdin"
    );
    Ok(code.trim().to_owned())
}

pub(crate) async fn request(
    home: &Path,
    method: reqwest::Method,
    path: &str,
) -> Result<reqwest::Response> {
    request_with(home, method, path, None).await
}

pub(crate) async fn request_with(
    home: &Path,
    method: reqwest::Method,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<reqwest::Response> {
    let token = crate::up::read_admin_file(&home.join("admin.token"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let mut request = client.request(method, url(home, path)?).bearer_auth(token);
    if let Some(body) = body {
        request = request.json(body);
    }
    request
        .send()
        .await
        .context("cannot contact local admin server")
}
