use crate::{
    results::Observation,
    settings::HttpSettings,
    vectors::{registry::Backend, TestContext},
};
use anyhow::{Context, Result};
use std::{net::SocketAddr, sync::Arc};

struct ProbeSession {
    endpoint: quinn::Endpoint,
    driver: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for ProbeSession {
    fn drop(&mut self) {
        self.endpoint
            .close(0u32.into(), b"validation probe finished");
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

pub(crate) async fn execute(context: &TestContext, settings: &HttpSettings) -> Result<Observation> {
    let target = context.target.as_ref().context("HTTP/3 target required")?;
    let name = target
        .server_name
        .as_ref()
        .context("HTTP/3 requires a configured TLS server_name")?;
    let mut tls = (*super::tls_checks::client_config(Backend::Tls13, &context.protocol)?).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut endpoint = quinn::Endpoint::client(
        if target.ip.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse::<SocketAddr>()?,
    )?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let mut session = ProbeSession {
        endpoint,
        driver: None,
    };
    let connection = session.endpoint.connect(target.address(), name)?.await?;
    let (mut driver, mut sender) = h3::client::builder()
        .max_field_section_size(4096)
        .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(connection))
        .await?;
    session.driver = Some(tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    }));
    let mut url = reqwest::Url::parse(&super::http_url(target, true))?;
    url.set_path(&settings.path);
    let mut request = http::Request::builder()
        .method("GET")
        .uri(url.as_str())
        .header("user-agent", "isradar-external-agent/0.1");
    for (name, value) in &settings.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let mut stream = sender.send_request(request.body(())?).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let code = response.status().as_u16();
    let mut value =
        super::http_checks::observe_response(Backend::Http3Get, settings, code, response.headers());
    value
        .protocol_details
        .insert("transport".into(), "quic".into());
    value
        .protocol_details
        .insert("http_version".into(), "HTTP/3".into());
    value
        .protocol_details
        .insert("tls_certificate_verified".into(), true.into());
    Ok(value)
}
