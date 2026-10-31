use crate::{
    results::{Observation, Outcome},
    settings::HttpSettings,
    vectors::{registry::Backend, TestContext},
};
use anyhow::{ensure, Context, Result};
use std::time::Duration;

pub(crate) fn correlation_id(backend: Backend, run_id: &str, sequence: u64) -> Option<String> {
    // These backends use one reqwest request. Fixed-header and multi-request
    // backends retain their contracts and are explicitly outside this evidence.
    (backend.is_http()
        && !matches!(
            backend,
            Backend::HttpTrace | Backend::HttpConnect | Backend::HttpReuse | Backend::Http3Get
        ))
    .then(|| format!("{run_id}-{sequence}"))
}

fn add_correlation_header(
    request: reqwest::RequestBuilder,
    id: Option<&str>,
) -> reqwest::RequestBuilder {
    match id {
        Some(id) => request.header("x-isradar-probe", id),
        None => request,
    }
}

pub(crate) async fn execute(backend: Backend, context: &TestContext) -> Result<Observation> {
    backend.validate_options(&context.protocol)?;
    let target = context.target.as_ref().context("HTTP target required")?;
    let settings = context.protocol.http.clone().unwrap_or_default();
    if backend == Backend::Http3Get {
        return super::http3::execute(context, &settings).await;
    }
    if backend == Backend::HttpReuse {
        return super::sessions::reuse_http(context, &settings).await;
    }
    if matches!(backend, Backend::HttpSlowHeaders | Backend::HttpSlowBody) {
        return super::sessions::slow_http(backend, context, &settings).await;
    }
    let method = reqwest::Method::from_bytes(
        backend
            .http_method()
            .context("HTTP method required")?
            .as_bytes(),
    )?;
    let https = matches!(backend, Backend::HttpsGet | Backend::HttpsHead);
    let mut url = reqwest::Url::parse(&super::http_url(target, https))?;
    url.set_path(&settings.path);
    if backend == Backend::HttpConnect {
        url = reqwest::Url::parse(&format!("http://{}/", target.address()))?;
    }
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(context.timeout_ms))
        .pool_max_idle_per_host(0)
        .user_agent("isradar-external-agent/0.1 authorized-validation");
    builder = if backend == Backend::Http2Get {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    };
    if let Some(name) = &target.server_name {
        builder = builder.resolve(name, target.address());
    }
    if let Some(ca) = &context.protocol.tls_ca {
        builder = builder.add_root_certificate(reqwest::Certificate::from_der(&ca.read_der()?)?);
    }
    let client = builder.build()?;
    let mut request = client.request(method, url);
    for (name, value) in &settings.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    request = add_correlation_header(request, context.http_request_id.as_deref());
    if matches!(backend, Backend::HttpTrace | Backend::HttpOptions) {
        request = request.header("Max-Forwards", "0");
    }
    if !settings.body.is_empty() {
        request = request
            .header("Content-Type", "application/octet-stream")
            .body(settings.body.clone());
    }
    let response = request.send().await?;
    ensure!(
        backend != Backend::Http2Get || response.version() == reqwest::Version::HTTP_2,
        "HTTP/2 was not negotiated"
    );
    let code = response.status().as_u16();
    let mut value = observe_response(backend, &settings, code, response.headers());
    if backend == Backend::Http2Get && value.outcome == Outcome::Success {
        value.detail = "HTTP/2 response headers/status observed; body not downloaded".into();
    }
    value.tcp_handshake_success = true;
    value.protocol_details.insert(
        "http_version".into(),
        format!("{:?}", response.version()).into(),
    );
    value.protocol_details.insert(
        "http_method".into(),
        backend.http_method().unwrap_or("?").into(),
    );
    value
        .protocol_details
        .insert("http_path".into(), settings.path.clone().into());
    if backend == Backend::HttpConnect {
        value.protocol_details.insert(
            "connect_authority".into(),
            target.address().to_string().into(),
        );
        if value.outcome == Outcome::Success {
            value.detail="CONNECT policy observed against the configured target's own numeric authority; no tunnel payload sent and no third-party destination allowed".into();
        }
    }
    Ok(value)
}

pub(crate) fn observe_response(
    backend: Backend,
    settings: &HttpSettings,
    code: u16,
    headers: &reqwest::header::HeaderMap,
) -> Observation {
    let mut value = Observation::success(
        "HTTP response headers/status observed; redirect not followed and body not downloaded",
    );
    value.response_received = true;
    value.http_status = Some(code);
    if settings
        .expected_status
        .is_some_and(|expected| expected != code)
        || (settings.expected_status.is_none()
            && (!(200..400).contains(&code) || (backend == Backend::HttpHealth && code != 200)))
    {
        value.outcome = Outcome::RemoteRejection;
    }
    let checked = (|| -> Result<()> {
        let header_bytes = headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
            .sum::<usize>();
        ensure!(
            headers.len() <= 64 && header_bytes <= 4096,
            "HTTP response headers exceed validation cap"
        );
        validate_headers(settings, headers)?;
        if backend == Backend::HttpRedirect {
            ensure!(
                (300..400).contains(&code) && code != 304,
                "expected a redirect response"
            );
            let mut locations = headers.get_all(reqwest::header::LOCATION).iter();
            let location = locations
                .next()
                .context("redirect Location header missing")?
                .to_str()?;
            ensure!(
                locations.next().is_none() && location.len() <= 2048,
                "ambiguous or oversized redirect Location"
            );
            value
                .protocol_details
                .insert("redirect_location".into(), location.into());
        }
        Ok(())
    })();
    if let Err(error) = checked {
        value.outcome = Outcome::ProtocolError;
        value.detail = error.to_string();
    }
    value
}

pub(crate) fn validate_headers(
    settings: &HttpSettings,
    headers: &reqwest::header::HeaderMap,
) -> Result<()> {
    for (name, expected) in &settings.expected_headers {
        let mut values = headers.get_all(name.as_str()).iter();
        let value = values
            .next()
            .with_context(|| format!("expected response header {name} missing"))?
            .to_str()?;
        ensure!(
            value == expected && values.next().is_none(),
            "response header {name} did not match its configured expectation"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn correlation_header_identifies_one_request_and_preserves_signature() {
        let id = correlation_id(Backend::HttpGet, "0123456789abcdef0123456789abcdef", 7).unwrap();
        let client = reqwest::Client::new();
        let request = client
            .get("http://192.0.2.1/")
            .header("user-agent", "BlackSun");
        let request = add_correlation_header(request, Some(&id)).build().unwrap();
        assert_eq!(request.headers()["x-isradar-probe"], id);
        assert_eq!(request.headers()["user-agent"], "BlackSun");
        assert_ne!(
            Some(id),
            correlation_id(Backend::HttpGet, "0123456789abcdef0123456789abcdef", 8)
        );
        assert!(correlation_id(Backend::HttpsGet, "run", 0).is_some());
        for backend in [
            Backend::HttpTrace,
            Backend::HttpConnect,
            Backend::HttpReuse,
            Backend::Http3Get,
            Backend::TcpConnect,
        ] {
            assert!(correlation_id(backend, "run", 0).is_none());
        }
        let settings = HttpSettings {
            headers: [("X-Isradar-Probe".into(), "forged".into())].into(),
            ..Default::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn http_policy_failures_preserve_observed_status_and_response() {
        let settings = HttpSettings {
            expected_headers: [("x-check".into(), "ok".into())].into(),
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        let missing = observe_response(Backend::HttpHeaders, &settings, 200, &headers);
        assert_eq!(missing.outcome, Outcome::ProtocolError);
        assert!(missing.response_received);
        assert_eq!(missing.http_status, Some(200));
        headers.insert("x-check", HeaderValue::from_static("ok"));
        assert_eq!(
            observe_response(Backend::HttpHeaders, &settings, 200, &headers).outcome,
            Outcome::Success
        );
        headers.append("x-check", HeaderValue::from_static("conflicting"));
        assert_eq!(
            observe_response(Backend::HttpHeaders, &settings, 200, &headers).outcome,
            Outcome::ProtocolError
        );
        let settings = HttpSettings::default();
        for backend in [Backend::HttpGet, Backend::Http2Get, Backend::Http3Get] {
            assert_eq!(
                observe_response(backend, &settings, 503, &HeaderMap::new()).outcome,
                Outcome::RemoteRejection
            );
            let expected = HttpSettings {
                expected_status: Some(503),
                ..Default::default()
            };
            assert_eq!(
                observe_response(backend, &expected, 503, &HeaderMap::new()).outcome,
                Outcome::Success
            );
        }
        assert_eq!(
            observe_response(Backend::HttpHealth, &settings, 204, &HeaderMap::new()).outcome,
            Outcome::RemoteRejection
        );
    }

    #[test]
    fn redirects_require_one_location_and_bounded_headers() {
        let settings = HttpSettings::default();
        let mut headers = HeaderMap::new();
        assert_eq!(
            observe_response(Backend::HttpRedirect, &settings, 302, &headers).outcome,
            Outcome::ProtocolError
        );
        headers.insert("location", HeaderValue::from_static("/next"));
        let result = observe_response(Backend::HttpRedirect, &settings, 302, &headers);
        assert_eq!(result.outcome, Outcome::Success);
        assert_eq!(result.protocol_details["redirect_location"], "/next");
        assert_eq!(
            observe_response(Backend::HttpRedirect, &settings, 304, &headers).outcome,
            Outcome::ProtocolError
        );
        headers.append("location", HeaderValue::from_static("/other"));
        assert_eq!(
            observe_response(Backend::HttpRedirect, &settings, 302, &headers).outcome,
            Outcome::ProtocolError
        );
        headers.insert("x-long", HeaderValue::from_str(&"a".repeat(4096)).unwrap());
        assert_eq!(
            observe_response(Backend::HttpGet, &settings, 200, &headers).outcome,
            Outcome::ProtocolError
        );
    }
}
