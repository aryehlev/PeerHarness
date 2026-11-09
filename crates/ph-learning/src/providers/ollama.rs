//! Ollama-compatible HTTP provider (`POST /api/generate`), loopback only by default.

use std::net::IpAddr;
use std::time::Duration;

use serde_json::{json, Value};
use ureq::http::Uri;

use super::{
    sanitize_output, validate_model, AdvisoryRequest, AdvisoryResponse, AgentProvider,
    ProviderError, DEFAULT_TIMEOUT_SECS, MAX_OUTPUT_BYTES,
};

/// A validated Ollama endpoint.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OllamaEndpoint {
    /// Canonical `http://host[:port]` with no trailing slash, rebuilt from the parsed
    /// host and port (never the raw configured string). `localhost` is pinned to
    /// `127.0.0.1` so name resolution cannot redirect a "local" request.
    pub base: String,
    /// Whether the host is a loopback address (`127.0.0.0/8`, `::1`, an IPv4-mapped
    /// loopback, or the name `localhost`).
    pub is_loopback: bool,
}

/// Validates an Ollama base URL.
///
/// Accepted: `http://<host>[:port][/]` with no user info, query or fragment, and no path
/// other than `/`. The port, when present, must be 1-65535 in plain decimal. `https` is
/// refused (this build has no TLS). A non-loopback host is refused with
/// [`ProviderError::NonLoopback`] unless `allow_non_loopback`. The check is on the
/// literal host: only loopback IP literals and `localhost` (which is then connected to
/// as `127.0.0.1`) count as loopback; any other name, and any IP spelling that is not a
/// standard literal (`0177.0.0.1`, `2130706433`), is non-loopback.
pub fn check_endpoint(
    url: &str,
    allow_non_loopback: bool,
) -> Result<OllamaEndpoint, ProviderError> {
    let url = url.trim();
    if url.contains('#') {
        return Err(ProviderError::InvalidConfig(
            "ollama_url must be a base URL without path, query or fragment",
        ));
    }
    let uri: Uri = url
        .parse()
        .map_err(|_| ProviderError::InvalidConfig("ollama_url is not a valid URL"))?;
    match uri.scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("http") => {}
        Some(s) if s.eq_ignore_ascii_case("https") => {
            return Err(ProviderError::InvalidConfig(
                "ollama_url must use http (https is not supported in this build)",
            ))
        }
        _ => {
            return Err(ProviderError::InvalidConfig(
                "ollama_url must start with http://",
            ))
        }
    }
    let authority = uri
        .authority()
        .ok_or(ProviderError::InvalidConfig("ollama_url has no host"))?;
    if authority.as_str().contains('@') {
        return Err(ProviderError::InvalidConfig(
            "ollama_url must not contain credentials",
        ));
    }
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err(ProviderError::InvalidConfig(
            "ollama_url must be a base URL without path, query or fragment",
        ));
    }
    let host = authority.host();
    // Parse the port text ourselves: `http::Uri` drops out-of-range ports silently and
    // accepts an empty one ("host:").
    let port = match authority.as_str().get(host.len()..) {
        Some("") => None,
        Some(rest) => {
            let digits = rest.strip_prefix(':').unwrap_or("");
            let valid = !digits.is_empty()
                && digits.len() <= 5
                && !digits.starts_with('0')
                && digits.bytes().all(|b| b.is_ascii_digit());
            match digits.parse::<u16>() {
                Ok(n) if valid && n != 0 => Some(n),
                _ => {
                    return Err(ProviderError::InvalidConfig(
                        "ollama_url port must be 1-65535",
                    ))
                }
            }
        }
        None => {
            return Err(ProviderError::InvalidConfig(
                "ollama_url is not a valid URL",
            ))
        }
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.is_empty() {
        return Err(ProviderError::InvalidConfig("ollama_url has no host"));
    }
    let (canonical_host, is_loopback) = if bare.eq_ignore_ascii_case("localhost") {
        ("127.0.0.1".to_owned(), true)
    } else {
        match bare.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => (v4.to_string(), v4.is_loopback()),
            Ok(IpAddr::V6(v6)) => (
                format!("[{v6}]"),
                v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
            ),
            Err(_) => (bare.to_ascii_lowercase(), false),
        }
    };
    if !is_loopback && !allow_non_loopback {
        return Err(ProviderError::NonLoopback);
    }
    let base = match port {
        Some(p) => format!("http://{canonical_host}:{p}"),
        None => format!("http://{canonical_host}"),
    };
    Ok(OllamaEndpoint { base, is_loopback })
}

/// Talks to an Ollama-compatible endpoint with
/// `POST {base}/api/generate {"model", "prompt", "stream": false}` and returns the
/// `response` field.
///
/// The HTTP client ignores proxy environment variables, follows no redirects, enforces
/// the timeout for the whole exchange and caps the body at [`MAX_OUTPUT_BYTES`].
/// `is_remote()` is `true` only for a non-loopback host allowed by configuration.
#[derive(Clone, Debug)]
pub struct OllamaLocal {
    endpoint: OllamaEndpoint,
    model: String,
    timeout: Duration,
}

impl OllamaLocal {
    /// Validates `url` (see [`check_endpoint`]) and `model` (see [`validate_model`]).
    pub fn new(url: &str, model: &str, allow_non_loopback: bool) -> Result<Self, ProviderError> {
        let endpoint = check_endpoint(url, allow_non_loopback)?;
        validate_model(model)?;
        Ok(Self {
            endpoint,
            model: model.to_owned(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        })
    }

    /// Sets the timeout for one completion.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The validated endpoint.
    pub fn endpoint(&self) -> &OllamaEndpoint {
        &self.endpoint
    }

    fn map_err(&self, e: ureq::Error) -> ProviderError {
        match e {
            ureq::Error::StatusCode(c) => ProviderError::HttpStatus(c),
            ureq::Error::Timeout(_) => ProviderError::Timeout {
                secs: self.timeout.as_secs().max(1),
            },
            ureq::Error::BodyExceedsLimit(_) => ProviderError::OutputTooLarge {
                max: MAX_OUTPUT_BYTES,
            },
            ureq::Error::HostNotFound => ProviderError::Transport("host not found"),
            ureq::Error::ConnectionFailed => ProviderError::Transport("connection failed"),
            ureq::Error::Io(io) => ProviderError::Io(io.kind()),
            ureq::Error::Json(_) => ProviderError::Malformed("not JSON"),
            _ => ProviderError::Transport("request failed"),
        }
    }
}

impl AgentProvider for OllamaLocal {
    fn name(&self) -> &str {
        "ollama"
    }

    fn is_remote(&self) -> bool {
        !self.endpoint.is_loopback
    }

    fn disclosure(&self) -> String {
        if self.is_remote() {
            "REMOTE: this text will be sent over plain HTTP to a non-loopback Ollama-compatible \
             endpoint you configured."
                .to_owned()
        } else {
            "Local: this text is sent only to the Ollama-compatible endpoint on this machine \
             (loopback)."
                .to_owned()
        }
    }

    fn complete(&self, req: &AdvisoryRequest) -> Result<AdvisoryResponse, ProviderError> {
        let payload = req.exact_payload();
        let config = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(true)
            .timeout_global(Some(self.timeout))
            .build();
        let agent = ureq::Agent::new_with_config(config);
        tracing::debug!(
            provider = "ollama",
            remote = self.is_remote(),
            payload_bytes = payload.len(),
            "sending advisory request"
        );
        let body = json!({ "model": self.model, "prompt": payload, "stream": false });
        let mut resp = agent
            .post(format!("{}/api/generate", self.endpoint.base))
            .send_json(&body)
            .map_err(|e| self.map_err(e))?;
        if !resp.status().is_success() {
            return Err(ProviderError::HttpStatus(resp.status().as_u16()));
        }
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(MAX_OUTPUT_BYTES as u64)
            .read_to_vec()
            .map_err(|e| self.map_err(e))?;
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|_| ProviderError::Malformed("not JSON"))?;
        if v.get("error").is_some() {
            return Err(ProviderError::Reported);
        }
        let text = match v.get("response") {
            Some(Value::String(s)) => sanitize_output(s),
            _ => return Err(ProviderError::Malformed("missing response")),
        };
        if text.is_empty() {
            return Err(ProviderError::Malformed("empty response"));
        }
        Ok(AdvisoryResponse {
            text,
            provider: self.name().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_rules() {
        for ok in [
            "http://127.0.0.1:11434",
            "http://127.0.0.1:11434/",
            "http://127.1.2.3:80",
            "http://localhost:11434",
            "http://LOCALHOST",
            "http://[::1]:11434",
            "http://[::ffff:127.0.0.1]:11434",
        ] {
            let e = check_endpoint(ok, false).unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert!(e.is_loopback, "{ok}");
            assert!(!e.base.ends_with('/'));
        }
        // The base is rebuilt canonically; localhost is pinned to 127.0.0.1.
        let base = |u: &str| check_endpoint(u, false).unwrap().base;
        assert_eq!(base("http://localhost:11434"), "http://127.0.0.1:11434");
        assert_eq!(base("HTTP://LocalHost/"), "http://127.0.0.1");
        assert_eq!(base(" http://127.0.0.1:11434/\n"), "http://127.0.0.1:11434");
        assert_eq!(base("http://[::1]:11434"), "http://[::1]:11434");
        assert_eq!(
            base("http://[::ffff:7f00:1]:1"),
            "http://[::ffff:127.0.0.1]:1"
        );
        assert_eq!(
            check_endpoint("http://Example.COM:8080", true)
                .unwrap()
                .base,
            "http://example.com:8080"
        );
        for remote in [
            "http://10.0.0.5:11434",
            "http://192.168.1.2",
            "http://example.com:11434",
            "http://localhost.:11434",
            "http://127.0.0.1.nip.io",
            "http://127.0.0.1.evil.com:11434",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://0x7f.0.0.1",
            "http://[fe80::1%25lo0]:1",
            "http://[::2]:1",
            "http://0.0.0.0:11434",
        ] {
            assert!(
                matches!(
                    check_endpoint(remote, false),
                    Err(ProviderError::NonLoopback)
                ),
                "{remote}"
            );
            let e = check_endpoint(remote, true).unwrap();
            assert!(!e.is_loopback);
        }
        for bad in [
            "https://127.0.0.1:11434",
            "ftp://127.0.0.1",
            "127.0.0.1:11434",
            "http://user:pw@127.0.0.1:11434",
            "http://127.0.0.1:11434/api",
            "http://127.0.0.1:11434/?x=1",
            "http://127.0.0.1:11434#frag",
            "http://127.0.0.1:",
            "http://127.0.0.1:0",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:+80",
            "http://127.0.0.1:011434",
            "http://127.0.0.1:11434@evil.com",
            "http://127.0.0.1\\@evil.com",
            "http://127.0.0.1%40evil.com",
            "http://127.0.0.1 .evil.com",
            "http://evil.com/127.0.0.1",
            "http:/127.0.0.1",
            "",
            "not a url",
        ] {
            assert!(
                matches!(
                    check_endpoint(bad, true),
                    Err(ProviderError::InvalidConfig(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn remote_flag_follows_endpoint() {
        let local = OllamaLocal::new("http://127.0.0.1:11434", "llama3.2", false).unwrap();
        assert!(!local.is_remote());
        let remote = OllamaLocal::new("http://10.1.2.3:11434", "llama3.2", true).unwrap();
        assert!(remote.is_remote());
        assert!(remote.disclosure().starts_with("REMOTE"));
        assert!(OllamaLocal::new("http://127.0.0.1:11434", "-x", false).is_err());
    }
}
