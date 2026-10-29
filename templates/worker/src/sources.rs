//! The worker's sources: the generic `EchoSource` and `HttpJsonSource`. Add your own here, one type per
//! backend, each with its own read-only credential from this worker's config (never from a call's params).

use std::sync::Arc;
use std::time::Duration;

use ai_env_source::{collect_capped, BoxFuture, CallContext, CallRequest, DataSource, OpDescriptor, Output, Sensitivity, SourceDescriptor, SourceError, SourceKind};
use serde::Deserialize;
use serde_json::json;

use crate::config::SourceConfig;

/// Echoes its text: a source to check the relay path with.
pub struct EchoSource {
    name: String,
}

impl EchoSource {
    /// An echo source named `name`.
    pub fn new(name: impl Into<String>) -> EchoSource {
        EchoSource { name: name.into() }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EchoParams {
    text: String,
}

impl DataSource for EchoSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor::new(self.name.clone(), env!("CARGO_PKG_VERSION"), "Echoes its text.")
            .kind(SourceKind::Other)
            .env("example")
            .sensitivity(Sensitivity::Public)
            .op(OpDescriptor::new("echo", "Answers {\"text\": <text>}.")
                .read_only(true)
                .params_schema(json!({"type":"object","properties":{"text":{"type":"string","maxLength":4096}},"required":["text"],"additionalProperties":false}))
                .example(json!({"text":"hello"})))
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            if req.op != "echo" {
                return Err(SourceError::NotFound(format!("no op {}", req.op)));
            }
            let p: EchoParams = req.params_as()?;
            Ok(Output::json(json!({ "text": p.text })))
        })
    }
}

/// GETs JSON from an HTTP API, under a fixed list of path prefixes.
pub struct HttpJsonSource {
    name: String,
    base_url: String,
    paths: Vec<String>,
    timeout: Duration,
    client: reqwest::Client,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetParams {
    path: String,
}

impl HttpJsonSource {
    /// A source of `base_url`, answering only paths under one of `paths`; `timeout` defaults to 10 s.
    pub fn new(name: impl Into<String>, base_url: impl Into<String>, paths: Vec<String>, timeout: Option<Duration>) -> HttpJsonSource {
        // reqwest's rustls has no provider of its own: aws-lc-rs (main installs it too; a second install is a no-op).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = reqwest::Client::builder().build().expect("an HTTP client with rustls on aws-lc-rs");
        HttpJsonSource { name: name.into(), base_url: base_url.into(), paths, timeout: timeout.unwrap_or(Duration::from_secs(10)), client }
    }

    /// A path the URL parser takes as written: it starts with `/`, holds only printable ASCII (no blank or
    /// control character, which the parser drops) and none of `%` (a percent-encoded `..` is one), `\` (a
    /// `/` for http), `?` or `#`, and no `..`; and one of the configured prefixes matches it on a segment
    /// boundary (`/v1/status` allows `/v1/status` and `/v1/status/x`, never `/v1/statusx`).
    fn allowed(&self, path: &str) -> bool {
        let plain = path.starts_with('/') && path.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'%' | b'\\' | b'?' | b'#')) && !path.contains("..");
        plain && self.paths.iter().any(|p| path.strip_prefix(p.as_str()).is_some_and(|rest| rest.is_empty() || p.ends_with('/') || rest.starts_with('/')))
    }
}

impl DataSource for HttpJsonSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor::new(self.name.clone(), env!("CARGO_PKG_VERSION"), "GETs JSON from an HTTP API under fixed path prefixes.")
            .kind(SourceKind::HttpApi)
            .env("example")
            .sensitivity(Sensitivity::Internal)
            .op(OpDescriptor::new("get", "GETs <base_url><path> and answers its JSON.")
                .read_only(true)
                .params_schema(json!({"type":"object","properties":{"path":{"type":"string","maxLength":1024}},"required":["path"],"additionalProperties":false})))
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            if req.op != "get" {
                return Err(SourceError::NotFound(format!("no op {}", req.op)));
            }
            let p: GetParams = req.params_as()?;
            if !self.allowed(&p.path) {
                return Err(SourceError::InvalidArgument("params: path is not allowed".into()));
            }
            let max_bytes = ctx.limits.max_bytes;
            let fetch = async {
                // A source that needs a credential adds it here, from its own config, never from the request.
                let response = self.client.get(format!("{}{}", self.base_url, p.path)).timeout(self.timeout).send().await;
                let response = response.map_err(|_| SourceError::Unavailable("the HTTP request failed".into()))?;
                let status = response.status();
                if !status.is_success() {
                    return Err(SourceError::Unavailable(format!("http {}", status.as_u16())));
                }
                let body = collect_capped(Box::pin(response.bytes_stream()), max_bytes).await?;
                if body.truncated {
                    // A cut JSON text is no JSON.
                    return Err(SourceError::ResourceExhausted(format!("body over max_bytes {max_bytes}")));
                }
                serde_json::from_slice(&body.value).map(Output::json).map_err(|_| SourceError::Unavailable("not JSON".into()))
            };
            ctx.within(fetch).await
        })
    }
}

/// The sources of the config's `[[source]]` tables, in order.
pub fn build_sources(configs: &[SourceConfig]) -> Vec<Arc<dyn DataSource>> {
    configs
        .iter()
        .map(|c| -> Arc<dyn DataSource> {
            match c {
                SourceConfig::Echo { name } => Arc::new(EchoSource::new(name.clone())),
                SourceConfig::HttpJson { name, base_url, paths, timeout_ms } => {
                    Arc::new(HttpJsonSource::new(name.clone(), base_url.clone(), paths.clone(), timeout_ms.map(Duration::from_millis)))
                }
            }
        })
        .collect()
}
