//! P-T39 (phase 0's proof of the frozen trait form, LD-P2; slice P owns and extends this file): the trait takes
//! a hand-written impl and `#[async_trait]` impls, behind `Arc<dyn DataSource>` and across `tokio::spawn`.

use std::sync::Arc;
use std::time::Duration;

use ai_env_source::redact::Rule;
use ai_env_source::testkit::context;
use ai_env_source::{BoxFuture, CallContext, CallRequest, DataSource, Health, Limits, OpDescriptor, Output, SourceDescriptor, SourceError};

fn descriptor(name: &str) -> SourceDescriptor {
    SourceDescriptor::new(name, "0.1.0", "A test double.").op(OpDescriptor::new("get", "Answers its params."))
}

struct HandSource;

impl DataSource for HandSource {
    fn descriptor(&self) -> SourceDescriptor {
        descriptor("test-hand")
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        Box::pin(async move { ctx.within(async { Ok(Output::json(req.params.clone())) }).await })
    }
}

struct MacroSource;

#[async_trait::async_trait]
impl DataSource for MacroSource {
    fn descriptor(&self) -> SourceDescriptor {
        descriptor("test-macro")
    }

    async fn call(&self, req: CallRequest, ctx: CallContext) -> Result<Output, SourceError> {
        ctx.within(async { Ok(Output::json(req.params.clone())) }).await
    }

    async fn health(&self) -> Health {
        Health::Degraded("probe".to_string())
    }
}

struct DefaultsSource;

#[async_trait::async_trait]
impl DataSource for DefaultsSource {
    fn descriptor(&self) -> SourceDescriptor {
        descriptor("test-defaults")
    }

    async fn call(&self, req: CallRequest, _ctx: CallContext) -> Result<Output, SourceError> {
        Ok(Output::json(req.params))
    }
}

#[tokio::test]
async fn the_trait_takes_hand_written_and_async_trait_impls() {
    let sources: [(Arc<dyn DataSource>, Health); 3] = [
        (Arc::new(HandSource), Health::Ok),
        (Arc::new(MacroSource), Health::Degraded("probe".to_string())),
        (Arc::new(DefaultsSource), Health::Ok),
    ];
    for (source, health) in sources {
        let name = source.descriptor().name;
        let params = serde_json::json!({"n": 1});
        let ctx = context(&name, Limits::DEFAULT, Duration::from_secs(5));
        let out = source.call(CallRequest::new("get", params.clone()), ctx).await.expect("answers");
        assert!(matches!(out.body(), ai_env_source::Body::Json(v) if *v == params), "{name}");
        let spawned = Arc::clone(&source);
        let ctx = context(&name, Limits::DEFAULT, Duration::from_secs(5));
        let joined = tokio::spawn(async move { spawned.call(CallRequest::new("get", serde_json::json!({})), ctx).await.is_ok() });
        assert!(joined.await.expect("joins"), "{name} answers across tokio::spawn");
        assert_eq!(source.health().await, health, "{name}");
    }
    assert_eq!(DefaultsSource.redactor().rules(), Rule::ALL.as_slice());
}
