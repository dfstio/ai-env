//! P-T36 to P-T38: the conformance checks pass `EchoSource` and flag each broken double with its own
//! violation (plans/s13-contracts.md §P-proto-sdk.14, P-R85, P-R86).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_env_source::redact::Rule;
use ai_env_source::testkit::{assert_conforms, sample, Check, Conformance, EchoSource, Violation};
use ai_env_source::{BoxFuture, CallContext, CallRequest, DataSource, Health, OpDescriptor, Output, OutputKind, SourceDescriptor, SourceError};
use serde::Deserialize;
use serde_json::json;

/// The doubles' params: one optional `n`, nothing else.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    #[serde(default)]
    n: Option<u64>,
}

/// A conforming answer for the doubles' one op `get`: `NotFound` for another op, `InvalidArgument` for
/// unknown params, else `ok`.
fn strict(req: &CallRequest, ok: impl FnOnce() -> Result<Output, SourceError>) -> Result<Output, SourceError> {
    if req.op != "get" {
        return Err(SourceError::NotFound(format!("no op {}", req.op)));
    }
    req.params_as::<Params>()?;
    ok()
}

fn one_op(name: &str) -> SourceDescriptor {
    SourceDescriptor::new(name, "0.1.0", "A conformance test double.").op(OpDescriptor::new("get", "Gets.").example(json!({"n": 1})))
}

fn ready<'f>(answer: Result<Output, SourceError>) -> BoxFuture<'f, Result<Output, SourceError>> {
    Box::pin(async move { answer })
}

/// No op: its descriptor is invalid.
struct InvalidDescriptorSource;

impl DataSource for InvalidDescriptorSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor::new("test-invalid", "0.1.0", "A conformance test double.")
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        ready(strict(&req, || Ok(Output::json(json!({})))))
    }
}

/// Its version counts its descriptor calls.
#[derive(Default)]
struct UnstableDescriptorSource(AtomicU64);

impl DataSource for UnstableDescriptorSource {
    fn descriptor(&self) -> SourceDescriptor {
        let mut d = one_op("test-unstable");
        d.version = format!("1.{}", self.0.fetch_add(1, Ordering::SeqCst));
        d
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        ready(strict(&req, || Ok(Output::json(json!({})))))
    }
}

/// Answers `Ok` to an op it does not have; checks its own op's params.
struct LenientOpSource;

impl DataSource for LenientOpSource {
    fn descriptor(&self) -> SourceDescriptor {
        one_op("test-lenient-op")
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        let answer = if req.op == "get" { req.params_as::<Params>().map(|_| Output::json(json!({}))) } else { Ok(Output::json(json!({}))) };
        ready(answer)
    }
}

/// Answers `Ok` to its own op whatever its params, `NotFound` to others.
struct LenientParamsSource;

impl DataSource for LenientParamsSource {
    fn descriptor(&self) -> SourceDescriptor {
        one_op("test-lenient-params")
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        let answer = if req.op == "get" { Ok(Output::json(json!({}))) } else { Err(SourceError::NotFound(format!("no op {}", req.op))) };
        ready(answer)
    }
}

/// Its health takes 10 s.
struct SlowHealthSource;

#[async_trait::async_trait]
impl DataSource for SlowHealthSource {
    fn descriptor(&self) -> SourceDescriptor {
        one_op("test-slow-health")
    }

    async fn call(&self, req: CallRequest, _ctx: CallContext) -> Result<Output, SourceError> {
        strict(&req, || Ok(Output::json(json!({}))))
    }

    async fn health(&self) -> Health {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Health::Ok
    }
}

/// Its example answers INTERNAL, with a token-shaped text in the message.
struct InternalExampleSource;

impl DataSource for InternalExampleSource {
    fn descriptor(&self) -> SourceDescriptor {
        one_op("test-internal-example")
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        ready(strict(&req, || Err(SourceError::Internal(format!("a fault near {}", sample(Rule::Jwt).0)))))
    }
}

/// Declares `Json`, answers `Text`.
struct WrongKindSource;

impl DataSource for WrongKindSource {
    fn descriptor(&self) -> SourceDescriptor {
        one_op("test-wrong-kind")
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        ready(strict(&req, || Ok(Output::text("not JSON"))))
    }
}

/// Panics on any call, with a token-shaped text in the message.
struct PanickingSource;

impl DataSource for PanickingSource {
    fn descriptor(&self) -> SourceDescriptor {
        one_op("test-panicking")
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        Box::pin(boom(req.op))
    }
}

async fn boom(op: String) -> Result<Output, SourceError> {
    panic!("called {op} near {}", sample(Rule::Jwt).0)
}

/// Records every call's op and params, and conforms.
#[derive(Default)]
struct RecordingSource(Mutex<Vec<(String, serde_json::Value)>>);

impl DataSource for RecordingSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor::new("test-recording", "0.1.0", "A conformance test double.")
            .op(OpDescriptor::new("first", "First.").example(json!({"n": 1})).example(json!({"n": 2})))
            .op(OpDescriptor::new("second", "Second.").output(OutputKind::Text).example(json!({"n": 3})))
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        self.0.lock().expect("unpoisoned").push((req.op.clone(), req.params.clone()));
        let answer = match req.op.as_str() {
            "first" => req.params_as::<Params>().map(|p| Output::json(json!({"n": p.n}))),
            "second" => req.params_as::<Params>().map(|_| Output::text("second")),
            op => Err(SourceError::NotFound(format!("no op {op}"))),
        };
        ready(answer)
    }
}

/// Each violation's check and op.
type Shape<'a> = Vec<(Check, Option<&'a str>)>;

fn shape(violations: &[Violation]) -> Shape<'_> {
    violations.iter().map(|v| (v.check, v.op.as_deref())).collect()
}

/// P-T36.
#[tokio::test(start_paused = true)]
async fn echo_source_conforms_with_its_examples() {
    let violations = Conformance::new(Arc::new(EchoSource::new())).with_examples().run().await;
    assert!(violations.is_empty(), "{violations:#?}");
    assert_conforms(Arc::new(EchoSource::named("echo-2"))).await;
}

/// P-T37.
#[tokio::test(start_paused = true)]
async fn conformance_flags_each_broken_source() {
    let offline: [(Arc<dyn DataSource>, Shape<'static>); 6] = [
        (Arc::new(InvalidDescriptorSource), vec![(Check::DescriptorValid, None)]),
        (Arc::new(UnstableDescriptorSource::default()), vec![(Check::DescriptorStable, None)]),
        (Arc::new(LenientOpSource), vec![(Check::UnknownOp, Some("conformance-unknown-op"))]),
        (Arc::new(LenientParamsSource), vec![(Check::UnknownParams, Some("get"))]),
        (Arc::new(SlowHealthSource), vec![(Check::Health, None)]),
        (Arc::new(PanickingSource), vec![(Check::UnknownOp, Some("conformance-unknown-op")), (Check::UnknownParams, Some("get"))]),
    ];
    for (source, want) in offline {
        let name = source.descriptor().name;
        let violations = Conformance::new(source).run().await;
        assert_eq!(shape(&violations), want, "{name}: {violations:#?}");
    }
    let examples: [(Arc<dyn DataSource>, Shape<'static>); 2] = [
        (Arc::new(InternalExampleSource), vec![(Check::Example, Some("get"))]),
        (Arc::new(WrongKindSource), vec![(Check::ExampleOutputKind, Some("get"))]),
    ];
    for (source, want) in examples {
        let name = source.descriptor().name;
        assert!(Conformance::new(Arc::clone(&source)).run().await.is_empty(), "{name} passes the offline checks");
        let violations = Conformance::new(source).with_examples().run().await;
        assert_eq!(shape(&violations), want, "{name}: {violations:#?}");
    }

    let invalid = Conformance::new(Arc::new(InvalidDescriptorSource)).run().await;
    assert_eq!(invalid[0].detail, "descriptor \"test-invalid\": ops: at least one op");
    assert_eq!(invalid[0].to_string(), "descriptor-valid -: descriptor \"test-invalid\": ops: at least one op");
    let lenient = Conformance::new(Arc::new(LenientOpSource)).run().await;
    assert_eq!(lenient[0].detail, "answered a json output, not NOT_FOUND");
    let slow = Conformance::new(Arc::new(SlowHealthSource)).run().await;
    assert_eq!(slow[0].to_string(), "health -: no answer within 5s");
    assert!(Conformance::new(Arc::new(SlowHealthSource)).health_timeout(Duration::from_secs(11)).run().await.is_empty());
    // A source's error and panic texts reach the violations through its redactor, never raw (P-R32, P-R39).
    let masked = sample(Rule::Jwt).1;
    let panicking = Conformance::new(Arc::new(PanickingSource)).run().await;
    for v in &panicking {
        assert!(v.detail.starts_with("panicked: called "), "{v}");
        assert!(v.detail.ends_with(&format!(" near {masked}")), "{v}");
    }
    let internal = Conformance::new(Arc::new(InternalExampleSource)).with_examples().run().await;
    assert_eq!(internal[0].to_string(), format!("example get: {{\"n\":1}} answered INTERNAL: a fault near {masked}"));
    let wrong = Conformance::new(Arc::new(WrongKindSource)).with_examples().run().await;
    assert_eq!(wrong[0].to_string(), "example-output-kind get: {\"n\":1} answered text, the op declares json");
    let names: Vec<_> = [
        Check::DescriptorValid,
        Check::DescriptorStable,
        Check::UnknownOp,
        Check::UnknownParams,
        Check::Health,
        Check::Example,
        Check::ExampleOutputKind,
    ]
    .iter()
    .map(|c| c.name())
    .collect();
    assert_eq!(names, ["descriptor-valid", "descriptor-stable", "unknown-op", "unknown-params", "health", "example", "example-output-kind"]);

    let joined = tokio::spawn(assert_conforms(Arc::new(LenientParamsSource))).await;
    let payload = joined.expect_err("panics").into_panic();
    let message = payload.downcast_ref::<String>().expect("a text");
    assert!(message.starts_with("test-lenient-params does not conform:\n"), "{message}");
    assert_eq!(message.lines().count(), 2, "one violation per line: {message}");
}

/// P-T38.
#[tokio::test(start_paused = true)]
async fn examples_are_called_only_with_examples() {
    let unknown = || json!({"conformance_unknown_param": true});
    let offline = vec![("conformance-unknown-op".to_string(), json!({})), ("first".to_string(), unknown()), ("second".to_string(), unknown())];

    let source = Arc::new(RecordingSource::default());
    assert!(Conformance::new(Arc::clone(&source) as Arc<dyn DataSource>).run().await.is_empty());
    assert_eq!(*source.0.lock().expect("unpoisoned"), offline);

    let source = Arc::new(RecordingSource::default());
    assert!(Conformance::new(Arc::clone(&source) as Arc<dyn DataSource>).with_examples().run().await.is_empty());
    let mut with_examples = offline;
    with_examples.extend([("first".to_string(), json!({"n": 1})), ("first".to_string(), json!({"n": 2})), ("second".to_string(), json!({"n": 3}))]);
    assert_eq!(*source.0.lock().expect("unpoisoned"), with_examples);
}
