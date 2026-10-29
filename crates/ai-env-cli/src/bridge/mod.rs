//! Mac-side bridge (feature `bridge`): the MicroVM control-plane client, the
//! TLS policy, scrubbed logging, config, the sibling-binary lookup, doctor
//! rows, the pre-code gates, the S2 pump with its host-state recorder,
//! transcript-mirror writer, session registry, resume seeder and audit log,
//! the S3 infrastructure helpers (image scan, claude pin, stack outputs,
//! sealed AWS credentials), the S4 MicroVM lifecycle (`vm`), the S5
//! egress allowlist (`egress`, with the operator's aws CLI calls in
//! `awscli`), the S6 agent transport (`agent`: `vm exec`, `vm attach`), and
//! the S8 remote sessions: the pump's remote child and its pipeline
//! (`remote`), the workspace data plane (`workspace`, `codeout`,
//! `dataplane`, `boxcmd` for `ai-env box`), the settings capture
//! (`settings_capture`) and who speaks on stderr (`voice`). The S8
//! operators: the AWS identity of every operator `aws` child and the `ai-env
//! as` runner (`identity`), the concealed clipboard (`pasteboard`) and the
//! deployer key's hand-over through it (`handover`). S9: git smart-HTTP's
//! client (`gitsmart`), `box review` and its pre-push hook (`review`), the
//! transcript store in S3 (`s3`) and a remote chat's view on this Mac (`view`).
//! S10: `session migrate` (`migrate`) and an idle chat's park (`park`). S10
//! addendum A1: several Claude accounts, one active (`accounts`). S11: the
//! Claude Code versions VMs follow (`claude`), the cost estimate and its
//! timeline (`cost`, `timeline`), the loopback control panel (`panel`) and
//! doctor's drift rows (`drift`).
//! S12: chat names (`title`) and the live tests' cost rows (`testruns`).
//! Nothing here is compiled into the VM image.
pub mod accounts;
pub mod agent;
pub mod api;
pub mod audit;
pub mod authwatch;
pub mod awscli;
pub mod boxcmd;
pub mod census;
pub mod claude;
pub mod codeout;
pub mod config;
pub mod cost;
pub mod creds;
pub mod dataplane;
pub mod doctor;
pub mod drift;
pub mod egress;
pub mod errors;
pub mod gates;
pub mod gitsmart;
pub mod handover;
pub mod hoststate;
pub mod identity;
pub mod imagepin;
pub mod infra;
pub mod lab;
pub mod logging;
pub mod migrate;
pub mod mirror;
pub mod panel;
pub mod park;
pub mod pasteboard;
pub mod probes;
pub mod pump;
pub mod registry;
pub mod remote;
pub mod review;
pub mod route;
pub mod s3;
pub mod scan;
pub mod seed;
pub mod settings_capture;
pub mod setup_token;
pub mod sibling;
pub mod signals;
pub mod testruns;
pub mod timeline;
pub mod title;
pub mod tls;
pub mod transport;
pub mod unseal;
pub mod view;
pub mod vm;
pub mod voice;
pub mod workspace;
pub mod wrapper;
pub mod wrapper_status;
