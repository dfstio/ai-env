//! Regenerates the committed relay bindings: `make relay-proto` from the repo root. Needs `protoc` on
//! PATH. An optional first argument is another output directory, resolved against the current directory
//! (`make relay-proto-check` writes into `target/relay-proto-check` and compares the two files with the
//! committed ones, P-R23 and P-R24). The output is checked in, so nothing else in the build ever needs protoc.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let krate = root.join("crates/ai-env-relay-proto");
    let out = match std::env::args_os().nth(1) {
        Some(dir) => std::env::current_dir()?.join(dir),
        None => krate.join("src/gen"),
    };
    std::fs::create_dir_all(&out)?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(false)
        .file_descriptor_set_path(out.join("descriptor.bin"))
        .out_dir(&out)
        .compile_protos(&[krate.join("proto/ai_env/relay/v1/relay.proto")], &[krate.join("proto")])?;
    println!("regenerated {}", out.display());
    Ok(())
}
