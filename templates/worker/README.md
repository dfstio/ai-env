# my-worker: a worker behind the ai-env relay

This directory is ai-env's starting point for a worker: a small binary that dials the ai-env relay over
TLS 1.3, pinned to the relay's own CA, proves a whitelisted Ed25519 key, and serves data sources to the
agents in ai-env's VMs. It holds placeholders only, and the generic `EchoSource` and `HttpJsonSource`.

## Start a worker repository

1. Copy this directory into a new private repository, and rename the package in `Cargo.toml`.
2. Pin the tag of the ai-env release you build against (`tag = "relay-v…"` on both ai-env dependencies),
   never a branch. `Cargo.lock` is yours to commit in that repository.
3. Write your sources in `src/sources.rs`: one type per backend, each implementing
   `ai_env_source::DataSource`, with a `[[source]]` kind in `src/config.rs`. A source holds its own
   read-only credential, read from this worker's config; it never takes one from a call.
4. Run `cargo test`: `tests/conformance.rs` holds each source to ai-env-source's conformance checks.

Never commit `worker.toml`, a key, or a list of your private source or host names into ai-env: ai-env is
public. Keep that list in your repository's own pre-push hook.

## Install it on a server

1. `my-worker keygen --out /etc/ai-env-worker/worker.key`, as root, makes the worker's key (a 0600 file)
   and prints its public key, `ed25519:…`; nothing prints the private key. Then
   `chown ai-env-worker:ai-env-worker /etc/ai-env-worker/worker.key`: the worker reads only a key file its
   own user owns (and `/etc/ai-env-worker` is `root:ai-env-worker`, 0750).
2. Ask the deployer to allow it:
   `ai-env as deployer -- ai-env relay allow <worker-id> --key <the printed key> --sources '<glob>'`.
3. Install the relay CA's certificate, which `ai-env relay ca` prints on the Mac, as
   `/etc/ai-env-worker/relay-ca.pem`: it is the worker's only trust anchor.
4. Copy `worker.toml.example` to `/etc/ai-env-worker/worker.toml` (0640, `root:ai-env-worker`), fill it
   in, and install the binary as `/usr/local/bin/my-worker` and `ai-env-worker.service` as a systemd unit.
5. Run `runuser -u ai-env-worker -- my-worker check --config /etc/ai-env-worker/worker.toml` (as the
   worker's user, which owns the key) before `systemctl enable --now ai-env-worker`, or with the service
   stopped: a check under the id of a running worker supersedes that worker's tunnel, and it stays offline
   for about a minute.

## On the Mac

Set `signer = "agent"` (and no `key_file`): the worker then signs through `ai-env relay agent`, which
must be running, so the Mac's worker key never leaves ai-env's keystore.

## Logs

The worker logs to stderr (`RUST_LOG`, default `info`): one line per call with its ids, outcome, bytes
and time, never its parameters, its data or a key.

A source that panics is answered `INTERNAL` "the source failed", and no panic text leaves the worker; Rust's
default panic hook still prints the panic's message to this stderr. Keep secrets and data out of panic
messages, or install a hook in `main` (`std::panic::set_hook`) that leaves the message out.

The source of ai-env, and its relay's design, is at https://github.com/dfstio/ai-env.
