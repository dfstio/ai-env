# my-worker: a worker behind the ai-env relay

This directory is ai-env's starting point for a worker: a small binary that dials the ai-env relay over
TLS 1.3, pinned to the relay's own CA, from an address the relay lists, proves a whitelisted Ed25519 key, and
serves data sources to the agents in ai-env's VMs. It holds placeholders only, and the generic `EchoSource`
and `HttpJsonSource`.

## Start a worker repository

1. Copy this directory into a new private repository, and rename the package in `Cargo.toml`.
2. Pin the tag of the ai-env release you build against (`tag = "relay-v…"` on all three ai-env lines, both
   dependencies and the testkit's), never a branch. `Cargo.lock` is yours to commit in that repository. The
   template names `relay-v0.2.0`, the first release with what `tls-keygen` and `relay_client_cert` call, and
   that tag comes with the client certificates' roll-out. Until `git ls-remote --tags
   https://github.com/dfstio/ai-env` lists it, build against a checkout: `path = "…/crates/ai-env-worker"` and
   `path = "…/crates/ai-env-source"` in place of `git` and `tag` on those lines, never committed.
3. Write your sources in `src/sources.rs`: one type per backend, each implementing
   `ai_env_source::DataSource`, with a `[[source]]` kind in `src/config.rs`. A source holds its own
   read-only credential, read from this worker's config; it never takes one from a call. Keep control and
   format characters out of a descriptor's `version`, `env`, descriptions, examples and params schema (a soft
   hyphen, a zero-width joiner, a byte-order mark, a bidi override; TAB, LF and CR pass outside `version` and
   `env`): the relay refuses such a catalog when the worker connects, naming the source and the field, and
   neither the SDK's checks nor the conformance test catch them.
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
3. Ask the deployer to list the address the server dials from, a NAT gateway's on a private network:
   `ai-env as deployer -- ai-env relay allow-ip 203.0.113.10 --label <what it is>` (a bare address is a /32,
   and `a.b.c.d/n` a network; a year by default, at most two with `--not-after`). The relay applies it within
   60 s.
4. Install the relay CA's certificate, which `ai-env relay ca` prints on the Mac, as
   `/etc/ai-env-worker/relay-ca.pem`: it is the worker's only trust anchor.
5. Copy `worker.toml.example` to `/etc/ai-env-worker/worker.toml` (0640, `root:ai-env-worker`), fill it
   in, and install the binary as `/usr/local/bin/my-worker` and `ai-env-worker.service` as a systemd unit.
6. Run `runuser -u ai-env-worker -- my-worker check --config /etc/ai-env-worker/worker.toml` (as the
   worker's user, which owns the key) before `systemctl enable --now ai-env-worker`, or with the service
   stopped: a check under the id of a running worker supersedes that worker's tunnel, and it stays offline
   for about a minute.

## The client certificate

The relay requires one: it refuses at TLS a worker with no certificate under the relay CA, and gives no challenge
to one whose fingerprint no whitelist entry in force holds. Moving from a relay that asks for none, the order is
certificates first, then the relay that requires them: rustls presents a certificate only when a relay asks, so one
installed early changes nothing, and with every worker's certificate in place that relay deploys with no window.
Issue none while a relay from before the allowlist runs: it refuses a whitelist that carries a certificate's
fingerprint and unloads the whole list, and `ai-env relay status` then says `not yet` in the worker's row.

1. `my-worker tls-keygen --out /etc/ai-env-worker/relay-client.key`, as root, makes the TLS key (P-256, a 0600
   file, apart from the Ed25519 key, which goes on proving who the worker is) and prints its public point,
   `p256:…`, and the next command. Then
   `chown ai-env-worker:ai-env-worker /etc/ai-env-worker/relay-client.key`, as for the worker's key.
2. On the Mac, the deployer issues the certificate, for one paste and one Touch ID (the sealed relay CA's key):
   `ai-env as deployer -- ai-env relay allow <worker-id> --key <its ed25519 key> --sources '<glob>' --tls-key 'p256:…' > relay-client.pem`.
   Stdout holds the certificate alone, which is public, and the lines go to stderr. The whitelist entry records
   its SHA-256, and it ends with the entry's last day (`--not-after`). Name an existing entry's day: with none,
   `allow` moves the entry and its new certificate to a year from today.
3. Install it as `/etc/ai-env-worker/relay-client.pem` (0640, `root:ai-env-worker`), and set
   `relay_client_cert` and `relay_client_key` in `worker.toml` (both or neither; the example has them commented
   out).
4. `systemctl restart ai-env-worker`: the tunnel comes back at once. `ai-env relay status` on the Mac then
   shows `cert fp …` beside the worker, in place of `[NO ] worker … has no client certificate: the relay refuses it …`,
   or `[warn] worker … has no client certificate yet: …` under a relay that asks for none. `my-worker check --config
   /etc/ai-env-worker/worker.toml --offline` ends its line with `, cert fp <16 hex>`, the file its next start presents,
   which must equal that `cert fp`.

`allow` without `--tls-key` moves the entry's end, never the certificate's; a key rotation past the
certificate's end needs `--tls-key`, or the relay refuses the worker at TLS on that day. A new certificate closes
no live tunnel, which stays up on the old one until it next connects: if the worker's keys may be stolen, rotate
`--key` too, or revoke it. A new relay CA
(`ai-env relay tls init --force`) strands every client certificate, as it strands every `relay_ca` file. Under
a relay that requires them, `check` says `tls: the relay requires a client certificate` for a worker with
none, and `tls: the relay refused this worker's client certificate (…)` for one it refuses.

## On the Mac

Set `signer = "agent"` (and no `key_file`): the worker then signs through `ai-env relay agent`, which
must be running, so the Mac's worker key never leaves ai-env's keystore. The Mac's address moves, so it goes on
the relay's list for a time: `ai-env as deployer -- ai-env relay allow-ip --mine` lists it as a /32 labelled
`mac` for 24 hours (`--hours N`, at most 168). Run it again on another network, or when `ai-env relay status`
says `[warn] peer mac lapsed at …`: the entry's end closes this worker's tunnel. A client certificate's two
files go in the bridge's `state/`: `state/relay-client.key` (0600, made by this binary's `tls-keygen`) and
`state/relay-client.pem`.

## When it cannot connect

A connection that times out is the relay's allowlist and no network fault: the instance's kernel drops the SYN
of any address off the list, and the relay's log holds no line for it. `ai-env relay status` on the Mac shows
the entries in force. With no fresh list the relay refuses everyone.

A connection closed before TLS is a ban: 20 faults within 10 minutes ban a listed address for 15. A fault is a
refused handshake (a wrong key, an id or an entry not in force), no `Open` within 5 s of the TLS accept, a TLS
handshake past its 3 s, or one that fails once the client sent a byte (a stale `relay_ca` file does that). An
address that holds a live tunnel, or ended one less than 10 minutes ago, counts no fault. One SDK worker per
address never bans itself: it backs off 1, 2, 4 … 60 s, and waits at least 60 s after `authentication failed`.
Two workers behind one address, restarts or `check` runs from it can pass 20.

A running worker's log says `the relay tunnel ended; the next dial waits`, with the relay's reason: `peer
revoked` when its address left the list or its entry lapsed, `the peers list is not loaded` or `the peers list
is stale` when the relay lost the list, `inbound rate` or `catalog rate` past its tunnel's budget (600 frames
and 32 MiB a minute of what it sends unasked, six catalogs a minute). The worker dials again by itself.

## Stopping it

`run` stops on Ctrl-C (SIGINT) or SIGTERM, which `systemctl stop` sends: it logs `stopping`, ends its tunnel
within 2 s and exits 0. A process starts with its parent's blocked signals, so `main` unblocks both before
anything else: a shell that blocked SIGINT cannot keep the worker running through Ctrl-C. When you change
`main`, keep the unblock its first statement: each thread starts with the mask of the one that made it.

## Logs

The worker logs to stderr (`RUST_LOG`, default `info`): one line per call with its ids, outcome, bytes
and time, never its parameters, its data or a key.

A source that panics is answered `INTERNAL` "the source failed", and no panic text leaves the worker; Rust's
default panic hook still prints the panic's message to this stderr. Keep secrets and data out of panic
messages, or install a hook in `main` (`std::panic::set_hook`) that leaves the message out.

The source of ai-env, and its relay's design, is at https://github.com/dfstio/ai-env.
