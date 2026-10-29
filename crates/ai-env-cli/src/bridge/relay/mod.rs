//! S13 (plans/s13-contracts.md §WM-worker-mac.6): the Mac side of the relay, an info bridge in AWS that VMs
//! reach privately and workers dial from the internet.
//!
//! - `keys` (WM-R36, WM-R37): this Mac's two relay keys, its worker key and its session key, sealed into one
//!   container, `credentials/relay-worker.env` (`ai-env relay keygen`, no Touch ID; `ai-env relay pubkey`).
//! - `agent` (WM-R38 to WM-R40): `ai-env relay agent` unseals them once (one Touch ID) and, over a 0600 Unix
//!   socket and for at most a working day, signs worker handshakes and mints VM session tokens.
//! - `params` (WM-R41 to WM-R45): the relay's three lists, `/ai-env/relay/{workers,token-signers,grants}`,
//!   written as ai-env-deployer only (`ai-env relay allow|revoke|grant`).
//! - `tls` (WM-R59 to WM-R62): the relay CA, its key sealed on this Mac, and the relay's certificate in the
//!   SecureString `/ai-env/relay/tls` (`ai-env relay tls init|rotate`, as ai-env-deployer; `ai-env relay ca`).
//! - `ops` (WM-R47 to WM-R49): the relay instance as ai-env-ops (`ai-env relay status|start|stop`).
//! - `mint` (WM-R50 to WM-R53): the VM session token each remote spawn asks the agent for, which rides the
//!   spawn's credential delivery to its own VM only.
//!
//! The shared formats (ids, keys, session tokens, the lists, the agent's protocol, the certificates) are
//! `ai-env-worker`'s, taken without its runtime. Values, keys and tokens never reach an argument list, a log,
//! an audit row or stdout: audit values are ids, words, numbers and 16-hex fingerprints (WM-R57).
pub mod agent;
pub mod cli;
pub mod keys;
pub mod mint;
pub mod ops;
pub mod params;
pub mod tls;
