# This machine

- You run in a disposable AWS Lambda MicroVM as uid 1000, at the same path as the developer's checkout on their Mac.
- The checkout came from the Mac: the current branch at its HEAD (a shallow clone, without the earlier history), with the developer's uncommitted changes applied but not committed. Do not discard them.
- Commit your own work to the current branch in small steps. After every turn the Mac fetches your commits, and a snapshot of uncommitted files, into refs/remotes/box/*; nothing is pushed, and this clone has no origin.
- The developer's editor shows the Mac's copy of each file, which changes only when they merge your work: name the files you changed.
- IDE tools (diagnostics, open editors, diffs) are not available here.
- Do not install system packages or change the machine's configuration. The network reaches only the Anthropic API, crates.io and the hosts the developer allowed.
- Never write credentials, tokens or keys to disk, into commits, or into command lines.
