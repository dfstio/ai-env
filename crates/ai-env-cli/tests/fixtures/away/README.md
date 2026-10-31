# away fixtures (S14 T2, plans/s14-plan.md Phase P)

`initialize-cursor-hooks.json` is the `initialize` control request that
Cursor's Claude Code extension 2.1.314 (its SDK 0.3.314) writes to its claude
when a chat starts. It is one stream-json line, with its keys in the order the
SDK's `JSON.stringify` writes them. It was rebuilt from the extension's code
(`spawnClaude`'s options, `Query.buildInitializeRequest`, the in-process
server's `registerTool`), not captured from a run:

- `hooks`: the extension's SDK hooks. `PreToolUse` has `Edit|Write|MultiEdit`
  (captureBaseline) and `Edit|Write|Read` (saveFileIfNeeded); `PostToolUse` has
  `Edit|Write|MultiEdit` (findDiagnosticsProblems). There is one callback each,
  numbered `hook_0` to `hook_2` in that order by the query's counter, and no
  timeout.
- `sdkMcpServers`: the in-process `claude-vscode` server. Its manifest
  (`sdkMcpServerManifests`) is what the SDK captures before it writes the
  request, unless the capture misses its 250 ms deadline. It holds the MCP
  initialize result (protocol 2025-11-25, `tools.listChanged`) and the one
  tool, `getDiagnostics`, with the schema that the MCP SDK's
  zod-to-json-schema gives it. There are no `sdkMcpServerConfigs`, because the
  server has no settings.
- `appendSystemPrompt` is cut to its first two lines (the extension's "VSCode
  Extension Context" prompt). `systemPromptSnapshot`, `supportedDialogKinds`,
  `perTaskStopAffordance` and `forwardNestedSubagentToolCalls` are as the chat
  launch sets them.

The `request_id` is a placeholder; the SDK's is random base36. A claude that
gets this request asks its host: a `hook_callback` request (`hook_0` to
`hook_2`) when a matching tool runs, and an `mcp_message` request when it
calls the `claude-vscode` server. P1.3b and Track B's tests send it to a claude
that has no host to answer them.
`tests/continuity/rig.rs` pins the hooks and the server, and has the fake
claude answer this request.
