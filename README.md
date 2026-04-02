# CodeGuard MCP Server

Model Context Protocol server for security scanning in **Claude Desktop**, **Cursor**, **Windsurf**, and other MCP clients.

## Disclaimer

**Local heuristic scanner** — for full Semgrep-powered scanning use the [CodeGuard SaaS](https://codeguard.dev).

## Installation

```bash
npm install -g codeguard-mcp
```

Configure your MCP client to run `codeguard-mcp` (stdio transport). Set `ANTHROPIC_API_KEY` in the environment for the `fix_vulnerability` tool.

## Tools

- `scan_code` — scan a snippet
- `scan_file` — scan a file path
- `fix_vulnerability` — AI-generated fix (requires API key)

## License

MIT
