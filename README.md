# mdconfcli

A minimal, MCP‑friendly Confluence CLI that searches and reads pages and prints structured JSON. Credentials are stored in the OS keychain (on Windows, the Windows Credential Manager) and validated automatically.

## Features
- Search content via free‑text or CQL and return JSON.
- Read content by ID or URL; output as plain text, rendered HTML (view), or storage format.
- Keychain‑backed auth with interactive `init` flow.
- Ergonomic alias: `get` == `read`.

## Install / Build
- Build debug: `cargo build`
- Build release: `cargo build --release`
- Run help: `cargo run -- --help`
- Install locally: `cargo install --path .`

## Authentication
Credentials are stored in the OS keychain. On Windows this uses Windows Credential Manager via the `keyring` crate.

Initialize or update credentials:
```
conf-cli init
```
The init flow will prompt for:
- Base URL: e.g. `https://your-domain.atlassian.net/wiki`
- Email/username
- API token

Force reinitialize (overwrite even if current creds are valid):
```
conf-cli init --force
```

Notes:
- Cloud: use your Atlassian account email and an API token.
- Server/Data Center: use your username and a Personal Access Token (if enabled by your admin).

## Get a Confluence Token
- Confluence Cloud (recommended):
  1) Visit https://id.atlassian.com/manage-profile/security/api-tokens
  2) Create API token, copy it, and use it during `conf-cli init`.
- Confluence Server/Data Center (7.13+ with PAT):
  1) In Confluence, open your profile → Settings → Personal Access Tokens
  2) Create a token with minimal scopes and use it during `conf-cli init`.
  If PATs are not available, ask your admin to enable them. Avoid passwords.

## Usage Examples
- Check status and available commands:
  `conf-cli info`
- Search pages by text in a space:
  `conf-cli search "runbook" --space ENG --limit 5`
- Read a page as text by URL or ID:
  `conf-cli read https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Title --format text`
- Use the alias:
  `conf-cli get 123456 --format view`

Outputs are JSON for easy automation. Non‑zero exit codes indicate errors; details are printed to stderr in JSON.
