use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;
mod auth;
use auth as keyauth;

/// CLI shape ─ minimal, MCP-friendly, JSON-only
#[derive(Parser)]
#[command(
    name = "conf-cli",
    about = "Confluence CLI (MCP-friendly, JSON-only)",
    long_about = r#"Authentication is stored in the OS keychain (Windows Credential Manager).

Run `conf-cli init` to set or update:
  - Base URL: e.g. https://your-domain.atlassian.net/wiki
  - Email/username: e.g. you@example.com
  - API token: from https://id.atlassian.com/manage-profile/security/api-tokens

By default, init skips prompting if valid credentials already exist. Use
`conf-cli init --force` to overwrite stored credentials even if the current
ones validate. The CLI will prompt if credentials are missing or invalid."#
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Return supported commands & current keychain auth status
    Info,
    /// Initialize or update credentials in the OS keychain
    Init {
        /// Overwrite existing credentials without validating current ones
        #[arg(long)]
        force: bool,
    },
    /// Search Confluence via CQL or simple free-text
    Search {
        /// Free-text query -> becomes CQL 'text ~ "<query>"'
        #[arg(value_name = "QUERY")]
        query: Option<String>,
        /// Raw CQL (overrides --space/--type/--label and free-text)
        #[arg(long)]
        cql: Option<String>,
        /// Space key filter
        #[arg(long)]
        space: Option<String>,
        /// Content type (page, blogpost, etc.)
        #[arg(long, default_value = "page")]
        r#type: String,
        /// Label filters (repeatable)
        #[arg(long)]
        label: Vec<String>,
        /// Pagination controls
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        start: usize,
    },
    /// Read a page by numeric ID or full Confluence URL
    #[command(visible_alias = "get")]
    Read {
        /// Numeric ID or page URL like /spaces/KEY/pages/<ID>/...
        target: String,
        /// Output body format: text|view|storage
        #[arg(long, default_value = "text")]
        format: String,
        /// Text wrap width (for format=text)
        #[arg(long, default_value_t = 100)]
        width: usize,
    },
}

/// Keychain-based auth
#[derive(Clone)]
pub struct ConfAuth {
    base: String,
    email: String,
    token: String,
}

impl ConfAuth {}

fn main() {
    if let Err(e) = real_main() {
        // JSON error for MCP consumption (stderr) + non-zero exit
        let err = json!({ "error": { "message": e.to_string() }});
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&err).unwrap_or_else(|_| err.to_string())
        );
        std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Info => cmd_info(),
        Command::Init { force } => {
            keyauth::init_flow(force)?;
            Ok(())
        }
        Command::Search {
            query,
            cql,
            space,
            r#type,
            label,
            limit,
            start,
        } => {
            let auth = keyauth::resolve_interactive()?;
            cmd_search(&auth, query, cql, space, r#type, label, limit, start)
        }
        Command::Read {
            target,
            format,
            width,
        } => {
            let auth = keyauth::resolve_interactive()?;
            cmd_read(&auth, &target, &format, width)
        }
    }
}

/* -------------------- INFO -------------------- */

#[derive(Serialize)]
struct CommandSpec {
    name: String,
    description: String,
    args: serde_json::Value,
    example: String,
}

#[derive(Serialize)]
struct InfoOut {
    tool: &'static str,
    version: &'static str,
    auth: serde_json::Value,
    commands: Vec<CommandSpec>,
}

fn cmd_info() -> Result<()> {
    let auth = match keyauth::load()? {
        Some(a) => {
            let valid = keyauth::check(&a).is_ok();
            json!({ "exists": true, "valid": valid, "base": a.base, "email": a.email })
        }
        None => json!({ "exists": false, "valid": false }),
    };

    let commands = vec![
        CommandSpec {
            name: "info".into(),
            description: "Return supported commands & auth identity (from env)".into(),
            args: json!({}),
            example: "conf-cli info".into(),
        },
        CommandSpec {
            name: "search".into(),
            description: "Search Confluence via CQL or free-text (JSON only)".into(),
            args: json!({
                "query?": "string (free text)",
                "--cql?": "string (raw CQL, overrides query)",
                "--space?": "string (space key)",
                "--type?": "string (page|blogpost|... default: page)",
                "--label?": "string[] (repeatable)",
                "--limit?": "number (default 25)",
                "--start?": "number (default 0)"
            }),
            example: r#"conf-cli search "runbook" --space ENG --limit 10"#.into(),
        },
        CommandSpec {
            name: "read".into(),
            description: "Read page by numeric ID or URL. Formats: text|view|storage (alias: get)".into(),
            args: json!({
                "target": "string (ID or Confluence URL)",
                "--format?": "text|view|storage (default text)",
                "--width?": "number (wrap width for text, default 100)"
            }),
            example: r#"conf-cli read https://your.atlassian.net/wiki/spaces/ENG/pages/123456/My+Page --format text"#.into(),
        },
        CommandSpec {
            name: "get".into(),
            description: "Alias of 'read' for convenience".into(),
            args: json!({
                "target": "string (ID or Confluence URL)",
                "--format?": "text|view|storage (default text)",
                "--width?": "number (wrap width for text, default 100)"
            }),
            example: r#"conf-cli get 123456 --format view"#.into(),
        },
    ];

    let out = InfoOut {
        tool: "conf-cli",
        version: "0.3.3",
        auth,
        commands,
    };

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/* -------------------- HTTP & MODELS -------------------- */

fn http_client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client")
}

#[derive(Debug, Deserialize)]
struct TopLinks {
    #[serde(default)]
    #[allow(dead_code)]
    base: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Label {
    name: String,
}

#[derive(Debug, Deserialize)]
struct Labels {
    #[serde(default)]
    results: Vec<Label>,
}

#[derive(Debug, Deserialize)]
struct Space {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct User {
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LastUpdated {
    #[serde(default)]
    when: Option<String>,
    #[serde(default)]
    by: Option<User>,
}

#[derive(Debug, Deserialize)]
struct History {
    #[serde(default, rename = "lastUpdated")]
    last_updated: Option<LastUpdated>,
}

#[derive(Debug, Deserialize)]
struct Links {
    #[serde(default)]
    webui: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Content {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    space: Option<Space>,
    #[serde(default)]
    history: Option<History>,
    #[serde(default, rename = "_links")]
    links: Option<Links>,
    #[serde(default)]
    metadata: Option<Metadata>,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    #[serde(default)]
    labels: Option<Labels>,
}

#[derive(Debug, Deserialize)]
struct SearchResp {
    #[serde(default)]
    results: Vec<Content>,
    #[serde(default)]
    start: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    size: Option<usize>,
    #[serde(default, rename = "_links")]
    #[allow(dead_code)]
    top_links: Option<TopLinks>,
}

#[derive(Debug, Deserialize)]
struct BodyPart {
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct Body {
    #[serde(default)]
    storage: Option<BodyPart>,
    #[serde(default)]
    view: Option<BodyPart>,
}

#[derive(Debug, Deserialize)]
struct ContentExpanded {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    space: Option<Space>,
    #[serde(default)]
    history: Option<History>,
    #[serde(default)]
    version: Option<serde_json::Value>,
    #[serde(default)]
    body: Option<Body>,
    #[serde(default, rename = "_links")]
    links: Option<Links>,
}

/* -------------------- SEARCH -------------------- */

#[derive(Serialize)]
struct SearchItemOut {
    id: String,
    r#type: String,
    title: String,
    space_key: Option<String>,
    space_name: Option<String>,
    last_modified: Option<String>,
    last_modified_by: Option<String>,
    url: Option<String>,
    labels: Vec<String>,
}

#[derive(Serialize)]
struct SearchOut {
    cql: String,
    start: usize,
    limit: usize,
    count: usize,
    results: Vec<SearchItemOut>,
    next_start: Option<usize>,
}

fn build_cql(
    freetext: Option<String>,
    cql: Option<String>,
    space: Option<String>,
    kind: String,
    labels: Vec<String>,
) -> String {
    if let Some(c) = cql {
        return c;
    }
    let mut parts: Vec<String> = Vec::new();
    if !kind.is_empty() {
        parts.push(format!(r#"type = {}"#, kind));
    }
    if let Some(s) = space {
        parts.push(format!(r#"space = "{}""#, s));
    }
    for l in labels {
        parts.push(format!(r#"label = "{}""#, l));
    }
    if let Some(q) = freetext {
        parts.push(format!(r#"text ~ "{}""#, q));
    }
    if parts.is_empty() {
        parts.push("type = page".into());
    }
    parts.join(" AND ")
}

#[allow(clippy::too_many_arguments)]
fn cmd_search(
    auth: &ConfAuth,
    query: Option<String>,
    cql: Option<String>,
    space: Option<String>,
    kind: String,
    labels: Vec<String>,
    limit: usize,
    start: usize,
) -> Result<()> {
    let cql_final = build_cql(query, cql, space, kind, labels);
    let url = format!("{}/rest/api/content/search", auth.base);

    let client = http_client();
    let resp = client
        .get(&url)
        .query(&[
            ("cql", cql_final.as_str()),
            ("limit", &limit.to_string()),
            ("start", &start.to_string()),
            // expansions provide nice fields for MCP to use
            ("expand", "space,history.lastUpdated,metadata.labels,_links"),
        ])
        .basic_auth(&auth.email, Some(&auth.token))
        .header(ACCEPT, "application/json")
        .send()
        .context("HTTP request failed")?;

    if !resp.status().is_success() {
        bail!(
            "HTTP {}: {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }

    let data: SearchResp = resp
        .json()
        .context("Failed to parse JSON from Confluence")?;
    let mut out_items = Vec::with_capacity(data.results.len());

    for c in data.results {
        let labels = c
            .metadata
            .as_ref()
            .and_then(|m| m.labels.as_ref())
            .map(|ls| {
                ls.results
                    .iter()
                    .map(|l| l.name.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let url = c
            .links
            .as_ref()
            .and_then(|l| l.webui.as_ref())
            .map(|path| format!("{}{}", auth.base, path));

        let (when, by) = match c.history.as_ref().and_then(|h| h.last_updated.as_ref()) {
            Some(lu) => (
                lu.when.clone(),
                lu.by.as_ref().and_then(|u| u.display_name.clone()),
            ),
            None => (None, None),
        };

        out_items.push(SearchItemOut {
            id: c.id,
            r#type: c.kind,
            title: c.title,
            space_key: c.space.as_ref().and_then(|s| s.key.clone()),
            space_name: c.space.as_ref().and_then(|s| s.name.clone()),
            last_modified: when,
            last_modified_by: by,
            url,
            labels,
        });
    }

    let count = out_items.len();
    let next_start = match (data.size, data.limit, data.start) {
        (Some(size), Some(lim), Some(st)) if size == lim => Some(st + size),
        _ => None,
    };

    let out = SearchOut {
        cql: cql_final,
        start,
        limit,
        count,
        results: out_items,
        next_start,
    };

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/* -------------------- READ -------------------- */

#[derive(Serialize)]
struct ReadOut {
    id: String,
    r#type: String,
    title: String,
    space_key: Option<String>,
    space_name: Option<String>,
    last_modified: Option<String>,
    url: Option<String>,
    version: Option<serde_json::Value>,
    format_used: String,
    body_text: Option<String>,
    body_view_html: Option<String>,
    body_storage: Option<String>,
}

/// Accept numeric ID or full URL. Extract numeric ID.
fn extract_id(target: &str) -> Result<String> {
    // numeric?
    if target.chars().all(|c| c.is_ascii_digit()) {
        return Ok(target.to_string());
    }

    // try parse URL and pull out .../pages/<ID>/...
    let url = Url::parse(target).context("Target is not a valid numeric ID or URL")?;
    let re = Regex::new(r"/pages/(\d+)/").unwrap();
    if let Some(cap) = re.captures(url.path()) {
        return Ok(cap[1].to_string());
    }

    bail!("Could not extract page ID from URL (expected /pages/<ID>/)");
}

fn cmd_read(auth: &ConfAuth, target: &str, format: &str, width: usize) -> Result<()> {
    let id = extract_id(target)?;
    let url = format!("{}/rest/api/content/{}", auth.base, id);

    // Ask for both storage + view so we can serve either (Cloud & Server/DC)
    let client = http_client();
    let resp = client
        .get(&url)
        .query(&[(
            "expand",
            "body.storage,body.view,space,version,history.lastUpdated,_links",
        )])
        .basic_auth(&auth.email, Some(&auth.token))
        .header(ACCEPT, "application/json")
        .send()
        .context("HTTP request failed")?;

    if !resp.status().is_success() {
        bail!(
            "HTTP {}: {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }

    let data: ContentExpanded = resp
        .json()
        .context("Failed to parse JSON from Confluence")?;
    let web_url = data
        .links
        .as_ref()
        .and_then(|l| l.webui.as_ref())
        .map(|p| format!("{}{}", auth.base, p));
    let (when, _) = match data.history.as_ref().and_then(|h| h.last_updated.as_ref()) {
        Some(lu) => (
            lu.when.clone(),
            lu.by.as_ref().and_then(|u| u.display_name.clone()),
        ),
        None => (None, None),
    };

    let storage = data
        .body
        .as_ref()
        .and_then(|b| b.storage.as_ref())
        .map(|p| p.value.clone());
    let view = data
        .body
        .as_ref()
        .and_then(|b| b.view.as_ref())
        .map(|p| p.value.clone());

    let (format_used, body_text, body_view_html, body_storage) = match format {
        "text" => {
            let html = view.clone().or_else(|| storage.clone()).unwrap_or_default();
            let text = html2text::from_read(html.as_bytes(), width);
            ("text".into(), Some(text), None, None)
        }
        "view" => ("view".into(), None, view.clone(), None),
        "storage" => ("storage".into(), None, None, storage.clone()),
        other => bail!("Unsupported --format '{}'. Use text|view|storage.", other),
    };

    let out = ReadOut {
        id: data.id,
        r#type: data.kind,
        title: data.title,
        space_key: data.space.as_ref().and_then(|s| s.key.clone()),
        space_name: data.space.as_ref().and_then(|s| s.name.clone()),
        last_modified: when,
        url: web_url,
        version: data.version,
        format_used,
        body_text,
        body_view_html,
        body_storage,
    };

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
