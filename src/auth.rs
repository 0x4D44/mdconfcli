use crate::{http_client, ConfAuth};
use anyhow::{anyhow, Context, Result};
use keyring::Entry;
use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};

const SERVICE: &str = "mdconfcli";
const USER: &str = "confluence";

#[derive(Debug, Serialize, Deserialize)]
struct StoredAuth {
    base: String,
    email: String,
    token: String,
}

pub fn load() -> Result<Option<ConfAuth>> {
    let entry = Entry::new(SERVICE, USER).map_err(|e| anyhow!("keyring init failed: {e}"))?;
    match entry.get_password() {
        Ok(secret) => {
            let s: StoredAuth = serde_json::from_str(&secret)
                .context("Failed to parse credentials from keychain")?;
            Ok(Some(ConfAuth {
                base: s.base,
                email: s.email,
                token: s.token,
            }))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("keyring read failed: {e}")),
    }
}

pub fn store(auth: &ConfAuth) -> Result<()> {
    let s = StoredAuth {
        base: auth.base.clone(),
        email: auth.email.clone(),
        token: auth.token.clone(),
    };
    let json = serde_json::to_string(&s)?;
    let entry = Entry::new(SERVICE, USER).map_err(|e| anyhow!("keyring init failed: {e}"))?;
    entry
        .set_password(&json)
        .map_err(|e| anyhow!("keyring write failed: {e}"))
}

pub fn check(auth: &ConfAuth) -> Result<()> {
    // Lightweight probe to validate credentials
    let url = format!("{}/rest/api/space?limit=1", auth.base);
    let client = http_client();
    let resp = client
        .get(&url)
        .basic_auth(&auth.email, Some(&auth.token))
        .header(ACCEPT, "application/json")
        .send()
        .context("Auth check request failed")?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!("HTTP {} during auth check", resp.status()))
    }
}

pub fn resolve_interactive() -> Result<ConfAuth> {
    if let Some(a) = load()? {
        if check(&a).is_ok() {
            return Ok(a);
        }
        eprintln!("Stored credentials appear invalid. Let's update them.");
    } else {
        eprintln!("No credentials found. Let's set them up.");
    }

    let base = prompt(
        "Confluence base URL (e.g. https://your-domain.atlassian.net/wiki): ",
        None,
    )?;
    let email = prompt("Email/username (e.g. you@example.com): ", None)?;
    let token = prompt_secret("API token (input hidden): ")?;

    let auth = ConfAuth {
        base: base.trim_end_matches('/').to_string(),
        email,
        token,
    };
    store(&auth)?;
    check(&auth).context("Stored credentials failed to authenticate")?;
    Ok(auth)
}

pub fn init_flow(force: bool) -> Result<()> {
    if force {
        eprintln!("Forcing credential reinitialization.");
        let base = prompt(
            "Confluence base URL (e.g. https://your-domain.atlassian.net/wiki): ",
            None,
        )?;
        let email = prompt("Email/username (e.g. you@example.com): ", None)?;
        let token = prompt_secret("API token (input hidden): ")?;

        let auth = ConfAuth {
            base: base.trim_end_matches('/').to_string(),
            email,
            token,
        };
        store(&auth)?;
        check(&auth).context("Stored credentials failed to authenticate")?;
        eprintln!("Credentials saved to Windows Credential Manager.");
        return Ok(());
    }

    match load()? {
        Some(a) => {
            if check(&a).is_ok() {
                eprintln!("Credentials already valid; no changes made.");
                return Ok(());
            }
            eprintln!("Stored credentials appear invalid. Let's update them.");
        }
        None => {
            eprintln!("No credentials found. Let's set them up.");
        }
    }

    let base = prompt(
        "Confluence base URL (e.g. https://your-domain.atlassian.net/wiki): ",
        None,
    )?;
    let email = prompt("Email/username (e.g. you@example.com): ", None)?;
    let token = prompt_secret("API token (input hidden): ")?;

    let auth = ConfAuth {
        base: base.trim_end_matches('/').to_string(),
        email,
        token,
    };
    store(&auth)?;
    check(&auth).context("Stored credentials failed to authenticate")?;
    eprintln!("Credentials saved to Windows Credential Manager.");
    Ok(())
}

fn prompt(msg: &str, default: Option<&str>) -> Result<String> {
    use std::io::{stdin, stdout, Write};
    let mut out = String::new();
    loop {
        if let Some(d) = default {
            print!("{}[{}] ", msg, d);
        } else {
            print!("{}", msg);
        }
        stdout().flush().ok();
        out.clear();
        stdin().read_line(&mut out)?;
        let v = out.trim().to_string();
        if !v.is_empty() {
            return Ok(v);
        }
        if let Some(d) = default {
            return Ok(d.to_string());
        }
    }
}

fn prompt_secret(msg: &str) -> Result<String> {
    let v = rpassword::prompt_password(msg)?;
    Ok(v.trim().to_string())
}
