//! Nexus Mods API client.
//!
//! * Public metadata comes from the v2 GraphQL API (no key needed).
//! * Premium download links and MD5 verification use the v1 REST API with the
//!   owner's personal API key. The key is only ever placed in the `apikey`
//!   request header and is never printed, logged or written anywhere.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

const GRAPHQL: &str = "https://api.nexusmods.com/v2/graphql";
const V1: &str = "https://api.nexusmods.com/v1";
pub const APP_NAME: &str = "skyforge";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Nexus {
    http: Client,
    key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    #[serde(rename = "fileId")]
    pub file_id: u64,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    pub category: String,
    pub date: i64,
    #[serde(rename = "sizeInBytes", default, deserialize_with = "de_opt_u64_str")]
    pub size_in_bytes: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
    /// Archive file name as stored on Nexus.
    pub uri: String,
}

fn de_opt_u64_str<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<u64>, D::Error> {
    let v = Option::<Value>::deserialize(d)?;
    Ok(match v {
        Some(Value::String(s)) => s.parse().ok(),
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    })
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModInfo {
    #[serde(rename = "modId")]
    pub mod_id: u64,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: Option<String>,
    #[serde(rename = "adultContent", default)]
    pub adult_content: bool,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub is_premium: bool,
    #[serde(default)]
    pub is_supporter: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Md5Hit {
    #[serde(rename = "mod")]
    pub mod_: Md5Mod,
    pub file_details: Md5File,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Md5Mod {
    pub mod_id: u64,
}
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Md5File {
    pub file_id: u64,
    #[serde(default)]
    pub md5: Option<String>,
    #[serde(default)]
    pub size_in_bytes: Option<u64>,
    #[serde(default)]
    pub file_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DownloadLink {
    #[serde(rename = "URI")]
    uri: String,
    #[serde(default)]
    short_name: String,
}

impl Nexus {
    pub fn new(key_file: Option<&Path>) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert("Application-Name", HeaderValue::from_static(APP_NAME));
        headers.insert("Application-Version", HeaderValue::from_static(APP_VERSION));
        let http = Client::builder()
            .user_agent(format!("{APP_NAME}/{APP_VERSION} (Linux; x86_64) rust-reqwest"))
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(30))
            .timeout(None)
            .build()?;
        let key = match key_file {
            Some(p) if p.exists() => {
                let k = std::fs::read_to_string(p)
                    .with_context(|| format!("reading API key file {}", p.display()))?
                    .trim()
                    .to_string();
                if k.is_empty() {
                    bail!("API key file {} is empty", p.display());
                }
                Some(k)
            }
            _ => None,
        };
        Ok(Nexus { http, key })
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub fn http(&self) -> &Client {
        &self.http
    }

    // ---------- public GraphQL ----------

    pub fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        let mut last_err = None;
        for attempt in 0..4 {
            let r = self
                .http
                .post(GRAPHQL)
                .timeout(Duration::from_secs(60))
                .json(&json!({ "query": query, "variables": variables }))
                .send();
            match r {
                Ok(resp) if resp.status().is_success() => {
                    let v: Value = resp.json()?;
                    if let Some(errs) = v.get("errors") {
                        bail!("GraphQL error: {errs}");
                    }
                    return Ok(v["data"].clone());
                }
                Ok(resp) => last_err = Some(anyhow!("GraphQL HTTP {}", resp.status())),
                Err(e) => last_err = Some(anyhow!(e)),
            }
            std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
        }
        Err(last_err.unwrap())
    }

    pub fn mod_files(&self, game_id: u64, mod_id: u64) -> Result<Vec<FileInfo>> {
        let q = "query($m:ID!,$g:ID!){ modFiles(modId:$m, gameId:$g){ fileId name version category date sizeInBytes description uri } }";
        let d = self.graphql(q, json!({ "m": mod_id.to_string(), "g": game_id.to_string() }))?;
        Ok(serde_json::from_value(d["modFiles"].clone())?)
    }

    #[allow(dead_code)]
    pub fn mods_info(&self, domain: &str, mod_ids: &[u64]) -> Result<Vec<ModInfo>> {
        let mut out = Vec::new();
        for chunk in mod_ids.chunks(40) {
            let ids: Vec<Value> = chunk
                .iter()
                .map(|m| json!({ "gameDomain": domain, "modId": m }))
                .collect();
            let q = "query($ids:[CompositeDomainWithIdInput!]!){ legacyModsByDomain(ids:$ids){ nodes { modId name version author updatedAt adultContent status } } }";
            let d = self.graphql(q, json!({ "ids": ids }))?;
            let nodes: Vec<ModInfo> = serde_json::from_value(d["legacyModsByDomain"]["nodes"].clone())?;
            out.extend(nodes);
        }
        Ok(out)
    }

    // ---------- authenticated v1 REST ----------

    fn v1_get(&self, path: &str) -> Result<Response> {
        let key = self
            .key
            .as_deref()
            .ok_or_else(|| anyhow!("no Nexus API key configured"))?;
        // Transient failures (DNS, connect, timeouts, 5xx) are retried with backoff; 429 is not.
        let mut attempt = 0;
        let resp = loop {
            let r = self
                .http
                .get(format!("{V1}{path}"))
                .header("apikey", key)
                .timeout(Duration::from_secs(60))
                .send();
            let retry = match &r {
                Ok(resp) => resp.status().is_server_error(),
                Err(_) => true,
            };
            if !retry || attempt == 3 {
                break r.with_context(|| format!("GET {path}"))?;
            }
            attempt += 1;
            eprintln!("  GET {path} failed transiently; retry {attempt}/3");
            std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
        };
        // Respect rate limits: back off well before exhaustion.
        let hourly = resp
            .headers()
            .get("x-rl-hourly-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok());
        let daily = resp
            .headers()
            .get("x-rl-daily-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok());
        if let (Some(h), Some(d)) = (hourly, daily) {
            if d < 50 && h < 10 {
                eprintln!("  rate limit low (daily {d}, hourly {h}); pausing 120 s");
                std::thread::sleep(Duration::from_secs(120));
            }
        }
        if resp.status().as_u16() == 429 {
            bail!("Nexus API rate limit reached (HTTP 429)");
        }
        Ok(resp)
    }

    pub fn validate(&self) -> Result<UserInfo> {
        let r = self.v1_get("/users/validate.json")?;
        if !r.status().is_success() {
            bail!("API key validation failed: HTTP {}", r.status());
        }
        Ok(r.json()?)
    }

    /// Premium-only direct download URLs for a file (ordered by Nexus preference).
    pub fn download_links(&self, domain: &str, mod_id: u64, file_id: u64) -> Result<Vec<String>> {
        let r = self.v1_get(&format!(
            "/games/{domain}/mods/{mod_id}/files/{file_id}/download_link.json"
        ))?;
        let status = r.status();
        if !status.is_success() {
            let body = r.text().unwrap_or_default();
            bail!("download_link for {mod_id}/{file_id}: HTTP {status}: {}", body.chars().take(300).collect::<String>());
        }
        let links: Vec<DownloadLink> = r.json()?;
        if links.is_empty() {
            bail!("no download links returned for {mod_id}/{file_id}");
        }
        // Prefer the CDN entry Nexus lists as "Nexus CDN" if present, else keep the given order.
        let mut v: Vec<(bool, String)> = links
            .into_iter()
            .map(|l| (l.short_name.eq_ignore_ascii_case("Nexus CDN"), l.uri))
            .collect();
        v.sort_by_key(|(cdn, _)| !*cdn);
        Ok(v.into_iter().map(|(_, u)| u).collect())
    }

    /// v1 file details; used for the canonical archive file name and size.
    pub fn file_details(&self, domain: &str, mod_id: u64, file_id: u64) -> Result<(String, Option<u64>)> {
        let r = self.v1_get(&format!("/games/{domain}/mods/{mod_id}/files/{file_id}.json"))?;
        if !r.status().is_success() {
            bail!("file details {mod_id}/{file_id}: HTTP {}", r.status());
        }
        let v: Value = r.json()?;
        let name = v["file_name"]
            .as_str()
            .ok_or_else(|| anyhow!("file details {mod_id}/{file_id} lack file_name"))?
            .to_string();
        Ok((name, v["size_in_bytes"].as_u64()))
    }

    pub fn md5_search(&self, domain: &str, md5: &str) -> Result<Vec<Md5Hit>> {
        let r = self.v1_get(&format!("/games/{domain}/mods/md5_search/{md5}.json"))?;
        if r.status().as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !r.status().is_success() {
            bail!("md5_search HTTP {}", r.status());
        }
        Ok(r.json()?)
    }
}
