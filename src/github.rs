use eyre::{bail, ensure};
use inquire::{Select, Text};
use reqwest::blocking::{Client};
use reqwest::header::{ACCEPT, USER_AGENT};

use serde::Deserialize;
use std::collections::HashMap;
use std::io;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

const CLIENT_ID: &str = "0588399af06895a0a9ff";
const GITHUB_COM: &str = "github.com";
const JSON: &str = "application/json";
const GITHUB_JSON: &str = "application/vnd.github+json";
const API_VERSION_KEY: &str = "X-GitHub-Api-Version";
const API_VERSION: &str = "2022-11-28";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

pub fn register_keys(auth_key: &str, signing_key: &str) -> eyre::Result<()> {
    let (api_url, access_token) = authenticate_against_github()?;
    let name = Text::new("enter a name for the keys. This should be unique.")
        .with_default("cs-generated-key")
        .prompt()?;
    create_key(&api_url, &access_token, KeyPurpose::Comms, &name, auth_key)?;
    create_key(
        &api_url,
        &access_token,
        KeyPurpose::Signing,
        &name,
        signing_key,
    )?;
    Ok(())
}

#[derive(Clone, Copy)]
enum KeyPurpose {
    Comms,
    Signing,
}

fn create_key(
    api_hostname: &str,
    auth_token: &str,
    purpose: KeyPurpose,
    name: &str,
    key: &str,
) -> eyre::Result<()> {
    let client = Client::new();
    let endpoint = match purpose {
        KeyPurpose::Comms => "keys",
        KeyPurpose::Signing => "ssh_signing_keys",
    };
    let suffix = match purpose {
        KeyPurpose::Comms => "comms",
        KeyPurpose::Signing => "signing",
    };
    let mut form_entries = HashMap::new();
    form_entries.insert("title", format!("{name}-{suffix}"));
    form_entries.insert("key", key.to_string());
    let request = client
        .post(format!("https://{api_hostname}/user/{endpoint}"))
        .bearer_auth(auth_token)
        .header(ACCEPT, GITHUB_JSON)
        .header(API_VERSION_KEY, API_VERSION)
        .header(USER_AGENT, "commit-signer")
        .json(&form_entries)
        .build()?;
    let response = client.execute(request)?;
    if !response.status().is_success() {
        let body = response.text()?;
        let already_exists = body.contains("key is already in use");
        if already_exists {
            println!("key already registered under a different name");
            return Ok(());
        } else {
            bail!("unable to register key. Error result: {body}");
        }
    }
    println!("successfully registered token for {suffix}");
    Ok(())
}

fn authenticate_against_github() -> eyre::Result<(String, String)> {
    let kind = Select::new(
        "What account do you want to log into?",
        vec![GITHUB_COM, "github enterprise"],
    )
    .prompt()?;
    match kind {
        GITHUB_COM => authenticate_against_github_com(),
        _ => authenticate_against_github_enterprise(),
    }
}

fn authenticate_against_github_com() -> eyre::Result<(String, String)> {
    let device_auth = Select::new(
        "How would you like to log into github.com?",
        vec!["with a web browser", "with an api key"],
    )
    .raw_prompt()?
    .index;
    if device_auth != 0 {
        return authenticate_with_access_token("github.com");
    }

    let client = Client::new();

    let mut form = HashMap::new();
    form.insert("client_id", CLIENT_ID);
    form.insert(
        "scope",
        "read:ssh_signing_key write:ssh_signing_key read:public_key write:public_key",
    );

    let response = client
        .post("https://github.com/login/device/code")
        .form(&form)
        .header(ACCEPT, JSON)
        .send()?;

    let resp: DeviceCodeLoginResponse = response.json()?;

    println!("First, copy your one-time code: {}", resp.user_code);
    println!("Now, press enter to open a web browser");
    let mut _unused_string = String::new();
    io::stdin().read_line(&mut _unused_string)?;

    Command::new("open").arg(resp.verification_uri).status()?;

    let start = Instant::now();
    let timeout = Duration::from_secs(resp.expires_in);
    let interval = Duration::from_secs(resp.interval);
    let mut params = HashMap::new();
    params.insert("client_id", CLIENT_ID.to_string());
    params.insert("device_code", resp.device_code);
    params.insert("grant_type", GRANT_TYPE.to_string());
    while start.elapsed() < timeout {
        sleep(interval);
        let access_token_response = client
            .post("https://github.com/login/oauth/access_token")
            .form(&params)
            .header(ACCEPT, JSON)
            .send()?;
        ensure!(
            access_token_response.status().is_success(),
            "requesting a token should always be successful"
        );
        let response_string = access_token_response.text()?;
        let access_token_response: AccessTokenResponse = serde_json::from_str(&response_string)?;
        match access_token_response {
            AccessTokenResponse::Success { access_token, .. } => {
                return Ok(("api.github.com".to_string(), access_token))
            }
            AccessTokenResponse::Failure { error, .. } => {
                ensure!(
                    error == "authorization_pending",
                    "only expected to see authorization_pending error string, but saw {error}"
                )
            }
        }
    }
    bail!("User could not be authenticated before timeout {timeout:?}");
}

fn authenticate_against_github_enterprise() -> eyre::Result<(String, String)> {
    bail!("unfortunately, GitHub enterprise is not yet implemented. please use the manual approach");
}

fn authenticate_with_access_token(_domain: &str) -> eyre::Result<(String, String)> {
    bail!("unfortunately, non-automatic authentication is not yet implemented, please use the manual approach");
}

#[derive(Deserialize)]
struct DeviceCodeLoginResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AccessTokenResponse {
    Success { access_token: String },
    Failure { error: String },
}
