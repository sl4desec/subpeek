use regex::Regex;
use reqwest::{redirect, Client};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::process;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Serialize, Debug, Clone)]
struct SubdomainResult {
    subdomain: String,
    ip: Option<String>,
    status_code: Option<u16>,
    title: Option<String>,
    server: Option<String>,
    content_length: Option<u64>,
}

#[derive(Debug, Clone)]
struct WildcardProfile {
    ip: Option<String>,
    status_code: Option<u16>,
    title: Option<String>,
    content_length: Option<u64>,
}

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

#[derive(Deserialize)]
struct OtxUrl {
    hostname: String,
}

#[derive(Deserialize)]
struct OtxResp {
    url_list: Vec<OtxUrl>,
}

const TOP_SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "m",
    "shop",
    "ftp",
    "mail2",
    "test",
    "portal",
    "ns",
    "ww1",
    "host",
    "dev",
    "support",
    "admin",
    "web",
    "api",
    "cloud",
    "data",
    "app",
    "autodiscover",
    "autoconfig",
];

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: subpeek_core <domain>");
        process::exit(1);
    }
    let domain = &args[1];

    // 0. Wildcard Detection
    eprintln!("[*] Checking for Wildcard DNS...");
    let wildcard_profile = detect_wildcard(domain).await;
    if let Some(ref profile) = wildcard_profile {
        eprintln!(
            "[!] Wildcard DNS detected. IP: {:?}, Title: {:?}. Filtering junk results...",
            profile.ip, profile.title
        );
    }

    // 1. Discovery Phase
    eprintln!("[*] Discovering subdomains concurrently...");
    let mut candidates = fetch_all_subdomains(domain).await;

    for sub in TOP_SUBDOMAINS {
        candidates.insert(format!("{}.{}", sub, domain));
    }
    let total_candidates = candidates.len();
    eprintln!(
        "[*] Found {} potential subdomains. Verifying...",
        total_candidates
    );

    // 2. DNS Verification Phase
    let resolved = verify_dns(candidates).await;
    let resolvable_count = resolved.len();
    eprintln!(
        "[*] {} subdomains resolved. Probing HTTP...",
        resolvable_count
    );

    // 3. HTTP Probing Phase
    let mut final_results = probe_http(resolved).await;

    // 4. Filtering Phase
    if let Some(profile) = wildcard_profile {
        let before_count = final_results.len();
        final_results.retain(|r| !is_wildcard_match(r, &profile));
        eprintln!(
            "[*] Filtered {} false positives (Wildcard matches).",
            before_count - final_results.len()
        );
    }

    let json_output =
        serde_json::to_string_pretty(&final_results).unwrap_or_else(|_| "[]".to_string());
    println!("{}", json_output);

    eprintln!(
        "[+] Done. Found {} unique valid subdomains.",
        final_results.len()
    );
}

async fn detect_wildcard(domain: &str) -> Option<WildcardProfile> {
    // Generate a random subdomain unlikely to exist
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let random_sub = format!("wildcard-test-{}.{}", nanos, domain);

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
    let ip = match resolver.lookup_ip(&random_sub).await {
        Ok(lookup) => lookup.iter().next().map(|ip| ip.to_string()),
        Err(_) => return None, // If DNS fails, no wildcard DNS (usually)
    };

    // If it resolves, check HTTP response to build a profile
    // Make a fake result to reuse probe logic, but just doing a single request here for simplicity
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let protocols = ["https", "http"];
    let mut status = None;
    let mut title = None;
    let mut content_length = None;

    let title_regex = Regex::new(r"(?i)<title>(.*?)</title>").unwrap();

    for proto in protocols {
        let url = format!("{}://{}", proto, random_sub);
        if let Ok(resp) = client.get(&url).send().await {
            status = Some(resp.status().as_u16());
            content_length = resp.content_length();
            if let Ok(text) = resp.text().await {
                // If content length wasn't in header, use body length
                if content_length.is_none() {
                    content_length = Some(text.len() as u64);
                }
                if let Some(caps) = title_regex.captures(&text) {
                    if let Some(m) = caps.get(1) {
                        title = Some(m.as_str().trim().to_string());
                    }
                }
            }
            break;
        }
    }

    Some(WildcardProfile {
        ip,
        status_code: status,
        title,
        content_length,
    })
}

fn is_wildcard_match(result: &SubdomainResult, profile: &WildcardProfile) -> bool {
    // IP Match is the strongest indicator if combined with same content
    let ip_match = result.ip == profile.ip;

    if !ip_match {
        return false;
    }

    // If IPs match, check content similarity
    // 1. Title Match
    if result.title == profile.title && result.title.is_some() {
        return true;
    }

    // 2. Content Length Match (Allow small variance)
    if let (Some(a), Some(b)) = (result.content_length, profile.content_length) {
        let diff = if a > b { a - b } else { b - a };
        if diff < 50 {
            // If length is very similar
            return true;
        }
    }

    // 3. If exact status code match and default title/no title
    if result.status_code == profile.status_code {
        // High risk of wildcard if titles are both None or empty
        if result.title.is_none() && profile.title.is_none() {
            return true;
        }
    }

    false
}

async fn fetch_all_subdomains(domain: &str) -> HashSet<String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubPeek/2.0")
        .build()
        .unwrap_or_default();

    let client = Arc::new(client);
    let subdomains = Arc::new(Mutex::new(HashSet::new()));
    let mut handles = Vec::new();

    // Source: Crt.sh
    {
        let c = client.clone();
        let s = subdomains.clone();
        let d = domain.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(subs) = fetch_crtsh(&c, &d).await {
                let mut lock = s.lock().await;
                lock.extend(subs);
            }
        }));
    }

    // Source: Anubis
    {
        let c = client.clone();
        let s = subdomains.clone();
        let d = domain.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(subs) = fetch_anubis(&c, &d).await {
                let mut lock = s.lock().await;
                lock.extend(subs);
            }
        }));
    }

    // Source: HackerTarget
    {
        let c = client.clone();
        let s = subdomains.clone();
        let d = domain.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(subs) = fetch_hackertarget(&c, &d).await {
                let mut lock = s.lock().await;
                lock.extend(subs);
            }
        }));
    }

    // Source: Sublist3r
    {
        let c = client.clone();
        let s = subdomains.clone();
        let d = domain.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(subs) = fetch_sublist3r(&c, &d).await {
                let mut lock = s.lock().await;
                lock.extend(subs);
            }
        }));
    }

    // Source: AlienVault
    {
        let c = client.clone();
        let s = subdomains.clone();
        let d = domain.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(subs) = fetch_alienvault(&c, &d).await {
                let mut lock = s.lock().await;
                lock.extend(subs);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let lock = subdomains.lock().await;
    lock.clone()
}

// --- Fetchers ---

async fn fetch_crtsh(
    client: &Client,
    domain: &str,
) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let res = client.get(&url).send().await?;
    if !res.status().is_success() {
        return Err("failed".into());
    }

    let text = res.text().await?;
    let entries: Vec<CrtShEntry> = serde_json::from_str(&text).unwrap_or_default();

    let mut subs = HashSet::new();
    let suffix = format!(".{}", domain);
    for e in entries {
        for line in e.name_value.split('\n') {
            let clean = line.trim().to_lowercase();
            if !clean.contains('*') && (clean == domain || clean.ends_with(&suffix)) {
                subs.insert(clean);
            }
        }
    }
    Ok(subs)
}

async fn fetch_anubis(
    client: &Client,
    domain: &str,
) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://jldc.me/anubis/subdomains/{}", domain);
    let res = client.get(&url).send().await?;
    if !res.status().is_success() {
        return Err("failed".into());
    }
    let entries: Vec<String> = res.json().await.unwrap_or_default();
    Ok(filter_subs(entries, domain))
}

async fn fetch_hackertarget(
    client: &Client,
    domain: &str,
) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let res = client.get(&url).send().await?;
    let text = res.text().await?;
    let mut subs = HashSet::new();
    let suffix = format!(".{}", domain);
    for line in text.lines() {
        if let Some(host) = line.split(',').next() {
            let clean = host.trim().to_lowercase();
            if clean == domain || clean.ends_with(&suffix) {
                subs.insert(clean);
            }
        }
    }
    Ok(subs)
}

async fn fetch_sublist3r(
    client: &Client,
    domain: &str,
) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://api.sublist3r.com/search.php?domain={}", domain);
    let res = client.get(&url).send().await?;
    let entries: Vec<String> = res.json().await.unwrap_or_default();
    Ok(filter_subs(entries, domain))
}

async fn fetch_alienvault(
    client: &Client,
    domain: &str,
) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list?limit=100&page=1",
        domain
    );
    let res = client.get(&url).send().await?;
    let resp: OtxResp = res.json().await.unwrap_or(OtxResp { url_list: vec![] });
    Ok(filter_subs(
        resp.url_list.into_iter().map(|u| u.hostname).collect(),
        domain,
    ))
}

fn filter_subs(raw: Vec<String>, domain: &str) -> HashSet<String> {
    let mut s = HashSet::new();
    let suffix = format!(".{}", domain);
    for r in raw {
        let clean = r.trim().to_lowercase();
        if clean == domain || clean.ends_with(&suffix) {
            s.insert(clean);
        }
    }
    s
}

async fn verify_dns(candidates: HashSet<String>) -> Vec<(String, String)> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
    let resolver = Arc::new(resolver);
    let semaphore = Arc::new(Semaphore::new(200));
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut tasks = Vec::new();

    for sub in candidates {
        let r = resolver.clone();
        let s = semaphore.clone();
        let res_list = results.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = s.acquire().await.unwrap();
            if let Ok(lookup) = r.lookup_ip(sub.as_str()).await {
                if let Some(ip) = lookup.iter().next() {
                    let mut lock = res_list.lock().await;
                    lock.push((sub, ip.to_string()));
                }
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    let lock = results.lock().await;
    lock.clone()
}

async fn probe_http(targets: Vec<(String, String)>) -> Vec<SubdomainResult> {
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(redirect::Policy::limited(3))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let client = Arc::new(client);
    let semaphore = Arc::new(Semaphore::new(50));
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut tasks = Vec::new();

    let title_regex = Regex::new(r"(?i)<title>(.*?)</title>").unwrap();

    for (sub, ip) in targets {
        let c = client.clone();
        let s = semaphore.clone();
        let r_list = results.clone();
        let re = title_regex.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = s.acquire().await.unwrap();

            let protocols = ["https", "http"];
            let mut status = None;
            let mut title = None;
            let mut server = None;
            let mut content_length = None;

            for proto in protocols {
                let url = format!("{}://{}", proto, sub);
                if let Ok(resp) = c.get(&url).send().await {
                    status = Some(resp.status().as_u16());
                    content_length = resp.content_length();
                    if let Some(h) = resp.headers().get("server") {
                        server = h.to_str().ok().map(|s| s.to_string());
                    }
                    if let Ok(text) = resp.text().await {
                        if content_length.is_none() {
                            content_length = Some(text.len() as u64);
                        }
                        if let Some(caps) = re.captures(&text) {
                            if let Some(m) = caps.get(1) {
                                title = Some(m.as_str().trim().to_string());
                            }
                        }
                    }
                    break;
                }
            }

            let result = SubdomainResult {
                subdomain: sub,
                ip: Some(ip),
                status_code: status,
                title,
                server,
                content_length,
            };

            let mut lock = r_list.lock().await;
            lock.push(result);
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    let lock = results.lock().await;
    lock.clone()
}
