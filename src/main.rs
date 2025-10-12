use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use native_tls::TlsConnector as NativeTlsConnector;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as TokioTlsConnector;

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_RESOLVER: &str = "/meta";
const PROXY_FILE: &str = "Data/emeliaProxyIP15AGS.txt"; //Input
const OUTPUT_AZ: &str = "Data/alive.txt"; //Output dalam susunan A-Z
const OUTPUT_PRIORITY: &str = "Data/Country-ALIVE.txt"; //Output dalam susunan PRIORITY_COUNTRIES lalu A-Z
const MAX_CONCURRENT: usize = 175;
const TIMEOUT_SECONDS: u64 = 9;
const PRIORITY_COUNTRIES: [&str; 3] = ["ID", "MY","SG", "HK"];

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone)]
struct ProxyEntry {
    ip: String,
    port: u16,
    country: String,
    org: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting proxy scanner...");

    // Create output directories
    for output_file in &[OUTPUT_AZ, OUTPUT_PRIORITY] {
        if let Some(parent) = Path::new(output_file).parent() {
            fs::create_dir_all(parent)?;
        }
        File::create(output_file)?;
    }

    println!("Output files have been cleared/created before scanning.");

    // Read proxy list from file
    let proxies = match read_proxy_file(PROXY_FILE) {
        Ok(proxies) => proxies,
        Err(e) => {
            eprintln!("Error reading proxy file: {}", e);
            return Err(e.into());
        }
    };

    println!("Loaded {} proxies from file", proxies.len());

    // Get original IP (without proxy)
    let original_ip_data = match check_connection(IP_RESOLVER, PATH_RESOLVER, None).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to get original IP info: {}", e);
            return Err(e.into());
        }
    };

    let original_ip = match original_ip_data.get("clientIp") {
        Some(Value::String(ip)) => ip.clone(),
        _ => {
            eprintln!("Failed to extract original client IP from response: {:?}", original_ip_data);
            return Err("Failed to extract original client IP".into());
        }
    };

    println!("Original IP: {}", original_ip);

    // Store active proxies
    let active_proxies = Arc::new(Mutex::new(Vec::new()));

    // Process proxies concurrently
    let tasks = futures::stream::iter(
        proxies.into_iter().map(|proxy_line| {
            let original_ip = original_ip.clone();
            let active_proxies = Arc::clone(&active_proxies);
            async move {
                process_proxy(proxy_line, &original_ip, &active_proxies).await;
            }
        })
    ).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();

    tasks.await;

    // Process and save results
    let active_proxies_locked = active_proxies.lock().unwrap();
    
    if !active_proxies_locked.is_empty() {
        // Remove duplicates
        let unique_proxies = remove_duplicates(active_proxies_locked.clone());
        println!("Found {} unique proxies (after removing duplicates)", unique_proxies.len());

        // Create mutable copies for sorting
        let mut az_sorted = unique_proxies.clone();
        let mut priority_sorted = unique_proxies;

        // Sorting A-Z
        sort_az_countries(&mut az_sorted);
        save_proxies_to_file(&az_sorted, OUTPUT_AZ)?;
        println!("A-Z sorted proxies saved to {}", OUTPUT_AZ);

        // Sorting priority (ID → SG → MY → A-Z others)
        sort_priority_countries(&mut priority_sorted);
        save_proxies_to_file(&priority_sorted, OUTPUT_PRIORITY)?;
        println!("Priority sorted proxies saved to {}", OUTPUT_PRIORITY);

        // Print summary
        print_sorting_summary(&priority_sorted);
    } else {
        println!("No active proxies found");
    }

    println!("Proxy checking completed.");
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            proxies.push(line);
        }
    }

    Ok(proxies)
}

async fn check_connection(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>,
) -> Result<Value> {
    let timeout_duration = Duration::from_secs(TIMEOUT_SECONDS);

    match tokio::time::timeout(timeout_duration, async {
        let payload = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n\
             Connection: close\r\n\r\n",
            path, host
        );

        let stream = if let Some((proxy_ip, proxy_port)) = proxy {
            let connect_addr = if proxy_ip.contains(':') {
                format!("[{}]:{}", proxy_ip, proxy_port)
            } else {
                format!("{}:{}", proxy_ip, proxy_port)
            };
            TcpStream::connect(connect_addr).await?
        } else {
            TcpStream::connect(format!("{}:443", host)).await?
        };

        let native_connector = NativeTlsConnector::builder().build()?;
        let tokio_connector = TokioTlsConnector::from(native_connector);
        let mut tls_stream = tokio_connector.connect(host, stream).await?;

        tls_stream.write_all(payload.as_bytes()).await?;

        let mut response = Vec::new();
        let mut buffer = [0; 4096];

        loop {
            match tls_stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        }

        let response_str = String::from_utf8_lossy(&response);

        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];
            match serde_json::from_str::<Value>(body.trim()) {
                Ok(json_data) => Ok(json_data),
                Err(e) => {
                    eprintln!("Failed to parse JSON: {}", e);
                    Err("Invalid JSON response".into())
                }
            }
        } else {
            Err("Invalid HTTP response: No separator found".into())
        }
    }).await {
        Ok(inner_result) => inner_result,
        Err(_) => Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, "Connection attempt timed out")) as Box<dyn std::error::Error + Send + Sync>),
    }
}

fn clean_org_name(org_name: &str) -> String {
    org_name.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect()
}

async fn process_proxy(
    proxy_line: String,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<ProxyEntry>>>,
) {
    let parts: Vec<&str> = proxy_line.split(',').collect();
    if parts.len() < 4 {
        println!("Invalid proxy line format: {}. Expected ip,port,country,org", proxy_line);
        return;
    }

    let ip = parts[0];
    let port_str = parts[1];
    let country = parts[2];
    let org = parts[3];

    let port_num = match port_str.parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            println!("Invalid port number: {} in line: {}", port_str, proxy_line);
            return;
        }
    };

    match check_connection(IP_RESOLVER, PATH_RESOLVER, Some((ip, port_num))).await {
        Ok(proxy_data) => {
            if let Some(Value::String(proxy_ip)) = proxy_data.get("clientIp") {
                if proxy_ip != original_ip {
                    let org_name_from_response = if let Some(Value::String(org_val)) = proxy_data.get("asOrganization") {
                        clean_org_name(org_val)
                    } else {
                        clean_org_name(org)
                    };

                    let proxy_entry = ProxyEntry {
                        ip: ip.to_string(),
                        port: port_num,
                        country: country.to_string(),
                        org: org_name_from_response,
                    };
                    
                    println!("CF PROXY LIVE ✅: {}:{} - {}", ip, port_num, country);

                    let mut active_proxies_locked = active_proxies.lock().unwrap();
                    active_proxies_locked.push(proxy_entry);
                } else {
                    println!("CF PROXY DEAD ❌ (Same IP as original): {}:{}", ip, port_num);
                }
            } else {
                println!("CF PROXY DEAD ❌ (No clientIp field in response): {}:{}", ip, port_num);
            }
        },
        Err(e) => {
            println!("CF PROXY DEAD ⏱️ (Error connecting): {}:{} - {}", ip, port_num, e);
        }
    }
}

fn remove_duplicates(proxies: Vec<ProxyEntry>) -> Vec<ProxyEntry> {
    use std::collections::HashSet;
    
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    
    for proxy in proxies {
        let key = format!("{}:{}", proxy.ip, proxy.port);
        if !seen.contains(&key) {
            seen.insert(key);
            unique.push(proxy);
        }
    }
    
    unique
}

fn sort_priority_countries(proxies: &mut [ProxyEntry]) {
    proxies.sort_by(|a, b| {
        let a_priority = PRIORITY_COUNTRIES.iter().position(|&c| c == a.country);
        let b_priority = PRIORITY_COUNTRIES.iter().position(|&c| c == b.country);
        
        match (a_priority, b_priority) {
            (Some(a_idx), Some(b_idx)) => a_idx.cmp(&b_idx),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.country.cmp(&b.country),
        }
    });
}

fn sort_az_countries(proxies: &mut [ProxyEntry]) {
    proxies.sort_by(|a, b| a.country.cmp(&b.country));
}

fn save_proxies_to_file(proxies: &[ProxyEntry], filename: &str) -> Result<()> {
    let mut file = File::create(filename)?;
    for proxy in proxies {
        writeln!(file, "{},{},{},{}", proxy.ip, proxy.port, proxy.country, proxy.org)?;
    }
    Ok(())
}

fn print_sorting_summary(proxies: &[ProxyEntry]) {
    use std::collections::HashMap;
    
    let mut counts: HashMap<String, usize> = HashMap::new();
    for proxy in proxies {
        *counts.entry(proxy.country.clone()).or_insert(0) += 1;
    }

    println!("\n=== PRIORITY SORTING SUMMARY ===");
    for priority_country in &PRIORITY_COUNTRIES {
        if let Some(count) = counts.get(*priority_country) {
            println!("{}: {} proxies", priority_country, count);
        }
    }
    
    println!("=== OTHER COUNTRIES (A-Z) ===");
    let mut other_countries: Vec<_> = counts.iter()
        .filter(|(country, _)| !PRIORITY_COUNTRIES.contains(&country.as_str()))
        .collect();
    
    other_countries.sort_by_key(|(country, _)| *country);
    
    for (country, count) in other_countries {
        println!("{}: {} proxies", country, count);
    }
}
