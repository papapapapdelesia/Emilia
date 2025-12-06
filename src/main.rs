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
const PATH_HOME: &str = "/";
const PATH_META: &str = "/meta";
const PROXY_FILE: &str = "Data/IPPROXY23K.txt";
const OUTPUT_AZ: &str = "Data/alive.txt";
const OUTPUT_PRIORITY: &str = "Data/Country-ALIVE.txt";
const MAX_CONCURRENT: usize = 180;
const TIMEOUT_SECONDS: u64 = 15;
const PRIORITY_COUNTRIES: [&str; 4] = ["ID","MY","SG","HK"];

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone)]
struct ProxyEntry {
    ip: String,
    port: u16,
    country: String,
    org: String,
}

#[derive(Debug, Clone)]
struct CookieJar {
    cookies: Vec<String>,
}

impl CookieJar {
    fn new() -> Self {
        Self { cookies: Vec::new() }
    }
    
    fn add_from_headers(&mut self, headers: &str) {
        for line in headers.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("set-cookie:") {
                let cookie = line[11..].trim();
                if let Some(cookie_value) = cookie.split(';').next() {
                    self.cookies.push(cookie_value.to_string());
                }
            }
        }
    }
    
    fn to_header(&self) -> String {
        if self.cookies.is_empty() {
            String::new()
        } else {
            format!("Cookie: {}\r\n", self.cookies.join("; "))
        }
    }
    
    fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("==========================================");
    println!("   CLOUDFLARE PROXY SCANNER v2.0");
    println!("==========================================");

    // Create output directories
    for output_file in &[OUTPUT_AZ, OUTPUT_PRIORITY] {
        if let Some(parent) = Path::new(output_file).parent() {
            fs::create_dir_all(parent)?;
        }
        File::create(output_file)?;
    }

    println!("✓ Output files created: {} & {}", OUTPUT_AZ, OUTPUT_PRIORITY);

    // Read proxy list from file
    let proxies = match read_proxy_file(PROXY_FILE) {
        Ok(proxies) => proxies,
        Err(e) => {
            eprintln!("✗ Error reading proxy file: {}", e);
            return Err(e.into());
        }
    };

    println!("✓ Loaded {} proxies from {}", proxies.len(), PROXY_FILE);

    // Get original IP (without proxy) for comparison
    println!("\n[1/3] Getting original IP information...");
    let original_ip_data = match get_original_ip_info().await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("✗ Failed to get original IP info: {}", e);
            return Err(e.into());
        }
    };

    let original_ip = match original_ip_data.get("clientIp") {
        Some(Value::String(ip)) => ip.clone(),
        _ => {
            eprintln!("✗ Failed to extract original client IP");
            return Err("Failed to extract original client IP".into());
        }
    };

    println!("✓ Original IP: {}", original_ip);
    if let Some(Value::String(country)) = original_ip_data.get("country") {
        println!("✓ Original Location: {}", country);
    }

    // Store active proxies
    let active_proxies = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(Mutex::new((0u32, proxies.len())));

    println!("\n[2/3] Scanning proxies ({} concurrent)...", MAX_CONCURRENT);
    println!("==========================================");

    // Process proxies concurrently
    let tasks = futures::stream::iter(
        proxies.into_iter().enumerate().map(|(idx, proxy_line)| {
            let original_ip = original_ip.clone();
            let active_proxies = Arc::clone(&active_proxies);
            let counter = Arc::clone(&counter);
            
            async move {
                let result = process_proxy_with_session(idx, proxy_line, &original_ip, &active_proxies).await;
                
                // Update progress
                let mut counter_lock = counter.lock().unwrap();
                counter_lock.0 += 1;
                if counter_lock.0 % 100 == 0 || counter_lock.0 == counter_lock.1 as u32 {
                    println!("  Progress: {}/{} ({:.1}%)", 
                           counter_lock.0, counter_lock.1,
                           (counter_lock.0 as f32 / counter_lock.1 as f32) * 100.0);
                }
                
                result
            }
        })
    ).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();

    tasks.await;

    // Process and save results
    println!("\n[3/3] Processing results...");
    println!("==========================================");
    
    let active_proxies_locked = active_proxies.lock().unwrap();
    
    if !active_proxies_locked.is_empty() {
        // Remove duplicates
        let unique_proxies = remove_duplicates(active_proxies_locked.clone());
        println!("✓ Found {} unique active proxies", unique_proxies.len());

        // Create mutable copies for sorting
        let mut az_sorted = unique_proxies.clone();
        let mut priority_sorted = unique_proxies;

        // Sorting A-Z
        sort_az_countries(&mut az_sorted);
        if let Err(e) = save_proxies_to_file(&az_sorted, OUTPUT_AZ) {
            eprintln!("✗ Error saving A-Z file: {}", e);
        } else {
            println!("✓ A-Z sorted proxies saved to {}", OUTPUT_AZ);
        }

        // Sorting priority (ID → MY → SG → HK → A-Z others)
        sort_priority_countries(&mut priority_sorted);
        if let Err(e) = save_proxies_to_file(&priority_sorted, OUTPUT_PRIORITY) {
            eprintln!("✗ Error saving priority file: {}", e);
        } else {
            println!("✓ Priority sorted proxies saved to {}", OUTPUT_PRIORITY);
        }

        // Print summary
        print_sorting_summary(&priority_sorted);
    } else {
        println!("✗ No active proxies found");
    }

    println!("\n==========================================");
    println!("   SCANNING COMPLETED SUCCESSFULLY!");
    println!("==========================================");
    
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            proxies.push(trimmed.to_string());
        }
    }

    Ok(proxies)
}

async fn get_original_ip_info() -> Result<Value> {
    let mut cookie_jar = CookieJar::new();
    
    // Step 1: Access homepage to get cookies
    if let Err(e) = make_request(IP_RESOLVER, PATH_HOME, None, &mut cookie_jar, false).await {
        eprintln!("  Warning: Failed to get homepage cookies: {}", e);
    }
    
    // Step 2: Access meta endpoint with cookies
    let (_, body) = make_request(IP_RESOLVER, PATH_META, None, &mut cookie_jar, true).await?;
    
    parse_json_response(&body)
}

async fn make_request(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>,
    cookie_jar: &mut CookieJar,
    is_meta_request: bool,
) -> Result<(String, String)> {
    let timeout_duration = Duration::from_secs(TIMEOUT_SECONDS);
    
    tokio::time::timeout(timeout_duration, async {
        // Build request headers
        let mut headers = Vec::new();
        
        // Basic headers
        headers.push(format!("Host: {}", host));
        headers.push("User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36".to_string());
        headers.push("Accept: */*".to_string());
        headers.push("Accept-Language: en-US,en;q=0.8".to_string());
        headers.push("Accept-Encoding: gzip, deflate, br".to_string());
        headers.push("Connection: close".to_string());
        
        // Add cookies if available
        let cookie_header = cookie_jar.to_header();
        if !cookie_header.is_empty() {
            headers.push(cookie_header);
        }
        
        // Add specific headers for meta request
        if is_meta_request {
            headers.push("Referer: https://speed.cloudflare.com/".to_string());
            headers.push("Sec-Fetch-Dest: empty".to_string());
            headers.push("Sec-Fetch-Mode: cors".to_string());
            headers.push("Sec-Fetch-Site: same-origin".to_string());
            headers.push("Sec-Ch-Ua: \"Brave\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"".to_string());
            headers.push("Sec-Ch-Ua-Mobile: ?0".to_string());
            headers.push("Sec-Ch-Ua-Platform: \"Linux\"".to_string());
            headers.push("Sec-Gpc: 1".to_string());
        }
        
        // Build the complete request
        let headers_str = headers.join("\r\n");
        let request = format!(
            "GET {} HTTP/1.1\r\n{}\r\n\r\n",
            path, headers_str
        );

        // Establish connection
        let stream = if let Some((proxy_ip, proxy_port)) = proxy {
            let connect_addr = format!("{}:{}", proxy_ip, proxy_port);
            TcpStream::connect(&connect_addr).await?
        } else {
            TcpStream::connect(format!("{}:443", host)).await?
        };

        // Setup TLS connector
        let native_connector = NativeTlsConnector::builder()
            .danger_accept_invalid_certs(false)
            .build()?;
        let tokio_connector = TokioTlsConnector::from(native_connector);
        
        // Establish TLS connection
        let mut tls_stream = match tokio_connector.connect(host, stream).await {
            Ok(stream) => stream,
            Err(e) => {
                return Err(format!("TLS connection failed: {}", e).into());
            }
        };

        // Send request
        if let Err(e) = tls_stream.write_all(request.as_bytes()).await {
            return Err(format!("Failed to send request: {}", e).into());
        }

        // Read response
        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];
        
        loop {
            match tls_stream.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => return Err(format!("Failed to read response: {}", e).into()),
            }
        }

        let response_str = String::from_utf8_lossy(&response).to_string();
        
        // Split headers and body
        if let Some(header_end) = response_str.find("\r\n\r\n") {
            let headers_part = &response_str[..header_end];
            let body = response_str[header_end + 4..].to_string();
            
            // Update cookies from response headers
            cookie_jar.add_from_headers(headers_part);
            
            Ok((headers_part.to_string(), body))
        } else {
            Err("Invalid HTTP response: No header/body separator found".into())
        }
    }).await.map_err(|_| "Request timeout".into())?
}

fn parse_json_response(response_body: &str) -> Result<Value> {
    let trimmed = response_body.trim();
    
    if trimmed.is_empty() {
        return Err("Empty response".into());
    }
    
    // Try to parse as JSON directly
    match serde_json::from_str::<Value>(trimmed) {
        Ok(json) => Ok(json),
        Err(_) => {
            // Try to find JSON object in the response
            if let Some(start) = trimmed.find('{') {
                if let Some(end) = trimmed.rfind('}') {
                    let json_str = &trimmed[start..=end];
                    match serde_json::from_str::<Value>(json_str) {
                        Ok(json) => Ok(json),
                        Err(e) => Err(format!("Failed to parse JSON: {}", e).into()),
                    }
                } else {
                    Err("No closing brace found in response".into())
                }
            } else {
                Err("No JSON object found in response".into())
            }
        }
    }
}

fn clean_org_name(org_name: &str) -> String {
    org_name.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == ',' || *c == '.' || *c == '-')
        .collect()
}

async fn process_proxy_with_session(
    idx: usize,
    proxy_line: String,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<ProxyEntry>>>,
) {
    // Parse proxy line
    let parts: Vec<&str> = proxy_line.split(',').collect();
    if parts.len() < 4 {
        return;
    }

    let ip = parts[0];
    let port_str = parts[1];
    let country_from_file = parts[2];
    let org_from_file = parts[3];

    let port_num = match port_str.parse::<u16>() {
        Ok(p) => p,
        Err(_) => return,
    };

    let mut cookie_jar = CookieJar::new();
    
    // First request: get homepage to establish session
    let home_result = make_request(IP_RESOLVER, PATH_HOME, Some((ip, port_num)), &mut cookie_jar, false).await;
    if home_result.is_err() {
        return;
    }
    
    // Second request: get meta data
    match make_request(IP_RESOLVER, PATH_META, Some((ip, port_num)), &mut cookie_jar, true).await {
        Ok((_, body)) => {
            match parse_json_response(&body) {
                Ok(proxy_data) => {
                    if let Some(Value::String(proxy_ip)) = proxy_data.get("clientIp") {
                        if proxy_ip != original_ip {
                            // Get country from Cloudflare response
                            let country = if let Some(Value::String(country_code)) = proxy_data.get("country") {
                                country_code.clone()
                            } else {
                                country_from_file.to_string()
                            };

                            // Get organization from Cloudflare response  
                            let org = if let Some(Value::String(org_val)) = proxy_data.get("asOrganization") {
                                clean_org_name(org_val)
                            } else {
                                clean_org_name(org_from_file)
                            };

                            let proxy_entry = ProxyEntry {
                                ip: ip.to_string(),
                                port: port_num,
                                country,
                                org,
                            };
                            
                            let mut active_proxies_locked = active_proxies.lock().unwrap();
                            active_proxies_locked.push(proxy_entry);
                        }
                    }
                },
                Err(_) => {
                    // Silently skip invalid responses
                }
            }
        },
        Err(_) => {
            // Silently skip failed connections
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

    println!("\n=== DISTRIBUTION SUMMARY ===");
    println!("Priority Countries:");
    for priority_country in &PRIORITY_COUNTRIES {
        if let Some(count) = counts.get(*priority_country) {
            println!("  {}: {} proxies", priority_country, count);
        }
    }
    
    println!("\nOther Countries:");
    let mut other_countries: Vec<_> = counts.iter()
        .filter(|(country, _)| !PRIORITY_COUNTRIES.contains(&country.as_str()))
        .collect();
    
    other_countries.sort_by_key(|(country, _)| *country);
    
    for (country, count) in other_countries {
        println!("  {}: {} proxies", country, count);
    }
}
