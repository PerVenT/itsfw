use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

pub fn parse_ipconfig_displaydns(text: &str) -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();
    let mut current_name: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("---") {
            current_name = None;
            continue;
        }

        if let Some((key_part, val_part)) = trimmed.split_once(':') {
            let key = key_part.trim().to_lowercase();
            let val = val_part.trim();

            if key.contains("record name") || key.contains("имя записи") {
                let domain = val.trim_end_matches('.').trim().to_string();
                if !domain.is_empty() {
                    current_name = Some(domain);
                }
            } else if let Ok(ip) = val.parse::<IpAddr>() {
                if let Some(ref name) = current_name {
                    map.insert(ip, name.clone());
                }
            }
        }
    }

    map
}

pub fn format_recent_activity_endpoint(
    ip: &IpAddr,
    port: u16,
    protocol: &str,
    domain: Option<&str>,
) -> String {
    let proto = protocol.to_lowercase();
    match domain.map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => format!("{}:{}/{} {}", ip, port, proto, d),
        None => format!("{}:{}/{}", ip, port, proto),
    }
}

#[derive(Clone)]
pub struct DnsResolver {
    cache: Arc<RwLock<HashMap<IpAddr, Option<String>>>>,
    req_tx: crossbeam_channel::Sender<IpAddr>,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    pub fn new_empty() -> Self {
        let (req_tx, req_rx) = crossbeam_channel::bounded(256);
        std::mem::forget(req_rx);
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            req_tx,
        }
    }

    pub fn resolve_or_enqueue(&self, ip: IpAddr) -> Option<String> {
        if let Ok(cache) = self.cache.read() {
            if let Some(entry) = cache.get(&ip) {
                return entry.clone();
            }
        }

        if ip.is_loopback() || ip.is_unspecified() {
            return None;
        }

        if let Ok(mut cache) = self.cache.write() {
            if let Some(entry) = cache.get(&ip) {
                return entry.clone();
            }
            if self.req_tx.try_send(ip).is_ok() {
                cache.insert(ip, None);
            }
        }

        None
    }

    pub fn insert_for_test(&self, ip: IpAddr, domain: String) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(ip, Some(domain));
        }
    }

    #[cfg(not(windows))]
    pub fn new() -> Self {
        Self::new_empty()
    }

    #[cfg(windows)]
    pub fn new() -> Self {
        let (req_tx, req_rx) = crossbeam_channel::bounded::<IpAddr>(256);
        let cache = Arc::new(RwLock::new(HashMap::new()));

        let cache_prepop = Arc::clone(&cache);
        let _ = std::thread::Builder::new()
            .name("dns-prepopulate".into())
            .spawn(move || {
                prepopulate_os_dns_cache(&cache_prepop);
            });

        let cache_worker = Arc::clone(&cache);
        let _ = std::thread::Builder::new()
            .name("dns-rdns-worker".into())
            .spawn(move || {
                rdns_worker_loop(req_rx, cache_worker);
            });

        Self { cache, req_tx }
    }
}

#[cfg(windows)]
fn prepopulate_os_dns_cache(cache: &Arc<RwLock<HashMap<IpAddr, Option<String>>>>) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    if let Ok(output) = Command::new("ipconfig")
        .arg("/displaydns")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        let entries = parse_ipconfig_displaydns(&text);
        if let Ok(mut c) = cache.write() {
            for (ip, domain) in entries {
                c.entry(ip).or_insert(Some(domain));
            }
        }
    }
}

#[cfg(windows)]
fn rdns_worker_loop(
    req_rx: crossbeam_channel::Receiver<IpAddr>,
    cache: Arc<RwLock<HashMap<IpAddr, Option<String>>>>,
) {
    while let Ok(ip) = req_rx.recv() {
        let resolved = reverse_dns_lookup(ip);
        if let Ok(mut c) = cache.write() {
            c.insert(ip, resolved);
        }
    }
}

#[cfg(windows)]
fn reverse_dns_lookup(ip: IpAddr) -> Option<String> {
    use windows::Win32::Networking::WinSock::{
        socklen_t, GetNameInfoW, AF_INET, AF_INET6, IN6_ADDR, IN_ADDR, NI_NAMEREQD, SOCKADDR,
        SOCKADDR_IN, SOCKADDR_IN6,
    };

    let mut host_buf = [0u16; 1024];

    let ret = match ip {
        IpAddr::V4(v4) => {
            let mut sin: SOCKADDR_IN = unsafe { std::mem::zeroed() };
            sin.sin_family = AF_INET;
            sin.sin_addr = IN_ADDR {
                S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(v4.octets()),
                },
            };
            let ptr = &sin as *const SOCKADDR_IN as *const SOCKADDR;
            let len = std::mem::size_of::<SOCKADDR_IN>() as i32;
            unsafe {
                GetNameInfoW(
                    ptr,
                    socklen_t(len),
                    Some(&mut host_buf),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
        IpAddr::V6(v6) => {
            let mut sin6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            sin6.sin6_family = AF_INET6;
            sin6.sin6_addr = IN6_ADDR {
                u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: v6.octets() },
            };
            let ptr = &sin6 as *const SOCKADDR_IN6 as *const SOCKADDR;
            let len = std::mem::size_of::<SOCKADDR_IN6>() as i32;
            unsafe {
                GetNameInfoW(
                    ptr,
                    socklen_t(len),
                    Some(&mut host_buf),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
    };

    if ret == 0 {
        let len = host_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(host_buf.len());
        if len > 0 {
            let s = String::from_utf16_lossy(&host_buf[..len]);
            let trimmed = s.trim().trim_end_matches('.');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_ipconfig_displaydns_extracts_a_and_aaaa_records() {
        let sample = r#"
Windows IP Configuration

    api.github.com
    ----------------------------------------
    Record Name . . . . . : api.github.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 42
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 140.82.121.6

    telemetry.microsoft.com
    ----------------------------------------
    Record Name . . . . . : v10.events.data.microsoft.com
    A (Host) Record . . . : 20.190.159.4

    ipv6.google.com
    ----------------------------------------
    Record Name . . . . . : ipv6.google.com
    Record Type . . . . . : 28
    AAAA Record . . . . . : 2a00:1450:4001:828::200e
"#;
        let map = parse_ipconfig_displaydns(sample);
        assert_eq!(
            map.get(&IpAddr::from_str("140.82.121.6").unwrap())
                .map(|s| s.as_str()),
            Some("api.github.com")
        );
        assert_eq!(
            map.get(&IpAddr::from_str("20.190.159.4").unwrap())
                .map(|s| s.as_str()),
            Some("v10.events.data.microsoft.com")
        );
        assert_eq!(
            map.get(&IpAddr::from_str("2a00:1450:4001:828::200e").unwrap())
                .map(|s| s.as_str()),
            Some("ipv6.google.com")
        );
    }

    #[test]
    fn test_format_recent_activity_endpoint_and_resolver_cache() {
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        assert_eq!(
            format_recent_activity_endpoint(&ip, 22, "TCP", None),
            "127.0.0.1:22/tcp"
        );
        assert_eq!(
            format_recent_activity_endpoint(&ip, 22, "TCP", Some("local.dev")),
            "127.0.0.1:22/tcp local.dev"
        );
        assert_eq!(
            format_recent_activity_endpoint(&ip, 22, "TCP", Some("")),
            "127.0.0.1:22/tcp"
        );
        assert_eq!(
            format_recent_activity_endpoint(&ip, 443, "udp", Some("   ")),
            "127.0.0.1:443/udp"
        );

        let resolver = DnsResolver::new_empty();
        assert_eq!(resolver.resolve_or_enqueue(ip), None);
        resolver.insert_for_test(ip, "local.dev".into());
        assert_eq!(resolver.resolve_or_enqueue(ip), Some("local.dev".into()));
    }

    #[test]
    fn test_resolver_loopback_and_unspecified_not_enqueued() {
        let resolver = DnsResolver::new_empty();
        let unspec_v4 = IpAddr::from_str("0.0.0.0").unwrap();
        let unspec_v6 = IpAddr::from_str("::").unwrap();
        let loopback_v6 = IpAddr::from_str("::1").unwrap();

        assert_eq!(resolver.resolve_or_enqueue(unspec_v4), None);
        assert_eq!(resolver.resolve_or_enqueue(unspec_v6), None);
        assert_eq!(resolver.resolve_or_enqueue(loopback_v6), None);

        // None of these should be inserted in the cache as in-flight
        let cache = resolver.cache.read().unwrap();
        assert!(!cache.contains_key(&unspec_v4));
        assert!(!cache.contains_key(&unspec_v6));
        assert!(!cache.contains_key(&loopback_v6));
    }

    #[test]
    fn test_resolver_public_ip_in_flight_marking() {
        let resolver = DnsResolver::new_empty();
        let public_ip = IpAddr::from_str("8.8.8.8").unwrap();

        assert_eq!(resolver.resolve_or_enqueue(public_ip), None);
        // Should now be marked in-flight (Some(None))
        {
            let cache = resolver.cache.read().unwrap();
            assert_eq!(cache.get(&public_ip), Some(&None));
        }

        // Resolving again while in-flight still returns None
        assert_eq!(resolver.resolve_or_enqueue(public_ip), None);

        // Simulating worker thread updating cache
        resolver.insert_for_test(public_ip, "dns.google".into());
        assert_eq!(
            resolver.resolve_or_enqueue(public_ip),
            Some("dns.google".into())
        );
    }

    #[test]
    fn test_resolver_queue_full_does_not_poison_cache() {
        let resolver = DnsResolver::new_empty();
        // Fill up the 256-capacity channel
        for i in 0..256 {
            let dummy_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                0,
                (i / 256) as u8,
                (i % 256) as u8,
            ));
            assert_eq!(resolver.resolve_or_enqueue(dummy_ip), None);
            assert!(resolver.cache.read().unwrap().contains_key(&dummy_ip));
        }

        // Channel is now full. Next IP should fail to send and NOT be inserted into cache
        let overflow_ip = IpAddr::from_str("198.51.100.1").unwrap();
        assert_eq!(resolver.resolve_or_enqueue(overflow_ip), None);
        assert!(!resolver.cache.read().unwrap().contains_key(&overflow_ip));
    }

    #[test]
    fn test_parse_ipconfig_displaydns_edge_cases() {
        assert!(parse_ipconfig_displaydns("").is_empty());
        assert!(parse_ipconfig_displaydns("garbage data with no colons").is_empty());
        assert!(parse_ipconfig_displaydns("Record Type: 1\nSection: Answer").is_empty());

        let multi = r#"
    Record Name . . . . . : multi.example.com.
    A (Host) Record . . . : 1.1.1.1
    A (Host) Record . . . : 1.0.0.1
"#;
        let map = parse_ipconfig_displaydns(multi);
        assert_eq!(
            map.get(&IpAddr::from_str("1.1.1.1").unwrap())
                .map(|s| s.as_str()),
            Some("multi.example.com")
        );
        assert_eq!(
            map.get(&IpAddr::from_str("1.0.0.1").unwrap())
                .map(|s| s.as_str()),
            Some("multi.example.com")
        );
    }
}
