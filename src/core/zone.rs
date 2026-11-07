use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Zone {
    Lan,
    Internet,
}

impl Zone {
    /// Класифікує IP-адресу на LAN (локальна/приватна/службова) або Internet (публічна маршрутизована).
    pub fn classify(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => Self::classify_v4(ipv4),
            IpAddr::V6(ipv6) => Self::classify_v6(ipv6),
        }
    }

    pub fn classify_v4(ip: &Ipv4Addr) -> Self {
        let octets = ip.octets();

        // 127.0.0.0/8 (Loopback)
        if ip.is_loopback() {
            return Self::Lan;
        }

        // 10.0.0.0/8 (RFC1918 Private)
        if octets[0] == 10 {
            return Self::Lan;
        }

        // 172.16.0.0/12 (RFC1918 Private: 172.16.x.x - 172.31.x.x)
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return Self::Lan;
        }

        // 192.168.0.0/16 (RFC1918 Private)
        if octets[0] == 192 && octets[1] == 168 {
            return Self::Lan;
        }

        // 169.254.0.0/16 (Link-Local / APIPA)
        if ip.is_link_local() {
            return Self::Lan;
        }

        // 224.0.0.0/4 (Multicast: 224.0.0.0 - 239.255.255.255)
        if ip.is_multicast() {
            return Self::Lan;
        }

        // 255.255.255.255 (Broadcast)
        if ip.is_broadcast() {
            return Self::Lan;
        }

        // 0.0.0.0 (Unspecified)
        if ip.is_unspecified() {
            return Self::Lan;
        }

        // 100.64.0.0/10 (Shared Address Space / CGNAT)
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            return Self::Lan;
        }

        Self::Internet
    }

    pub fn classify_v6(ip: &Ipv6Addr) -> Self {
        // ::1 (Loopback)
        if ip.is_loopback() {
            return Self::Lan;
        }

        // :: (Unspecified)
        if ip.is_unspecified() {
            return Self::Lan;
        }

        // fe80::/10 (Link-Local)
        let segments = ip.segments();
        if (segments[0] & 0xffc0) == 0xfe80 {
            return Self::Lan;
        }

        // fc00::/7 (Unique Local Address - ULA: fc00::/8 або fd00::/8)
        if (segments[0] & 0xfe00) == 0xfc00 {
            return Self::Lan;
        }

        // ff00::/8 (Multicast)
        if ip.is_multicast() {
            return Self::Lan;
        }

        Self::Internet
    }

    /// Повертає список підмереж у форматі Windows Firewall RemoteAddresses для зони LAN.
    /// УВАГА: netsh відхиляє loopback (127.0.0.0/8, ::1), multicast (224.0.0.0/4, ff00::/8) та broadcast (255.255.255.255/32).
    pub fn windows_firewall_lan_subnets() -> &'static str {
        "LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,fc00::/7,fe80::/10"
    }

    /// Повертає діапазони публічних IP-адрес Інтернету (поза RFC1918 / CGNAT / Link-Local) для блокування при режимі LAN Only.
    pub fn windows_firewall_internet_ranges() -> &'static str {
        "0.0.0.0-9.255.255.255,11.0.0.0-100.63.255.255,100.128.0.0-126.255.255.255,128.0.0.0-169.253.255.255,169.255.0.0-172.15.255.255,172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255,2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    }

    /// Повертає маску для будь-якої адреси (LAN + Internet) у синтаксисі netsh.
    pub fn windows_firewall_all_subnets() -> &'static str {
        "any"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv4_classification_boundary_values() {
        // Boundary Value Analysis (BVA) для меж IPv4 підмереж:
        // [нижня межа - 1, нижня межа, верхня межа, верхня межа + 1]
        let test_cases = [
            // 0.0.0.0 / Unspecified
            ("0.0.0.0", Zone::Lan),
            // Межі 10.0.0.0/8
            ("9.255.255.255", Zone::Internet),
            ("10.0.0.0", Zone::Lan),
            ("10.255.255.255", Zone::Lan),
            ("11.0.0.0", Zone::Internet),
            // Межі 100.64.0.0/10 (CGNAT)
            ("100.63.255.255", Zone::Internet),
            ("100.64.0.0", Zone::Lan),
            ("100.127.255.255", Zone::Lan),
            ("100.128.0.0", Zone::Internet),
            // Межі 127.0.0.0/8 (Loopback)
            ("127.0.0.1", Zone::Lan),
            ("127.255.255.255", Zone::Lan),
            // Межі 169.254.0.0/16 (Link-Local)
            ("169.253.255.255", Zone::Internet),
            ("169.254.0.0", Zone::Lan),
            ("169.254.255.255", Zone::Lan),
            ("169.255.0.0", Zone::Internet),
            // Межі 172.16.0.0/12
            ("172.15.255.255", Zone::Internet),
            ("172.16.0.0", Zone::Lan),
            ("172.31.255.255", Zone::Lan),
            ("172.32.0.0", Zone::Internet),
            // Межі 192.168.0.0/16
            ("192.167.255.255", Zone::Internet),
            ("192.168.0.0", Zone::Lan),
            ("192.168.255.255", Zone::Lan),
            ("192.169.0.0", Zone::Internet),
            // Межі 224.0.0.0/4 (Multicast: 224.0.0.0 - 239.255.255.255)
            ("223.255.255.255", Zone::Internet),
            ("224.0.0.0", Zone::Lan),
            ("239.255.255.255", Zone::Lan),
            // 255.255.255.255 (Broadcast)
            ("255.255.255.255", Zone::Lan),
        ];

        for (ip_str, expected_zone) in test_cases {
            let ip = IpAddr::from_str(ip_str)
                .unwrap_or_else(|_| panic!("Failed to parse IPv4: {}", ip_str));
            assert_eq!(
                Zone::classify(&ip),
                expected_zone,
                "BVA check failed for IPv4: {}",
                ip_str
            );
        }
    }

    #[test]
    fn test_ipv6_classification_boundary_values() {
        let test_cases = [
            // Unspecified & Loopback
            ("::", Zone::Lan),
            ("::1", Zone::Lan),
            // Link-Local (fe80::/10 -> діапазон fe80 - febf)
            ("fe80::1", Zone::Lan),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Zone::Lan),
            ("fec0::1", Zone::Internet),
            // Unique Local Address ULA (fc00::/7 -> fc00 - fdff)
            ("fc00::1", Zone::Lan),
            ("fd12:3456:789a:1::1", Zone::Lan),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Zone::Lan),
            // Multicast (ff00::/8)
            ("ff02::1", Zone::Lan),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Zone::Lan),
            // Global Unicast / Internet
            ("2606:4700:4700::1111", Zone::Internet),
            ("2001:4860:4860::8888", Zone::Internet),
        ];

        for (ip_str, expected_zone) in test_cases {
            let ip = IpAddr::from_str(ip_str)
                .unwrap_or_else(|_| panic!("Failed to parse IPv6: {}", ip_str));
            assert_eq!(
                Zone::classify(&ip),
                expected_zone,
                "BVA check failed for IPv6: {}",
                ip_str
            );
        }
    }

    #[test]
    fn test_windows_firewall_subnet_strings_contract() {
        let lan_subnets = Zone::windows_firewall_lan_subnets();
        assert!(!lan_subnets.is_empty());
        assert!(lan_subnets.contains("LocalSubnet"));
        assert!(lan_subnets.contains("10.0.0.0/8"));
        assert!(lan_subnets.contains("192.168.0.0/16"));
        // netsh не приймає пробілів біля ком
        assert!(!lan_subnets.contains(", "));
        assert!(!lan_subnets.contains(" ,"));

        let internet_ranges = Zone::windows_firewall_internet_ranges();
        assert!(!internet_ranges.is_empty());
        assert!(internet_ranges.contains('-'));
        assert!(!internet_ranges.contains(", "));

        let all = Zone::windows_firewall_all_subnets();
        assert_eq!(all, "any");
    }
}
