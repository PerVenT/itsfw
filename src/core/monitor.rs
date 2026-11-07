//! Read-only монітор мережевих спроб у реальному часі через Windows Filtering Platform (FwpmNetEvent).

use crate::core::zone::Zone;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEvent {
    pub timestamp: u64,
    pub app_path: String,
    pub service_name: Option<String>,
    pub direction: crate::core::rules::RuleDirection,
    pub process_id: u32,
    pub parent_process_name: Option<String>,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: String,
    pub is_blocked: bool,
    pub zone: Zone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppActivitySummary {
    pub app_path: String,
    pub app_name: String,
    pub service_name: Option<String>,
    pub direction: crate::core::rules::RuleDirection,
    pub process_id: u32,
    pub parent_process_name: Option<String>,
    pub total_hits: u64,
    pub last_hit_time: u64,
    pub is_knocking: bool,
    pub last_target_zone: Zone,
    pub last_target_port: u16,
    pub last_protocol: String,
    pub seen_zones: BTreeSet<Zone>,
    pub seen_ports: BTreeSet<u16>,
    pub seen_protocols: BTreeSet<String>,
    pub recent_events: Vec<NetworkEvent>,
}

impl AppActivitySummary {
    /// Відображає всі фактичні зони, куди звертався додаток (`LAN`, `INET`, `LAN+INET` або `-` якщо активності ще не було).
    pub fn zones_display(&self) -> &'static str {
        let has_lan = self.seen_zones.contains(&Zone::Lan);
        let has_inet = self.seen_zones.contains(&Zone::Internet);
        match (has_lan, has_inet) {
            (true, true) => "LAN+INET",
            (false, true) => "INET",
            (true, false) => "LAN",
            (false, false) => "-",
        }
    }

    /// Відображає компактний підсумок портів для таблиці (наприклад `:443` або `:53 +2`, щоб не мерехтіло при кількох портах).
    pub fn ports_display(&self) -> String {
        match self.seen_ports.len() {
            0 => {
                if self.last_target_port > 0 {
                    format!(":{}", self.last_target_port)
                } else {
                    "-".into()
                }
            }
            1 => {
                let p = *self.seen_ports.iter().next().unwrap();
                format!(":{}", p)
            }
            n => {
                let first = *self.seen_ports.iter().next().unwrap();
                format!(":{} (+{})", first, n - 1)
            }
        }
    }

    /// Повний список усіх портів, куди стукав додаток, для панелі Інспектора.
    pub fn all_ports_list(&self) -> String {
        if self.seen_ports.is_empty() {
            if self.last_target_port > 0 {
                format!(":{}", self.last_target_port)
            } else {
                "None (no active sockets observed)".into()
            }
        } else {
            self.seen_ports
                .iter()
                .map(|p| format!(":{}", p))
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    /// Усі протоколи (`TCP`, `UDP`, `TCP/UDP`), які використовував додаток.
    pub fn protocols_display(&self) -> String {
        if self.seen_protocols.is_empty() {
            self.last_protocol.clone()
        } else {
            self.seen_protocols
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("/")
        }
    }
}

#[derive(Default)]
pub struct EventAggregator {
    pub apps: HashMap<String, AppActivitySummary>,
    pub blocked_paths_or_names: std::collections::HashSet<String>,
}

impl EventAggregator {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            blocked_paths_or_names: std::collections::HashSet::new(),
        }
    }

    pub fn sync_firewall_rules(&mut self, rules: &HashMap<String, crate::core::rules::AppRule>) {
        self.blocked_paths_or_names.clear();

        for (key, rule) in rules {
            let base_filename = rule
                .app_path
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(&rule.app_path)
                .to_string();

            let filename = match rule.service_name.as_deref() {
                Some(svc) if !svc.trim().is_empty() => {
                    format!("{} [{}]", base_filename, svc.trim())
                }
                _ => base_filename,
            };

            let is_blocked = rule.action == crate::core::rules::RuleAction::Block;
            if is_blocked {
                self.blocked_paths_or_names.insert(key.to_lowercase());
                self.blocked_paths_or_names.insert(filename.to_lowercase());
            }

            let entry = self
                .apps
                .entry(key.to_lowercase())
                .or_insert_with(|| AppActivitySummary {
                    app_path: rule.app_path.clone(),
                    app_name: filename,
                    service_name: rule.service_name.clone(),
                    direction: rule.direction,
                    process_id: 0,
                    parent_process_name: None,
                    total_hits: 0,
                    last_hit_time: 0,
                    is_knocking: is_blocked,
                    last_target_zone: match rule.zone_scope {
                        crate::core::rules::AllowedZoneScope::LanOnly => Zone::Lan,
                        _ => Zone::Internet,
                    },
                    last_target_port: rule.ports.parse::<u16>().unwrap_or(0),
                    last_protocol: match rule.protocol {
                        crate::core::rules::NetProtocol::Tcp => "TCP".into(),
                        crate::core::rules::NetProtocol::Udp => "UDP".into(),
                        crate::core::rules::NetProtocol::Any => "ANY".into(),
                    },
                    seen_zones: BTreeSet::new(),
                    seen_ports: BTreeSet::new(),
                    seen_protocols: BTreeSet::new(),
                    recent_events: Vec::new(),
                });
            entry.is_knocking = is_blocked;
            entry.direction = rule.direction;
            if entry.service_name.is_none() && rule.service_name.is_some() {
                entry.service_name = rule.service_name.clone();
            }
        }
    }

    pub fn set_blocked_apps(&mut self, blocked: std::collections::HashSet<String>) {
        self.blocked_paths_or_names = blocked.iter().map(|s| s.to_lowercase()).collect();

        // 1. Оновлюємо вже наявні додатки
        for (path, app) in self.apps.iter_mut() {
            let path_lower = path.to_lowercase();
            let name_lower = app.app_name.to_lowercase();
            if self.blocked_paths_or_names.contains(&path_lower)
                || self.blocked_paths_or_names.contains(&name_lower)
            {
                app.is_knocking = true;
            }
        }

        // 2. Вносимо до списку всі заблоковані програми з Windows Firewall, навіть якщо вони зараз не активні
        for blocked_item in blocked {
            if blocked_item.contains('\\') || blocked_item.contains('/') {
                let filename = blocked_item
                    .rsplit(['\\', '/'])
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&blocked_item)
                    .to_string();

                let key = blocked_item.to_lowercase();
                self.apps.entry(key).or_insert_with(|| {
                    AppActivitySummary {
                        app_path: blocked_item,
                        app_name: filename,
                        service_name: None,
                        direction: crate::core::rules::RuleDirection::Outbound,
                        process_id: 0,
                        parent_process_name: None,
                        total_hits: 0,
                        last_hit_time: 0,
                        is_knocking: true, // Гарантовано позначаємо як заблокований!
                        last_target_zone: Zone::Internet,
                        last_target_port: 0,
                        last_protocol: "ANY".into(),
                        seen_zones: BTreeSet::new(),
                        seen_ports: BTreeSet::new(),
                        seen_protocols: BTreeSet::new(),
                        recent_events: Vec::new(),
                    }
                });
            }
        }
    }

    pub fn is_app_blocked(&self, path: &str, name: &str) -> bool {
        let p_low = path.to_lowercase();
        let n_low = name.to_lowercase();
        self.blocked_paths_or_names.contains(&p_low) || self.blocked_paths_or_names.contains(&n_low)
    }

    pub fn record_event(&mut self, event: NetworkEvent) {
        let base_name = event
            .app_path
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown.exe")
            .to_string();

        let app_name = match event.service_name {
            Some(ref s) if !s.trim().is_empty() => format!("{} [{}]", base_name, s.trim()),
            _ => base_name.clone(),
        };

        let key = crate::core::rules::make_app_key(
            &event.app_path,
            event.service_name.as_deref(),
            event.direction,
        );
        let is_fw_blocked = self.is_app_blocked(&event.app_path, &base_name)
            || self.blocked_paths_or_names.contains(&key.to_lowercase());

        let entry = self.apps.entry(key).or_insert_with(|| AppActivitySummary {
            app_path: event.app_path.clone(),
            app_name: app_name.clone(),
            service_name: event.service_name.clone(),
            direction: event.direction,
            process_id: event.process_id,
            parent_process_name: event.parent_process_name.clone(),
            total_hits: 0,
            last_hit_time: event.timestamp,
            is_knocking: event.is_blocked || is_fw_blocked,
            last_target_zone: event.zone,
            last_target_port: event.remote_port,
            last_protocol: event.protocol.clone(),
            seen_zones: BTreeSet::new(),
            seen_ports: BTreeSet::new(),
            seen_protocols: BTreeSet::new(),
            recent_events: Vec::new(),
        });

        entry.total_hits += 1;
        entry.last_hit_time = event.timestamp;
        if event.process_id > 0 {
            entry.process_id = event.process_id;
        }
        if event.parent_process_name.is_some() {
            entry.parent_process_name = event.parent_process_name.clone();
        }
        if event.is_blocked || is_fw_blocked {
            entry.is_knocking = true;
        }
        entry.last_target_zone = event.zone;
        entry.last_target_port = event.remote_port;
        entry.last_protocol = event.protocol.clone();
        entry.seen_zones.insert(event.zone);
        if event.remote_port > 0 {
            entry.seen_ports.insert(event.remote_port);
        }
        if !event.protocol.is_empty() && event.protocol != "ANY" {
            entry.seen_protocols.insert(event.protocol.to_uppercase());
        }

        entry.recent_events.push(event);
        if entry.recent_events.len() > 20 {
            entry.recent_events.remove(0);
        }
    }

    pub fn get_sorted_list(&self) -> Vec<&AppActivitySummary> {
        let mut list: Vec<&AppActivitySummary> = self.apps.values().collect();
        // Детерміноване стабільне сортування за назвою додатку (і шляхом), щоб інтерфейс ніколи не стрибав!
        list.sort_by(|a, b| {
            a.app_name
                .to_lowercase()
                .cmp(&b.app_name.to_lowercase())
                .then_with(|| a.app_path.to_lowercase().cmp(&b.app_path.to_lowercase()))
                .then_with(|| (a.direction as u8).cmp(&(b.direction as u8)))
                .then_with(|| a.service_name.cmp(&b.service_name))
        });
        list
    }
}

pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_event_aggregator_deduplication_and_sorting() {
        let mut aggregator = EventAggregator::new();

        let event1 = NetworkEvent {
            timestamp: 100,
            app_path: r"C:\Windows\System32\svchost.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 1234,
            parent_process_name: Some("services.exe".into()),
            remote_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            remote_port: 53,
            protocol: "UDP".into(),
            is_blocked: false,
            zone: Zone::Lan,
        };

        let event2 = NetworkEvent {
            timestamp: 150,
            app_path: r"C:\Program Files\Telegram\telegram.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 5678,
            parent_process_name: Some("explorer.exe".into()),
            remote_ip: IpAddr::from_str("149.154.167.50").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: true, // ломиться назовні!
            zone: Zone::Internet,
        };

        aggregator.record_event(event1);
        aggregator.record_event(event2);

        let list = aggregator.get_sorted_list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].app_name, "svchost.exe");
        assert_eq!(list[1].app_name, "telegram.exe");
        assert!(list[1].is_knocking);
        assert_eq!(list[1].last_target_zone, Zone::Internet);
        assert_eq!(list[1].last_target_port, 443);
    }

    #[test]
    fn test_stable_sorting_does_not_jump_on_new_events_or_status_change() {
        let mut aggregator = EventAggregator::new();

        aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: r"C:\Apps\zeta.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 10,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });

        aggregator.record_event(NetworkEvent {
            timestamp: 200,
            app_path: r"C:\Apps\alpha.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 20,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            remote_port: 80,
            protocol: "TCP".into(),
            is_blocked: true,
            zone: Zone::Lan,
        });

        let list1: Vec<String> = aggregator
            .get_sorted_list()
            .iter()
            .map(|a| a.app_name.clone())
            .collect();
        assert_eq!(list1, vec!["alpha.exe", "zeta.exe"]);

        // zeta.exe gets a newer timestamp and becomes blocked; order MUST NOT jump!
        aggregator.record_event(NetworkEvent {
            timestamp: 999,
            app_path: r"C:\Apps\zeta.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 10,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: true,
            zone: Zone::Internet,
        });

        let list2: Vec<String> = aggregator
            .get_sorted_list()
            .iter()
            .map(|a| a.app_name.clone())
            .collect();
        assert_eq!(list2, vec!["alpha.exe", "zeta.exe"]);
    }

    #[test]
    fn test_multi_zone_multi_port_multi_protocol_aggregation() {
        let mut aggregator = EventAggregator::new();
        let path = r"C:\Programs\client.exe";

        aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 100,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_port: 10090,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Lan,
        });

        let summary = aggregator.apps.get(&path.to_lowercase()).unwrap();
        assert_eq!(summary.zones_display(), "LAN");
        assert_eq!(summary.ports_display(), ":10090");
        assert_eq!(summary.protocols_display(), "TCP");

        // Тестуємо агрегацію кількох зон, портів і протоколів для одного додатку
        aggregator.record_event(NetworkEvent {
            timestamp: 105,
            app_path: path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 100,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("142.250.180.174").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });
        aggregator.record_event(NetworkEvent {
            timestamp: 106,
            app_path: path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 100,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            remote_port: 53,
            protocol: "UDP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });

        let summary = aggregator.apps.get(&path.to_lowercase()).unwrap();
        assert_eq!(summary.zones_display(), "LAN+INET");
        assert_eq!(summary.ports_display(), ":53 (+2)");
        assert_eq!(summary.all_ports_list(), ":53, :443, :10090");
        assert_eq!(summary.protocols_display(), "TCP/UDP");
    }

    #[test]
    fn test_recent_events_ring_buffer_caps_at_twenty() {
        let mut aggregator = EventAggregator::new();
        let path = r"C:\Services\daemon.exe";

        for i in 0..25 {
            aggregator.record_event(NetworkEvent {
                timestamp: 1000 + i,
                app_path: path.into(),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                process_id: 500,
                parent_process_name: None,
                remote_ip: IpAddr::from_str("10.0.0.1").unwrap(),
                remote_port: 8080,
                protocol: "TCP".into(),
                is_blocked: false,
                zone: Zone::Lan,
            });
        }

        let summary = aggregator.apps.get(&path.to_lowercase()).unwrap();
        assert_eq!(summary.total_hits, 25, "total_hits must record every event");
        assert_eq!(
            summary.recent_events.len(),
            20,
            "recent_events buffer must cap at 20"
        );
        assert_eq!(
            summary.recent_events[0].timestamp, 1005,
            "oldest 5 events should be evicted"
        );
        assert_eq!(
            summary.recent_events[19].timestamp, 1024,
            "latest event must be at the end"
        );
    }

    #[test]
    fn test_sync_firewall_rules_and_is_app_blocked_lookup() {
        let mut aggregator = EventAggregator::new();
        let mut rules = HashMap::new();

        rules.insert(
            "app1".to_string(),
            crate::core::rules::AppRule {
                app_path: r"C:\Security\malicious.exe".to_string(),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                action: crate::core::rules::RuleAction::Block,
                zone_scope: crate::core::rules::AllowedZoneScope::Both,
                custom_remote_ip: None,
                protocol: crate::core::rules::NetProtocol::Any,
                ports: "*".to_string(),
                interface_name: None,
                created_at: 1,
            },
        );

        rules.insert(
            "app2".to_string(),
            crate::core::rules::AppRule {
                app_path: r"C:\Browser\browser.exe".to_string(),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                action: crate::core::rules::RuleAction::Allow,
                zone_scope: crate::core::rules::AllowedZoneScope::Both,
                custom_remote_ip: None,
                protocol: crate::core::rules::NetProtocol::Any,
                ports: "*".to_string(),
                interface_name: None,
                created_at: 2,
            },
        );

        aggregator.sync_firewall_rules(&rules);

        // Пошук за повним шляхом та за іменем файлу, незалежно від регістру
        assert!(aggregator.is_app_blocked(r"C:\Security\malicious.exe", "malicious.exe"));
        assert!(aggregator.is_app_blocked(r"c:\security\MALICIOUS.EXE", "MALICIOUS.exe"));
        assert!(aggregator.is_app_blocked(r"C:\DifferentPath\malicious.exe", "malicious.exe"));

        // Дозволений додаток не вважається заблокованим
        assert!(!aggregator.is_app_blocked(r"C:\Browser\browser.exe", "browser.exe"));

        // Невідомий додаток не заблокований
        assert!(!aggregator.is_app_blocked(r"C:\Tools\unknown.exe", "unknown.exe"));
    }

    #[test]
    fn test_app_activity_summary_formatting_edge_cases() {
        let mut empty_summary = AppActivitySummary {
            app_path: r"C:\Apps\dummy.exe".into(),
            app_name: "dummy.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 1,
            parent_process_name: None,
            total_hits: 0,
            last_hit_time: 0,
            is_knocking: false,
            last_target_zone: Zone::Lan,
            last_target_port: 0,
            last_protocol: "TCP".into(),
            seen_zones: BTreeSet::new(),
            seen_ports: BTreeSet::new(),
            seen_protocols: BTreeSet::new(),
            recent_events: Vec::new(),
        };

        // Без подій
        assert_eq!(empty_summary.zones_display(), "-");
        assert_eq!(empty_summary.ports_display(), "-");
        assert_eq!(
            empty_summary.all_ports_list(),
            "None (no active sockets observed)"
        );

        // 1 порт
        empty_summary.seen_ports.insert(80);
        assert_eq!(empty_summary.ports_display(), ":80");
        assert_eq!(empty_summary.all_ports_list(), ":80");

        // 3 порти
        empty_summary.seen_ports.insert(443);
        empty_summary.seen_ports.insert(8080);
        assert_eq!(empty_summary.ports_display(), ":80 (+2)");
        assert_eq!(empty_summary.all_ports_list(), ":80, :443, :8080");
    }

    #[test]
    fn test_set_blocked_apps_populates_entries_and_marks_knocking() {
        let mut aggregator = EventAggregator::new();
        let app_path = r"C:\Windows\System32\cmd.exe";

        // Add regular event
        aggregator.record_event(NetworkEvent {
            timestamp: 10,
            app_path: app_path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 123,
            parent_process_name: None,
            remote_ip: "1.1.1.1".parse().unwrap(),
            remote_port: 80,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });

        assert!(
            !aggregator
                .apps
                .get(&app_path.to_lowercase())
                .unwrap()
                .is_knocking
        );

        let mut blocked_set = std::collections::HashSet::new();
        blocked_set.insert(app_path.to_string());
        blocked_set.insert(r"C:\Inactive\blocked.exe".to_string());

        aggregator.set_blocked_apps(blocked_set);

        // Existing app is now marked knocking
        assert!(
            aggregator
                .apps
                .get(&app_path.to_lowercase())
                .unwrap()
                .is_knocking
        );

        // Inactive app from Windows Firewall is also registered in the apps map
        let inactive = aggregator.apps.get(r"c:\inactive\blocked.exe").unwrap();
        assert!(inactive.is_knocking);
        assert_eq!(inactive.app_name, "blocked.exe");
    }

    #[test]
    fn test_aggregator_separates_services_and_directions() {
        let mut agg = EventAggregator::new();
        agg.record_event(NetworkEvent {
            timestamp: 10,
            app_path: r"C:\Windows\System32\svchost.exe".into(),
            service_name: Some("Dnscache".into()),
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 100,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            remote_port: 53,
            protocol: "UDP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });
        agg.record_event(NetworkEvent {
            timestamp: 11,
            app_path: r"C:\Windows\System32\svchost.exe".into(),
            service_name: Some("DiagTrack".into()),
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 200,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("20.190.159.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: true,
            zone: Zone::Internet,
        });
        assert_eq!(
            agg.apps.len(),
            2,
            "Different Windows services in svchost.exe must have distinct entries"
        );
    }

    #[test]
    fn test_aggregator_separates_inbound_and_outbound() {
        let mut agg = EventAggregator::new();
        let app_path = r"C:\Tools\listener.exe";
        agg.record_event(NetworkEvent {
            timestamp: 10,
            app_path: app_path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 100,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });
        agg.record_event(NetworkEvent {
            timestamp: 12,
            app_path: app_path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Inbound,
            process_id: 100,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("192.168.1.50").unwrap(),
            remote_port: 8080,
            protocol: "TCP".into(),
            is_blocked: true,
            zone: Zone::Lan,
        });
        assert_eq!(
            agg.apps.len(),
            2,
            "Inbound and Outbound for same binary must have distinct entries"
        );
        let out_key = crate::core::rules::make_app_key(
            app_path,
            None,
            crate::core::rules::RuleDirection::Outbound,
        );
        let in_key = crate::core::rules::make_app_key(
            app_path,
            None,
            crate::core::rules::RuleDirection::Inbound,
        );
        assert!(agg.apps.contains_key(&out_key));
        assert!(agg.apps.contains_key(&in_key));
        assert!(!agg.apps.get(&out_key).unwrap().is_knocking);
        assert!(agg.apps.get(&in_key).unwrap().is_knocking);
    }
}
