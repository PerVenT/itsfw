//! Стан програми та бізнес-логіка TUI.

use crate::core::firewall::FirewallRuleParams;
#[cfg(windows)]
use crate::core::firewall::WindowsFirewallManager;
use crate::core::monitor::EventAggregator;
use crate::core::rules::{
    ActiveTheme, AllowedZoneScope, AppRule, NetProtocol, RuleAction, RuleDirection, UserConfig,
};
use crate::tui::theme::ThemePalette;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewFilter {
    All,
    KnockingOnly,
    AllowedOnly,
    BlockedOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallDirection {
    Outbound,
    Inbound,
}

impl FirewallDirection {
    pub fn label(&self) -> &'static str {
        match self {
            FirewallDirection::Outbound => "Outbound",
            FirewallDirection::Inbound => "Inbound",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    NameAsc,
    ActivityHitsDesc,
    RecentActivityDesc,
    StatusPriority,
    ZoneInternetFirst,
}

impl SortMode {
    pub const ALL: [SortMode; 5] = [
        SortMode::NameAsc,
        SortMode::ActivityHitsDesc,
        SortMode::RecentActivityDesc,
        SortMode::StatusPriority,
        SortMode::ZoneInternetFirst,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            SortMode::NameAsc => "Name (A → Z)",
            SortMode::ActivityHitsDesc => "Network Activity (Most Hits)",
            SortMode::RecentActivityDesc => "Recent Activity (Last Seen)",
            SortMode::StatusPriority => "Status (Knocking → Blocked → Allowed)",
            SortMode::ZoneInternetFirst => "Traffic Zone (INET → LAN)",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            SortMode::NameAsc => "Name ▲",
            SortMode::ActivityHitsDesc => "Hits ▼",
            SortMode::RecentActivityDesc => "Recent ▼",
            SortMode::StatusPriority => "Status ▼",
            SortMode::ZoneInternetFirst => "Zone ▼",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEditorField {
    Action,      // [Allow | Block]
    Direction,   // [Outbound | Inbound]
    ZoneScope,   // [All (LAN+Inet) | LAN Only | Internet Only | Custom IP/CIDR]
    CustomIp,    // Editable string when ZoneScope == CustomIp
    Protocol,    // [TCP | UDP | Any]
    Ports,       // Editable string ("80,443", "8000-8080", "*") when Protocol != Any
    ServiceOnly, // [App Binary | Service: <name>] (shown/active when service_name is present)
}

pub struct App {
    pub should_quit: bool,
    pub is_admin: bool,
    pub firewall_active: bool,
    pub current_filter: ViewFilter,
    pub sort_mode: SortMode,
    pub sort_menu_open: bool,
    pub sort_menu_index: usize,
    pub sort_snapshot: std::collections::HashMap<String, (u64, u64)>,
    pub selected_index: usize,
    pub selected_app_path: Option<String>,
    pub config: UserConfig,
    pub active_rules: std::collections::HashMap<String, AppRule>,
    pub aggregator: EventAggregator,
    pub verified_fw_rules: std::collections::HashMap<String, String>,
    pub search_query: String,
    pub search_active: bool,
    pub active_direction: FirewallDirection,
    pub listening_mode: bool,
    pub listening_selected_index: usize,
    pub listening_sockets: Vec<crate::core::scanner::ListeningSocketInfo>,
    pub edit_mode: bool,
    pub edit_app_path: String,
    pub edit_remote_ip: Option<String>,
    pub edit_ports: String,
    pub edit_protocol: String,
    pub edit_focused_field: RuleEditorField,
    pub edit_action: RuleAction,
    pub edit_direction: RuleDirection,
    pub edit_zone_scope: AllowedZoneScope,
    pub edit_custom_ip_mode: bool,
    pub edit_custom_ip: String,
    pub edit_service_name: Option<String>,
    pub edit_apply_to_service: bool,
    pub edit_error: Option<String>,
    pub stream_paused: bool,
    pub lockdown_active: bool,
    pub unseen_knocking: std::collections::HashSet<String>,
    pub metadata_cache: std::collections::HashMap<String, crate::core::process::ProcessMetadata>,
    pub dns_resolver: crate::core::dns::DnsResolver,
    pub watcher: Option<crate::core::watcher::FirewallRegistryWatcher>,
    pub status_message: Option<(String, std::time::Instant)>,
}

impl App {
    pub fn new() -> Self {
        Self::new_with_privilege(crate::core::admin::is_running_as_admin())
    }

    pub fn new_with_privilege(is_admin: bool) -> Self {
        let config = UserConfig::load_or_create();
        Self {
            should_quit: false,
            is_admin,
            firewall_active:
                crate::core::firewall::WindowsFirewallManager::is_outbound_policy_blocking(),
            current_filter: ViewFilter::All,
            sort_mode: SortMode::NameAsc,
            sort_menu_open: false,
            sort_menu_index: 0,
            sort_snapshot: std::collections::HashMap::new(),
            selected_index: 0,
            selected_app_path: None,
            config,
            active_rules: std::collections::HashMap::new(),
            aggregator: EventAggregator::new(),
            verified_fw_rules: std::collections::HashMap::new(),
            search_query: String::new(),
            search_active: false,
            active_direction: FirewallDirection::Outbound,
            listening_mode: false,
            listening_selected_index: 0,
            listening_sockets: Vec::new(),
            edit_mode: false,
            edit_app_path: String::new(),
            edit_remote_ip: None,
            edit_ports: "80,443".into(),
            edit_protocol: "TCP".into(),
            edit_focused_field: RuleEditorField::Action,
            edit_action: RuleAction::Allow,
            edit_direction: RuleDirection::Outbound,
            edit_zone_scope: AllowedZoneScope::Both,
            edit_custom_ip_mode: false,
            edit_custom_ip: String::new(),
            edit_service_name: None,
            edit_apply_to_service: false,
            edit_error: None,
            stream_paused: false,
            lockdown_active: crate::core::firewall::WindowsFirewallManager::is_lockdown_active(),
            unseen_knocking: std::collections::HashSet::new(),
            metadata_cache: std::collections::HashMap::new(),
            dns_resolver: crate::core::dns::DnsResolver::default(),
            watcher: None,
            status_message: None,
        }
    }

    pub fn set_search_query(&mut self, query: &str) {
        self.search_query = query.to_string();
        self.search_active = !query.is_empty();
        self.listening_mode = query.starts_with(':');
        self.listening_selected_index = 0;
    }

    pub fn refresh_listening_sockets(&mut self) {
        self.listening_sockets = crate::core::scanner::scan_listening_sockets();
        self.listening_selected_index = 0;
    }

    pub fn filtered_listening_sockets(&self) -> Vec<&crate::core::scanner::ListeningSocketInfo> {
        let filter = if self.search_query.starts_with(':') {
            self.search_query[1..].trim().to_lowercase()
        } else {
            self.search_query.trim().to_lowercase()
        };

        if filter.is_empty() {
            return self.listening_sockets.iter().collect();
        }

        self.listening_sockets
            .iter()
            .filter(|s| {
                s.port.to_string().contains(&filter)
                    || s.process_name.to_lowercase().contains(&filter)
                    || s.protocol.to_lowercase().contains(&filter)
            })
            .collect()
    }

    pub fn next_listening_socket(&mut self) {
        let total = self.filtered_listening_sockets().len();
        if total == 0 {
            self.listening_selected_index = 0;
            return;
        }
        self.listening_selected_index = (self.listening_selected_index + 1) % total;
    }

    pub fn prev_listening_socket(&mut self) {
        let total = self.filtered_listening_sockets().len();
        if total == 0 {
            self.listening_selected_index = 0;
            return;
        }
        if self.listening_selected_index == 0 {
            self.listening_selected_index = total - 1;
        } else {
            self.listening_selected_index -= 1;
        }
    }

    pub fn kill_selected_listening_pid(&mut self) -> Result<u32, String> {
        if !self.is_admin {
            let err =
                "NON-ADMIN: Terminating process requires administrator privileges".to_string();
            self.set_status(err.clone());
            return Err(err);
        }

        let filtered = self.filtered_listening_sockets();
        let target = match filtered.get(self.listening_selected_index) {
            Some(s) => (s.pid, s.process_name.clone()),
            None => return Err("No process selected".to_string()),
        };

        let pid = target.0;
        let name = target.1;

        #[cfg(windows)]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                match OpenProcess(PROCESS_TERMINATE, false, pid) {
                    Ok(handle) => {
                        let res = TerminateProcess(handle, 1);
                        let _ = CloseHandle(handle);
                        if res.is_ok() {
                            self.set_status(format!("Killed process {} (PID {})", name, pid));
                            self.refresh_listening_sockets();
                            Ok(pid)
                        } else {
                            let err = format!("Failed to terminate PID {}", pid);
                            self.set_status(err.clone());
                            Err(err)
                        }
                    }
                    Err(e) => {
                        let err = format!("Failed to open PID {}: {:?}", pid, e);
                        self.set_status(err.clone());
                        Err(err)
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            self.set_status(format!("Killed mock process {} (PID {})", name, pid));
            Ok(pid)
        }
    }

    pub fn toggle_direction(&mut self) {
        self.active_direction = match self.active_direction {
            FirewallDirection::Outbound => FirewallDirection::Inbound,
            FirewallDirection::Inbound => FirewallDirection::Outbound,
        };
        self.sync_selection();
    }

    /// Фіксує знімок метрик активності (hits, last_hit_time), щоб список НЕ стрибав кожні 2 секунди під час перегляду.
    pub fn latch_sort_snapshot(&mut self) {
        self.sort_snapshot.clear();
        for (k, summary) in &self.aggregator.apps {
            self.sort_snapshot.insert(
                k.to_lowercase(),
                (summary.total_hits, summary.last_hit_time),
            );
        }
    }

    pub fn set_sort_mode(&mut self, mode: SortMode) {
        self.sort_mode = mode;
        if let Some(pos) = SortMode::ALL.iter().position(|m| *m == mode) {
            self.sort_menu_index = pos;
        }
        self.latch_sort_snapshot();
        self.sync_selection();
        self.set_status(format!("Sort: {}", mode.label()));
    }

    pub fn toggle_sort_menu(&mut self) {
        self.sort_menu_open = !self.sort_menu_open;
        if self.sort_menu_open {
            if let Some(pos) = SortMode::ALL.iter().position(|m| *m == self.sort_mode) {
                self.sort_menu_index = pos;
            }
        }
    }

    /// Zero-Trust перевірка прав Адміністратора перед будь-якою мутацією стану фаервола.
    pub fn require_admin(&mut self, action_name: &str) -> bool {
        if !self.is_admin {
            self.set_status(format!(
                "DENIED [{}]: Administrator privileges required (Read-Only Mode)",
                action_name
            ));
            return false;
        }
        true
    }

    /// Синхронізує стан додатків із правилами, зчитаними безпосередньо з Windows Firewall (Єдине Джерело Правди).
    pub fn sync_from_os_rules(&mut self, os_rules: std::collections::HashMap<String, AppRule>) {
        self.active_rules = os_rules;
        self.aggregator.sync_firewall_rules(&self.active_rules);
        self.sync_selection();
    }

    pub fn rule_for_app_entry(
        &self,
        item: &crate::core::monitor::AppActivitySummary,
    ) -> Option<&AppRule> {
        let key = crate::core::rules::make_app_key(
            &item.app_path,
            item.service_name.as_deref(),
            item.direction,
        );
        self.active_rules
            .get(&key)
            .or_else(|| self.active_rules.get(&item.app_path.to_lowercase()))
    }

    /// Повертає активне правило Windows Firewall для заданого шляху додатку (регістронезалежно).
    pub fn rule_for_app(&self, app_path: &str) -> Option<&AppRule> {
        let dir = match self.active_direction {
            FirewallDirection::Outbound => RuleDirection::Outbound,
            FirewallDirection::Inbound => RuleDirection::Inbound,
        };
        let app_key = crate::core::rules::make_app_key(app_path, None, dir);
        self.active_rules.get(&app_key).or_else(|| {
            self.active_rules
                .get(&app_path.to_lowercase())
                .filter(|r| r.service_name.is_none())
        })
    }

    /// Визначає назву служби для заданого шляху: спершу перевіряє поточний виділений елемент,
    /// а якщо він не збігається — шукає в агрегаторі запис для (app_path, active_direction) із service_name.
    pub fn resolve_service_for_path(&self, app_path: &str) -> Option<String> {
        let visible = self.visible_apps();
        if let Some(selected_item) = visible.get(self.selected_index) {
            if selected_item.app_path.eq_ignore_ascii_case(app_path) {
                return selected_item.service_name.clone();
            }
        }
        let target_dir = match self.active_direction {
            FirewallDirection::Outbound => RuleDirection::Outbound,
            FirewallDirection::Inbound => RuleDirection::Inbound,
        };
        for entry in self.aggregator.get_sorted_list() {
            if entry.direction == target_dir
                && entry.app_path.eq_ignore_ascii_case(app_path)
                && entry.service_name.is_some()
            {
                return entry.service_name.clone();
            }
        }
        None
    }

    /// Фіксує курсор на вибраному додатку (`selected_app_path`), щоб список не стрибав при появі нових процесів.
    pub fn sync_selection(&mut self) {
        let visible = self.visible_apps();
        if visible.is_empty() {
            self.selected_index = 0;
            self.selected_app_path = None;
            return;
        }

        if let Some(ref target) = self.selected_app_path {
            if let Some(pos) = visible
                .iter()
                .position(|a| a.app_path.eq_ignore_ascii_case(target))
            {
                self.selected_index = pos;
                return;
            }
        }

        if self.selected_index >= visible.len() {
            self.selected_index = visible.len() - 1;
        }
        self.selected_app_path = Some(visible[self.selected_index].app_path.clone());
    }

    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some((msg, std::time::Instant::now()));
    }

    /// Повертає список додатків, відфільтрований згідно з поточним фільтром та відсортований за вибраним режимом.
    /// Єдине джерело правди для рендерингу, навігації та виконання дій!
    pub fn visible_apps(&self) -> Vec<crate::core::monitor::AppActivitySummary> {
        let all_apps = self.aggregator.get_sorted_list();
        let target_dir = match self.active_direction {
            FirewallDirection::Outbound => RuleDirection::Outbound,
            FirewallDirection::Inbound => RuleDirection::Inbound,
        };

        let mut filtered: Vec<crate::core::monitor::AppActivitySummary> = all_apps
            .into_iter()
            .filter(|app_item| {
                if app_item.direction != target_dir {
                    return false;
                }
                if !self.search_query.is_empty()
                    && !app_item
                        .app_name
                        .to_lowercase()
                        .contains(&self.search_query.to_lowercase())
                {
                    return false;
                }
                match self.current_filter {
                    ViewFilter::All => true,
                    ViewFilter::KnockingOnly => app_item.is_knocking && app_item.total_hits > 0,
                    ViewFilter::AllowedOnly => !app_item.is_knocking,
                    ViewFilter::BlockedOnly => self
                        .rule_for_app_entry(app_item)
                        .map(|r| r.action == RuleAction::Block)
                        .unwrap_or(false),
                }
            })
            .cloned()
            .collect();

        let name_cmp = |a: &crate::core::monitor::AppActivitySummary,
                        b: &crate::core::monitor::AppActivitySummary| {
            a.app_name
                .to_lowercase()
                .cmp(&b.app_name.to_lowercase())
                .then_with(|| a.app_path.to_lowercase().cmp(&b.app_path.to_lowercase()))
        };

        match self.sort_mode {
            SortMode::NameAsc => {
                filtered.sort_by(name_cmp);
            }
            SortMode::ActivityHitsDesc => {
                filtered.sort_by(|a, b| {
                    let hits_a = self
                        .sort_snapshot
                        .get(&a.app_path.to_lowercase())
                        .map(|(h, _)| *h)
                        .unwrap_or(0);
                    let hits_b = self
                        .sort_snapshot
                        .get(&b.app_path.to_lowercase())
                        .map(|(h, _)| *h)
                        .unwrap_or(0);
                    hits_b.cmp(&hits_a).then_with(|| name_cmp(a, b))
                });
            }
            SortMode::RecentActivityDesc => {
                filtered.sort_by(|a, b| {
                    let ts_a = self
                        .sort_snapshot
                        .get(&a.app_path.to_lowercase())
                        .map(|(_, ts)| *ts)
                        .unwrap_or(0);
                    let ts_b = self
                        .sort_snapshot
                        .get(&b.app_path.to_lowercase())
                        .map(|(_, ts)| *ts)
                        .unwrap_or(0);
                    ts_b.cmp(&ts_a).then_with(|| name_cmp(a, b))
                });
            }
            SortMode::StatusPriority => {
                let status_rank = |item: &crate::core::monitor::AppActivitySummary| -> u8 {
                    let rule = self.rule_for_app_entry(item);
                    let is_explicit_block =
                        rule.map(|r| r.action == RuleAction::Block).unwrap_or(false);
                    if item.is_knocking && !is_explicit_block {
                        0 // Knocking (unconfigured / dropped)
                    } else if is_explicit_block {
                        1 // Explicitly blocked
                    } else if rule.is_some() {
                        2 // Explicitly allowed
                    } else {
                        3 // Default
                    }
                };
                filtered.sort_by(|a, b| {
                    status_rank(a)
                        .cmp(&status_rank(b))
                        .then_with(|| name_cmp(a, b))
                });
            }
            SortMode::ZoneInternetFirst => {
                let zone_rank = |item: &crate::core::monitor::AppActivitySummary| -> u8 {
                    match item.zones_display() {
                        "LAN+INET" => 0,
                        "INET" => 1,
                        "LAN" => 2,
                        _ => 3,
                    }
                };
                filtered
                    .sort_by(|a, b| zone_rank(a).cmp(&zone_rank(b)).then_with(|| name_cmp(a, b)));
            }
        }

        filtered
    }

    pub fn set_filter(&mut self, filter: ViewFilter, name: &str) {
        self.current_filter = filter;
        if filter == ViewFilter::KnockingOnly {
            self.unseen_knocking.clear();
        }
        self.selected_index = 0;
        self.selected_app_path = None;
        self.sync_selection();
        self.set_status(format!("Filter: {}", name));
    }

    pub fn current_palette(&self) -> ThemePalette {
        ThemePalette::for_theme(self.config.theme)
    }

    pub fn toggle_theme(&mut self) {
        self.config.theme = match self.config.theme {
            ActiveTheme::MonokaiProRistretto => ActiveTheme::GruvboxDarkSoft,
            ActiveTheme::GruvboxDarkSoft => ActiveTheme::MonokaiProRistretto,
        };
        let _ = self.config.save();
        self.set_status(format!("Theme changed to {:?}", self.config.theme));
    }

    pub fn next_item(&mut self, total: usize) {
        if total > 0 {
            self.selected_index = (self.selected_index + 1) % total;
            let visible = self.visible_apps();
            if let Some(item) = visible.get(self.selected_index) {
                self.selected_app_path = Some(item.app_path.clone());
            }
        }
    }

    pub fn prev_item(&mut self, total: usize) {
        if total > 0 {
            if self.selected_index == 0 {
                self.selected_index = total - 1;
            } else {
                self.selected_index -= 1;
            }
            let visible = self.visible_apps();
            if let Some(item) = visible.get(self.selected_index) {
                self.selected_app_path = Some(item.app_path.clone());
            }
        }
    }

    pub fn toggle_firewall_policy(&mut self) {
        if !self.require_admin("Toggle Firewall Policy") {
            return;
        }
        let target_state = !self.firewall_active;
        #[cfg(windows)]
        {
            match crate::core::firewall::WindowsFirewallManager::set_outbound_policy(target_state) {
                Ok(_) => {
                    self.firewall_active = target_state;
                    let status_str = if self.firewall_active {
                        "Firewall: ACTIVE (Blocking Outbound)"
                    } else {
                        "Firewall: INACTIVE (Allow Outbound)"
                    };
                    self.set_status(status_str.into());
                }
                Err(e) => {
                    self.set_status(format!("ERROR: Failed to change policy: {}", e));
                }
            }
        }
        #[cfg(not(windows))]
        {
            self.firewall_active = target_state;
        }
    }

    pub fn open_rule_editor(&mut self) {
        if let Some(app) = self.visible_apps().get(self.selected_index) {
            let path = app.app_path.clone();
            self.open_rule_editor_for_app(&path);
        } else if self.require_admin("Custom Rule Editor") {
            self.edit_mode = true;
        }
    }

    pub fn open_rule_editor_for_app(&mut self, app_path: &str) {
        if !self.require_admin("Custom Rule Editor") {
            return;
        }

        self.edit_app_path = app_path.to_string();
        self.edit_mode = true;
        self.edit_focused_field = RuleEditorField::Action;
        self.edit_error = None;

        let active_rule_dir = match self.active_direction {
            FirewallDirection::Outbound => RuleDirection::Outbound,
            FirewallDirection::Inbound => RuleDirection::Inbound,
        };

        let svc = self.resolve_service_for_path(app_path);
        let app_key = crate::core::rules::make_app_key(app_path, svc.as_deref(), active_rule_dir);

        let existing = self
            .active_rules
            .get(&app_key)
            .or_else(|| self.active_rules.get(&app_path.to_lowercase()))
            .cloned();

        if let Some(existing) = existing {
            self.edit_action = existing.action;
            self.edit_direction = existing.direction;
            self.edit_zone_scope = existing.zone_scope;
            self.edit_custom_ip_mode = existing.custom_remote_ip.is_some();
            self.edit_custom_ip = existing.custom_remote_ip.clone().unwrap_or_default();
            self.edit_remote_ip = existing.custom_remote_ip;
            self.edit_ports = existing.ports;
            self.edit_protocol = match existing.protocol {
                NetProtocol::Tcp => "TCP".into(),
                NetProtocol::Udp => "UDP".into(),
                NetProtocol::Any => "ANY".into(),
            };
            self.edit_service_name = existing.service_name.clone().or_else(|| svc.clone());
            self.edit_apply_to_service = self.edit_service_name.is_some();
        } else {
            self.edit_action = RuleAction::Allow;
            self.edit_direction = active_rule_dir;
            self.edit_zone_scope = AllowedZoneScope::Both;
            self.edit_custom_ip_mode = false;
            self.edit_custom_ip = String::new();
            self.edit_remote_ip = None;
            self.edit_service_name = svc.clone();
            self.edit_apply_to_service = svc.is_some();

            let summary = self
                .aggregator
                .apps
                .get(&app_key)
                .or_else(|| self.aggregator.apps.get(&app_path.to_lowercase()));

            if let Some(summary) = summary {
                if summary.service_name.is_some() {
                    self.edit_service_name = summary.service_name.clone();
                    self.edit_apply_to_service = true;
                }
                if let Some(last_ev) = summary.recent_events.last() {
                    self.edit_remote_ip = Some(last_ev.remote_ip.to_string());
                    self.edit_custom_ip = last_ev.remote_ip.to_string();
                    self.edit_ports = last_ev.remote_port.to_string();
                    self.edit_protocol = last_ev.protocol.clone();
                } else {
                    self.edit_ports = summary.all_ports_list();
                    self.edit_protocol = "TCP".into();
                }
            } else {
                self.edit_ports = "80,443".into();
                self.edit_protocol = "TCP".into();
            }
        }
    }

    pub fn editor_active_fields(&self) -> Vec<RuleEditorField> {
        let mut fields = vec![
            RuleEditorField::Action,
            RuleEditorField::Direction,
            RuleEditorField::ZoneScope,
        ];
        if self.edit_custom_ip_mode {
            fields.push(RuleEditorField::CustomIp);
        }
        fields.push(RuleEditorField::Protocol);
        let proto = match self.edit_protocol.to_uppercase().as_str() {
            "UDP" => NetProtocol::Udp,
            "ANY" => NetProtocol::Any,
            _ => NetProtocol::Tcp,
        };
        if proto != NetProtocol::Any {
            fields.push(RuleEditorField::Ports);
        }
        if self.edit_service_name.is_some() {
            fields.push(RuleEditorField::ServiceOnly);
        }
        fields
    }

    pub fn editor_next_field(&mut self) {
        let fields = self.editor_active_fields();
        if fields.is_empty() {
            return;
        }
        let pos = fields
            .iter()
            .position(|f| *f == self.edit_focused_field)
            .unwrap_or(0);
        let next_pos = (pos + 1) % fields.len();
        self.edit_focused_field = fields[next_pos];
    }

    pub fn editor_prev_field(&mut self) {
        let fields = self.editor_active_fields();
        if fields.is_empty() {
            return;
        }
        let pos = fields
            .iter()
            .position(|f| *f == self.edit_focused_field)
            .unwrap_or(0);
        let prev_pos = if pos == 0 { fields.len() - 1 } else { pos - 1 };
        self.edit_focused_field = fields[prev_pos];
    }

    pub fn editor_cycle_option(&mut self, forward: bool) {
        match self.edit_focused_field {
            RuleEditorField::Action => {
                self.edit_action = match self.edit_action {
                    RuleAction::Allow => RuleAction::Block,
                    RuleAction::Block => RuleAction::Allow,
                };
            }
            RuleEditorField::Direction => {
                self.edit_direction = match self.edit_direction {
                    RuleDirection::Outbound => RuleDirection::Inbound,
                    RuleDirection::Inbound => RuleDirection::Outbound,
                };
            }
            RuleEditorField::ZoneScope => {
                let cur = if self.edit_custom_ip_mode {
                    3
                } else {
                    match self.edit_zone_scope {
                        AllowedZoneScope::Both => 0,
                        AllowedZoneScope::LanOnly => 1,
                        AllowedZoneScope::InternetOnly => 2,
                    }
                };
                let next = if forward {
                    (cur + 1) % 4
                } else if cur == 0 {
                    3
                } else {
                    cur - 1
                };
                match next {
                    0 => {
                        self.edit_custom_ip_mode = false;
                        self.edit_zone_scope = AllowedZoneScope::Both;
                    }
                    1 => {
                        self.edit_custom_ip_mode = false;
                        self.edit_zone_scope = AllowedZoneScope::LanOnly;
                    }
                    2 => {
                        self.edit_custom_ip_mode = false;
                        self.edit_zone_scope = AllowedZoneScope::InternetOnly;
                    }
                    _ => {
                        self.edit_custom_ip_mode = true;
                        self.edit_zone_scope = AllowedZoneScope::Both;
                    }
                }
            }
            RuleEditorField::Protocol => {
                let protos = ["TCP", "UDP", "ANY"];
                let cur = self.edit_protocol.to_uppercase();
                let pos = protos.iter().position(|p| *p == cur).unwrap_or(0);
                let next_pos = if forward {
                    (pos + 1) % protos.len()
                } else if pos == 0 {
                    protos.len() - 1
                } else {
                    pos - 1
                };
                self.edit_protocol = protos[next_pos].to_string();
            }
            RuleEditorField::ServiceOnly => {
                self.edit_apply_to_service = !self.edit_apply_to_service;
            }
            RuleEditorField::CustomIp | RuleEditorField::Ports => {
                // Text fields do not cycle options
            }
        }
    }

    pub fn editor_input_char(&mut self, c: char) {
        self.edit_error = None;
        match self.edit_focused_field {
            RuleEditorField::CustomIp => {
                self.edit_custom_ip.push(c);
                self.edit_remote_ip = Some(self.edit_custom_ip.clone());
            }
            RuleEditorField::Ports => {
                self.edit_ports.push(c);
            }
            _ => {}
        }
    }

    pub fn editor_backspace(&mut self) {
        self.edit_error = None;
        match self.edit_focused_field {
            RuleEditorField::CustomIp => {
                self.edit_custom_ip.pop();
                self.edit_remote_ip = if self.edit_custom_ip.is_empty() {
                    None
                } else {
                    Some(self.edit_custom_ip.clone())
                };
            }
            RuleEditorField::Ports => {
                self.edit_ports.pop();
            }
            _ => {}
        }
    }

    pub fn delete_rule_from_editor(&mut self) {
        if !self.edit_app_path.is_empty() {
            let path = self.edit_app_path.clone();
            self.reset_selected_rule(&path);
        }
        self.edit_mode = false;
        self.edit_error = None;
    }

    pub fn save_prefilled_rule(&mut self) -> bool {
        if self.edit_app_path.is_empty() {
            return false;
        }
        if !self.require_admin("Save Rule") {
            return false;
        }

        let proto = match self.edit_protocol.to_uppercase().as_str() {
            "UDP" => NetProtocol::Udp,
            "ANY" => NetProtocol::Any,
            _ => NetProtocol::Tcp,
        };

        // Validate ports
        let validated_ports = match crate::core::rules::validate_ports_spec(&self.edit_ports, proto)
        {
            Ok(p) => p,
            Err(e) => {
                self.edit_error = Some(e);
                return false;
            }
        };

        // Validate custom IP if applicable
        let custom_remote_ip = if self.edit_custom_ip_mode {
            match crate::core::rules::validate_ip_or_cidr_spec(&self.edit_custom_ip) {
                Ok(ip) => Some(ip),
                Err(e) => {
                    self.edit_error = Some(e);
                    return false;
                }
            }
        } else {
            None
        };

        self.edit_ports = validated_ports.clone();
        self.edit_error = None;

        let rule = AppRule {
            app_path: self.edit_app_path.clone(),
            service_name: if self.edit_apply_to_service {
                self.edit_service_name.clone()
            } else {
                None
            },
            direction: self.edit_direction,
            action: self.edit_action,
            zone_scope: self.edit_zone_scope,
            custom_remote_ip,
            protocol: proto,
            ports: validated_ports,
            interface_name: None,
            created_at: crate::core::monitor::current_timestamp_secs() as i64,
        };

        let msg = format!(
            "Rule Applied: {} ({:?} {:?})",
            self.edit_app_path, self.edit_direction, self.edit_action
        );
        self.apply_rule_internal(rule, &msg);
        self.edit_mode = false;
        true
    }

    fn apply_quick_rule(
        &mut self,
        selected_app_path: &str,
        action: RuleAction,
        zone_scope: AllowedZoneScope,
        msg: &str,
    ) {
        let dir = match self.active_direction {
            FirewallDirection::Outbound => RuleDirection::Outbound,
            FirewallDirection::Inbound => RuleDirection::Inbound,
        };
        let svc = self.resolve_service_for_path(selected_app_path);
        let rule = AppRule {
            app_path: selected_app_path.to_string(),
            service_name: svc,
            direction: dir,
            action,
            zone_scope,
            custom_remote_ip: None,
            protocol: NetProtocol::Any,
            ports: "*".into(),
            interface_name: None,
            created_at: crate::core::monitor::current_timestamp_secs() as i64,
        };

        self.apply_rule_internal(rule, msg);
    }

    /// Дозволяє вибраний додаток у LAN + Internet
    pub fn allow_selected_all(&mut self, selected_app_path: &str) {
        if !self.require_admin("Allow All") {
            return;
        }
        self.apply_quick_rule(
            selected_app_path,
            RuleAction::Allow,
            AllowedZoneScope::Both,
            "Allowed: LAN + Internet",
        );
    }

    /// Дозволяє вибраний додаток ТІЛЬКИ в LAN
    pub fn allow_selected_lan_only(&mut self, selected_app_path: &str) {
        if !self.require_admin("Allow LAN Only") {
            return;
        }
        self.apply_quick_rule(
            selected_app_path,
            RuleAction::Allow,
            AllowedZoneScope::LanOnly,
            "Allowed: LAN Only",
        );
    }

    /// Дозволяє вибраний додаток ТІЛЬКИ в Інтернет (блокує LAN)
    pub fn allow_selected_internet_only(&mut self, selected_app_path: &str) {
        if !self.require_admin("Allow Internet Only") {
            return;
        }
        self.apply_quick_rule(
            selected_app_path,
            RuleAction::Allow,
            AllowedZoneScope::InternetOnly,
            "Allowed: Internet Only",
        );
    }

    /// Дозволяє поточний порт, куди стукав додаток
    pub fn allow_selected_current_port(
        &mut self,
        selected_app_path: &str,
        port: u16,
        protocol_str: &str,
    ) {
        if !self.require_admin("Allow Port") {
            return;
        }
        let proto = match protocol_str.to_uppercase().as_str() {
            "TCP" => NetProtocol::Tcp,
            "UDP" => NetProtocol::Udp,
            _ => NetProtocol::Any,
        };
        let dir = match self.active_direction {
            FirewallDirection::Outbound => RuleDirection::Outbound,
            FirewallDirection::Inbound => RuleDirection::Inbound,
        };
        let svc = self.resolve_service_for_path(selected_app_path);

        let rule = AppRule {
            app_path: selected_app_path.to_string(),
            service_name: svc,
            direction: dir,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::Both,
            custom_remote_ip: None,
            protocol: proto,
            ports: port.to_string(),
            interface_name: None,
            created_at: crate::core::monitor::current_timestamp_secs() as i64,
        };

        let msg = format!("Allowed: {}:{}", protocol_str, port);
        self.apply_rule_internal(rule, &msg);
    }

    /// Блокує вибраний додаток (DENY)
    pub fn block_selected(&mut self, selected_app_path: &str) {
        if !self.require_admin("Deny App") {
            return;
        }
        self.apply_quick_rule(
            selected_app_path,
            RuleAction::Block,
            AllowedZoneScope::Both,
            "DENY",
        );
    }

    /// Скидає правило для додатка (Reset to default)
    pub fn reset_selected_rule(&mut self, app_path: &str) {
        if !self.require_admin("Reset Rule") {
            return;
        }
        if let Some(ref w) = self.watcher {
            w.mark_self_mutation();
        }
        let dir = match self.active_direction {
            FirewallDirection::Outbound => RuleDirection::Outbound,
            FirewallDirection::Inbound => RuleDirection::Inbound,
        };
        let svc = self.resolve_service_for_path(app_path);
        let key = app_path.to_lowercase();
        let app_key = crate::core::rules::make_app_key(app_path, svc.as_deref(), dir);

        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(mgr) = WindowsFirewallManager::new() {
                    let _ = mgr.remove_app_rules_for(app_path, svc.as_deref(), dir);
                    if svc.is_some() {
                        let _ = mgr.remove_app_rules_for(app_path, None, dir);
                    }
                }
            }
        }

        self.active_rules.remove(&key);
        self.active_rules.remove(&app_key);
        self.verified_fw_rules.remove(&key);
        self.verified_fw_rules.remove(&app_key);
        self.aggregator.blocked_paths_or_names.remove(&key);
        self.aggregator.blocked_paths_or_names.remove(&app_key);

        if svc.is_some() {
            let base_key = crate::core::rules::make_app_key(app_path, None, dir);
            self.active_rules.remove(&base_key);
            self.verified_fw_rules.remove(&base_key);
            self.aggregator.blocked_paths_or_names.remove(&base_key);
            if let Some(app_item) = self.aggregator.apps.get_mut(&base_key) {
                app_item.is_knocking = false;
            }
        }

        let filename = app_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or("")
            .to_lowercase();
        if !filename.is_empty() {
            self.aggregator.blocked_paths_or_names.remove(&filename);
        }

        if let Some(app_item) = self.aggregator.apps.get_mut(&key) {
            app_item.is_knocking = false;
        }
        if let Some(app_item) = self.aggregator.apps.get_mut(&app_key) {
            app_item.is_knocking = false;
        }

        self.set_status(format!("Rule removed (reset to default): {}", app_path));
        self.sync_selection();
    }

    pub fn toggle_stream_pause(&mut self) {
        self.stream_paused = !self.stream_paused;
        let msg = if self.stream_paused {
            "Network activity stream PAUSED"
        } else {
            "Network activity stream RESUMED"
        };
        self.set_status(msg.to_string());
    }

    pub fn toggle_lockdown(&mut self) {
        if !self.require_admin("Toggle Lockdown") {
            return;
        }
        let target = !self.lockdown_active;
        match crate::core::firewall::WindowsFirewallManager::set_lockdown(target) {
            Ok(_) => {
                self.lockdown_active = target;
                let msg = if target {
                    "🚨 LOCKDOWN ACTIVATED: All inbound & outbound traffic blocked"
                } else {
                    "Lockdown deactivated: Standard policy restored"
                };
                self.set_status(msg.to_string());
            }
            Err(e) => {
                self.set_status(format!("ERROR: Failed to toggle lockdown: {}", e));
            }
        }
    }

    pub fn record_incoming_event(&mut self, ev: crate::core::monitor::NetworkEvent) {
        if ev.is_blocked && self.current_filter != ViewFilter::KnockingOnly {
            let key = crate::core::rules::make_app_key(
                &ev.app_path,
                ev.service_name.as_deref(),
                ev.direction,
            );
            self.unseen_knocking.insert(key);
        }
        self.aggregator.record_event(ev);
    }

    pub fn unseen_knocking_count(&self) -> usize {
        self.unseen_knocking.len()
    }

    pub fn apply_listener_inbound_rule(
        &mut self,
        action: RuleAction,
        zone_scope: AllowedZoneScope,
    ) {
        if !self.require_admin("Apply Inbound Listener Rule") {
            return;
        }
        let filtered = self.filtered_listening_sockets();
        let target = match filtered.get(self.listening_selected_index) {
            Some(s) => (*s).clone(),
            None => {
                self.set_status("No listening socket selected".into());
                return;
            }
        };

        let proto = match target.protocol.to_uppercase().as_str() {
            "TCP" => NetProtocol::Tcp,
            "UDP" => NetProtocol::Udp,
            _ => NetProtocol::Any,
        };

        let rule = AppRule {
            app_path: target.app_path.clone(),
            service_name: None,
            direction: RuleDirection::Inbound,
            action,
            zone_scope,
            custom_remote_ip: None,
            protocol: proto,
            ports: target.port.to_string(),
            interface_name: None,
            created_at: crate::core::monitor::current_timestamp_secs() as i64,
        };

        let action_str = match (action, zone_scope) {
            (RuleAction::Allow, AllowedZoneScope::Both) => "Inbound Allow (All)",
            (RuleAction::Allow, AllowedZoneScope::LanOnly) => "Inbound Allow (LAN Only)",
            (RuleAction::Allow, AllowedZoneScope::InternetOnly) => "Inbound Allow (Internet Only)",
            (RuleAction::Block, _) => "Inbound Block",
        };

        let msg = format!(
            "{}: {} (:{} {})",
            action_str, target.process_name, target.port, target.protocol
        );
        self.apply_rule_internal(rule, &msg);
    }

    pub fn get_or_load_metadata(
        &mut self,
        app_path: &str,
    ) -> crate::core::process::ProcessMetadata {
        if let Some(meta) = self.metadata_cache.get(app_path) {
            return meta.clone();
        }
        let meta = crate::core::process::query_process_metadata(app_path);
        self.metadata_cache
            .insert(app_path.to_string(), meta.clone());
        meta
    }

    pub fn set_watcher(&mut self, watcher: crate::core::watcher::FirewallRegistryWatcher) {
        self.watcher = Some(watcher);
    }

    fn apply_rule_internal(&mut self, rule: AppRule, success_text: &str) {
        if !self.require_admin(success_text) {
            return;
        }

        if let Some(ref w) = self.watcher {
            w.mark_self_mutation();
        }

        let key = rule.app_path.to_lowercase();
        let app_key = crate::core::rules::make_app_key(
            &rule.app_path,
            rule.service_name.as_deref(),
            rule.direction,
        );
        let filename = rule
            .app_path
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("")
            .to_lowercase();

        #[cfg(windows)]
        {
            let params = FirewallRuleParams::from_app_rule(&rule);
            let mgr = match WindowsFirewallManager::new() {
                Ok(m) => m,
                Err(e) => {
                    self.set_status(format!("ERROR: Firewall manager init failed: {}", e));
                    return;
                }
            };
            match mgr.apply_rule(&params) {
                Ok(_) => {
                    if rule.service_name.is_none() {
                        self.verified_fw_rules
                            .insert(key.clone(), params.name.clone());
                    }
                    self.verified_fw_rules.insert(app_key.clone(), params.name);
                    self.set_status(format!("ENFORCED: {} (Windows Firewall)", success_text));
                }
                Err(e) => {
                    // ZERO TRUST: якщо ОС не застосувала правило, жоден візуальний стан не змінюється!
                    self.set_status(format!("ERROR: Firewall rejected rule: {}", e));
                    return;
                }
            }
        }
        #[cfg(not(windows))]
        {
            let params = FirewallRuleParams::from_app_rule(&rule);
            if rule.service_name.is_none() {
                self.verified_fw_rules
                    .insert(key.clone(), params.name.clone());
            }
            self.verified_fw_rules.insert(app_key.clone(), params.name);
            self.set_status(format!("ENFORCED: {}", success_text));
        }

        // Оновлюємо стан в агрегаторі тільки після успішного застосування правила у фаерволі ОС
        if let Some(app_item) = self.aggregator.apps.get_mut(&app_key) {
            match rule.action {
                RuleAction::Allow => {
                    app_item.is_knocking = false;
                }
                RuleAction::Block => {
                    app_item.is_knocking = true;
                }
            }
        }
        if rule.service_name.is_none() {
            if let Some(app_item) = self.aggregator.apps.get_mut(&key) {
                match rule.action {
                    RuleAction::Allow => {
                        app_item.is_knocking = false;
                    }
                    RuleAction::Block => {
                        app_item.is_knocking = true;
                    }
                }
            }
        }

        match rule.action {
            RuleAction::Allow => {
                if rule.service_name.is_none() {
                    self.aggregator.blocked_paths_or_names.remove(&key);
                }
                self.aggregator.blocked_paths_or_names.remove(&app_key);
                if !filename.is_empty() && rule.service_name.is_none() {
                    self.aggregator.blocked_paths_or_names.remove(&filename);
                }
            }
            RuleAction::Block => {
                if rule.service_name.is_none() {
                    self.aggregator.blocked_paths_or_names.insert(key.clone());
                }
                self.aggregator
                    .blocked_paths_or_names
                    .insert(app_key.clone());
                if !filename.is_empty() && rule.service_name.is_none() {
                    self.aggregator.blocked_paths_or_names.insert(filename);
                }
            }
        }

        if rule.service_name.is_none() {
            self.active_rules.insert(key, rule.clone());
        }
        self.active_rules.insert(app_key, rule);
        self.sync_selection();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::monitor::NetworkEvent;
    use crate::core::zone::Zone;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_zero_trust_non_admin_cannot_mutate_rules_or_visual_state() {
        let mut app = App::new_with_privilege(false);
        let app_path = r"C:\Program Files\App\test.exe";
        app.aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: app_path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 42,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });

        // Attempt to block without admin rights
        app.block_selected(app_path);
        assert!(
            app.rule_for_app(app_path).is_none(),
            "rule must NOT be added without admin"
        );
        let summary = app.aggregator.apps.get(&app_path.to_lowercase()).unwrap();
        assert!(
            !summary.is_knocking,
            "visual state must NOT pretend app is blocked"
        );
        assert!(app.status_message.as_ref().unwrap().0.contains("DENIED"));

        // Attempt to allow LAN only without admin rights
        app.allow_selected_lan_only(app_path);
        assert!(
            app.rule_for_app(app_path).is_none(),
            "rule must NOT be added without admin"
        );

        // Attempt to toggle firewall policy without admin rights
        let prev_fw = app.firewall_active;
        app.toggle_firewall_policy();
        assert_eq!(
            app.firewall_active, prev_fw,
            "firewall policy must NOT flip without admin"
        );

        // Attempt to open rule editor without admin rights
        app.open_rule_editor();
        assert!(!app.edit_mode, "rule editor must NOT open without admin");
    }

    #[test]
    fn test_selection_stays_anchored_when_new_app_inserted_above() {
        let mut app = App::new_with_privilege(false);
        app.aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: r"C:\Apps\mu.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 1,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });
        app.aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: r"C:\Apps\zeta.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 2,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });

        // Move cursor to index 1 (zeta.exe)
        let total = app.visible_apps().len();
        app.next_item(total);
        assert_eq!(app.selected_index, 1);

        // Now alpha.exe appears on the network (sorted at index 0 before mu.exe and zeta.exe)
        app.aggregator.record_event(NetworkEvent {
            timestamp: 200,
            app_path: r"C:\Apps\alpha.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 3,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });
        app.sync_selection();

        // Cursor must stay anchored on zeta.exe (which is now at index 2)!
        let visible = app.visible_apps();
        assert_eq!(visible[app.selected_index].app_name, "zeta.exe");
    }

    #[test]
    fn test_dropped_tcp_syn_without_rule_appears_in_knocking_and_not_in_explicit_blocked() {
        let mut app = App::new_with_privilege(true);

        // 1. Явно заблокований додаток у правилах фаєрволу ОС (не запущений, total_hits == 0)
        let mut os_rules = std::collections::HashMap::new();
        let blocked_path = r"C:\Blocked\blocked_app.exe";
        os_rules.insert(
            blocked_path.to_lowercase(),
            AppRule {
                app_path: blocked_path.into(),
                service_name: None,
                direction: RuleDirection::Outbound,
                action: RuleAction::Block,
                zone_scope: AllowedZoneScope::Both,
                custom_remote_ip: None,
                protocol: NetProtocol::Any,
                ports: "*".into(),
                interface_name: None,
                created_at: 100,
            },
        );
        app.sync_from_os_rules(os_rules);

        // 2. Додаток без правил, чий TCP SYN відхилено типовим блокуванням вихідного трафіку (WFP drop)
        let knocking_path = r"C:\Tools\curl.exe";
        app.aggregator.record_event(NetworkEvent {
            timestamp: 200,
            app_path: knocking_path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 4321,
            parent_process_name: Some("shell.exe".into()),
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: true, // Dropped TCP SYN from WFP!
            zone: Zone::Internet,
        });

        // In ViewFilter::KnockingOnly ([2] Knocking):
        // curl.exe (dropped TCP SYN, total_hits > 0) MUST appear; inactive blocked_app.exe (total_hits == 0) must NOT clutter Knocking!
        app.set_filter(ViewFilter::KnockingOnly, "Knocking");
        let knocking_list = app.visible_apps();
        assert_eq!(knocking_list.len(), 1);
        assert_eq!(knocking_list[0].app_name, "curl.exe");
        assert!(knocking_list[0].is_knocking);

        // In ViewFilter::BlockedOnly ([4] Blocked):
        // Only blocked_app.exe (explicit Block rule) MUST appear; curl.exe (no explicit Block rule) must NOT appear in Blocked Rules!
        app.set_filter(ViewFilter::BlockedOnly, "Blocked");
        let blocked_list = app.visible_apps();
        assert_eq!(blocked_list.len(), 1);
        assert_eq!(blocked_list[0].app_name, "blocked_app.exe");
    }

    #[test]
    fn test_navigation_next_prev_wrap_and_empty() {
        let mut app = App::new_with_privilege(true);

        // Порожній список: навігація не панікує
        app.next_item(0);
        assert_eq!(app.selected_index, 0);
        app.prev_item(0);
        assert_eq!(app.selected_index, 0);

        // Додаємо 3 додатки
        for name in ["alpha.exe", "beta.exe", "gamma.exe"] {
            app.aggregator.record_event(NetworkEvent {
                timestamp: 100,
                app_path: format!(r"C:\Apps\{}", name),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                process_id: 1,
                parent_process_name: None,
                remote_ip: IpAddr::from_str("127.0.0.1").unwrap(),
                remote_port: 80,
                protocol: "TCP".into(),
                is_blocked: false,
                zone: Zone::Lan,
            });
        }

        let total = app.visible_apps().len();
        assert_eq!(total, 3);
        assert_eq!(app.selected_index, 0);

        // next_item: 0 -> 1 -> 2 -> 0 (циклічний перехід)
        app.next_item(total);
        assert_eq!(app.selected_index, 1);
        app.next_item(total);
        assert_eq!(app.selected_index, 2);
        app.next_item(total);
        assert_eq!(app.selected_index, 0);

        // prev_item: 0 -> 2 -> 1 -> 0 (циклічний перехід у зворотний бік)
        app.prev_item(total);
        assert_eq!(app.selected_index, 2);
        app.prev_item(total);
        assert_eq!(app.selected_index, 1);
        app.prev_item(total);
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn test_theme_toggle_cycles_palettes() {
        let mut app = App::new_with_privilege(true);
        app.config.theme = ActiveTheme::MonokaiProRistretto;
        assert_eq!(app.config.theme, ActiveTheme::MonokaiProRistretto);
        let initial_theme = app.current_palette();

        app.toggle_theme();
        assert_eq!(app.config.theme, ActiveTheme::GruvboxDarkSoft);
        let toggled_theme = app.current_palette();
        assert_ne!(
            initial_theme.fg, toggled_theme.fg,
            "Foreground colors must differ across Monokai and Gruvbox themes"
        );
        assert_ne!(
            initial_theme.surface, toggled_theme.surface,
            "Surface colors must differ across Monokai and Gruvbox themes"
        );

        app.toggle_theme();
        assert_eq!(app.config.theme, ActiveTheme::MonokaiProRistretto);
    }

    #[test]
    fn test_search_query_filters_visible_apps() {
        let mut app = App::new_with_privilege(true);
        for name in ["database.exe", "webserver.exe", "backup_agent.exe"] {
            app.aggregator.record_event(NetworkEvent {
                timestamp: 100,
                app_path: format!(r"C:\Services\{}", name),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                process_id: 1,
                parent_process_name: None,
                remote_ip: IpAddr::from_str("10.0.0.1").unwrap(),
                remote_port: 80,
                protocol: "TCP".into(),
                is_blocked: false,
                zone: Zone::Lan,
            });
        }

        assert_eq!(app.visible_apps().len(), 3);

        // Фільтр за підрядком
        app.search_query = "server".into();
        let filtered = app.visible_apps();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].app_name, "webserver.exe");

        // Нечутливість до регістру
        app.search_query = "DATA".into();
        let filtered_case = app.visible_apps();
        assert_eq!(filtered_case.len(), 1);
        assert_eq!(filtered_case[0].app_name, "database.exe");

        // Відсутність збігів
        app.search_query = "nonexistent".into();
        assert!(app.visible_apps().is_empty());

        // Скидання пошуку
        app.search_query.clear();
        assert_eq!(app.visible_apps().len(), 3);
    }

    #[test]
    fn test_sort_modes_and_latched_activity_sort_does_not_jump() {
        let mut app = App::new_with_privilege(true);

        // Record 1 hit for alpha.exe and 3 hits for beta.exe
        app.aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: r"C:\Apps\alpha.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 1,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            remote_port: 80,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Lan,
        });
        for ts in [101, 102, 103] {
            app.aggregator.record_event(NetworkEvent {
                timestamp: ts,
                app_path: r"C:\Apps\beta.exe".into(),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                process_id: 2,
                parent_process_name: None,
                remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
                remote_port: 443,
                protocol: "TCP".into(),
                is_blocked: false,
                zone: Zone::Internet,
            });
        }

        // Default sort is NameAsc: alpha.exe, beta.exe
        let names_default: Vec<String> =
            app.visible_apps().into_iter().map(|a| a.app_name).collect();
        assert_eq!(names_default, vec!["alpha.exe", "beta.exe"]);

        // Switch sort to ActivityHitsDesc via sort menu / set_sort_mode:
        // beta.exe (3 hits) comes before alpha.exe (1 hit)
        app.set_sort_mode(SortMode::ActivityHitsDesc);
        let names_hits: Vec<String> = app.visible_apps().into_iter().map(|a| a.app_name).collect();
        assert_eq!(names_hits, vec!["beta.exe", "alpha.exe"]);

        // Now alpha.exe gets 10 more live background hits while the user is looking at the list.
        // Because ActivityHitsDesc uses a latched snapshot until re-sorted/synced, the list MUST NOT jump!
        for ts in 200..210 {
            app.aggregator.record_event(NetworkEvent {
                timestamp: ts,
                app_path: r"C:\Apps\alpha.exe".into(),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                process_id: 1,
                parent_process_name: None,
                remote_ip: IpAddr::from_str("192.168.1.1").unwrap(),
                remote_port: 80,
                protocol: "TCP".into(),
                is_blocked: false,
                zone: Zone::Lan,
            });
        }
        let names_while_viewing: Vec<String> =
            app.visible_apps().into_iter().map(|a| a.app_name).collect();
        assert_eq!(
            names_while_viewing,
            vec!["beta.exe", "alpha.exe"],
            "List order must NOT jump during background polling in ActivityHitsDesc mode"
        );

        // When user explicitly re-applies sort (or presses sync), snapshot refreshes and alpha.exe (11 hits) moves to top:
        app.set_sort_mode(SortMode::ActivityHitsDesc);
        let names_after_refresh: Vec<String> =
            app.visible_apps().into_iter().map(|a| a.app_name).collect();
        assert_eq!(names_after_refresh, vec!["alpha.exe", "beta.exe"]);
    }

    #[test]
    fn test_sort_mode_short_label_and_app_default_init() {
        for mode in SortMode::ALL {
            assert!(!mode.short_label().is_empty());
        }

        let app = App::new();
        assert_eq!(app.selected_index, 0);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_firewall_direction_toggle_and_defaults() {
        let mut app = App::new();
        assert_eq!(app.active_direction, FirewallDirection::Outbound);

        app.toggle_direction();
        assert_eq!(app.active_direction, FirewallDirection::Inbound);

        app.toggle_direction();
        assert_eq!(app.active_direction, FirewallDirection::Outbound);
    }

    #[test]
    fn test_smart_search_and_listening_mode() {
        let mut app = App::new();
        assert!(!app.search_active);
        assert!(!app.listening_mode);

        app.listening_sockets = vec![
            crate::core::scanner::ListeningSocketInfo {
                port: 80,
                protocol: "TCP".into(),
                pid: 1234,
                process_name: "nginx.exe".into(),
                app_path: r"C:\nginx\nginx.exe".into(),
            },
            crate::core::scanner::ListeningSocketInfo {
                port: 53,
                protocol: "UDP".into(),
                pid: 5678,
                process_name: "dns.exe".into(),
                app_path: r"C:\dns\dns.exe".into(),
            },
        ];

        // 1. Regular search query does not activate listening_mode
        app.set_search_query("nginx");
        assert!(app.search_active);
        assert!(!app.listening_mode);

        // 2. Query starting with ':' activates listening_mode
        app.set_search_query(":");
        assert!(app.listening_mode);
        let all_listeners = app.filtered_listening_sockets();
        assert_eq!(all_listeners.len(), 2);

        // 3. Query with port filter
        app.set_search_query(":80");
        assert!(app.listening_mode);
        let filtered = app.filtered_listening_sockets();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 80);
        assert_eq!(filtered[0].process_name, "nginx.exe");

        // 4. Navigation over listening sockets
        app.set_search_query(":");
        assert_eq!(app.listening_selected_index, 0);
        app.next_listening_socket();
        assert_eq!(app.listening_selected_index, 1);
        app.next_listening_socket();
        assert_eq!(app.listening_selected_index, 0); // wraps
        app.prev_listening_socket();
        assert_eq!(app.listening_selected_index, 1); // wraps back
    }

    #[test]
    fn test_prefilled_rule_builder_from_recent_event() {
        let mut app = App::new_with_privilege(true);
        let path = r"C:\Tools\client.exe";
        app.aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 999,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            remote_port: 8443,
            protocol: "TCP".into(),
            is_blocked: true,
            zone: Zone::Internet,
        });

        app.open_rule_editor_for_app(path);
        assert!(app.edit_mode);
        assert_eq!(app.edit_app_path, path);
        assert_eq!(app.edit_remote_ip, Some("93.184.216.34".into()));
        assert_eq!(app.edit_ports, "8443");
        assert_eq!(app.edit_protocol, "TCP");
    }

    #[test]
    fn test_interactive_rule_editor_navigation_editing_and_validation() {
        let mut app = App::new_with_privilege(true);
        app.open_rule_editor_for_app(r"C:\App\curl.exe");
        assert!(app.edit_mode);
        assert_eq!(app.edit_focused_field, RuleEditorField::Action);

        // Toggle Action Allow -> Block
        app.editor_cycle_option(true);
        assert_eq!(app.edit_action, RuleAction::Block);

        // Navigate to Ports and enter invalid port
        app.edit_focused_field = RuleEditorField::Ports;
        app.edit_ports = "99999".into();
        assert!(
            !app.save_prefilled_rule(),
            "Invalid port must fail validation and keep editor open"
        );
        assert!(app.edit_mode);
        assert!(app.edit_error.is_some());

        // Enter valid port range and save
        app.edit_ports = "443,8080-8090".into();
        assert!(app.save_prefilled_rule());
        assert!(!app.edit_mode);
        let saved = app
            .rule_for_app(r"C:\App\curl.exe")
            .expect("rule must be saved");
        assert_eq!(saved.action, RuleAction::Block);
        assert_eq!(saved.ports, "443,8080-8090");
    }

    #[test]
    fn test_quick_rule_reset_int_only_unseen_knocking_pause_and_lockdown() {
        let mut app = App::new_with_privilege(true);
        let path = r"C:\App\test.exe";
        app.allow_selected_internet_only(path);
        assert_eq!(
            app.rule_for_app(path).map(|r| r.zone_scope),
            Some(AllowedZoneScope::InternetOnly)
        );

        // Reset rule via [x] / [Delete]
        app.reset_selected_rule(path);
        assert!(app.rule_for_app(path).is_none());

        // Switch to Allowed tab and record a knocking event -> unseen_knocking increments
        app.set_filter(ViewFilter::AllowedOnly, "Allowed");
        app.record_incoming_event(NetworkEvent {
            timestamp: 100,
            app_path: path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 99,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 443,
            protocol: "TCP".into(),
            is_blocked: true,
            zone: Zone::Internet,
        });
        assert_eq!(app.unseen_knocking_count(), 1);
        app.set_filter(ViewFilter::KnockingOnly, "Knocking");
        assert_eq!(
            app.unseen_knocking_count(),
            0,
            "Switching to Knocking tab must clear unseen badge"
        );

        // Stream pause & Lockdown
        app.toggle_stream_pause();
        assert!(app.stream_paused);
        app.toggle_lockdown();
        assert!(app.lockdown_active);
    }

    #[test]
    fn test_shared_service_disambiguation_and_direction_clamping() {
        let mut app = App::new_with_privilege(true);
        let path = r"C:\Windows\System32\svchost.exe";

        // Record event for shared service
        app.record_incoming_event(NetworkEvent {
            timestamp: 100,
            app_path: path.into(),
            service_name: Some("Dnscache".into()),
            direction: RuleDirection::Outbound,
            process_id: 1234,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            remote_port: 53,
            protocol: "UDP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });

        app.sync_selection();
        let visible = app.visible_apps();
        assert_eq!(visible.len(), 1);
        let item = &visible[0];
        assert_eq!(item.service_name.as_deref(), Some("Dnscache"));

        // Apply quick action [l] (LAN only)
        app.allow_selected_lan_only(path);

        // Verify rule is saved with service_name
        let entry_rule = app
            .rule_for_app_entry(item)
            .expect("per-service rule should be found");
        assert_eq!(entry_rule.service_name.as_deref(), Some("Dnscache"));
        assert_eq!(entry_rule.zone_scope, AllowedZoneScope::LanOnly);

        // Verify base rule_for_app (which looks up None service) does NOT match this per-service rule
        assert!(app.rule_for_app(path).is_none());

        // Verify reset_selected_rule removes the per-service rule
        app.reset_selected_rule(path);
        assert!(app.rule_for_app_entry(item).is_none());

        // Test toggle_direction selection clamping
        // Currently on Outbound with 1 item
        app.selected_index = 5; // force out of bounds
        app.toggle_direction(); // switches to Inbound (where visible_apps is empty)
        assert_eq!(app.selected_index, 0);

        // Add inbound item and test clamping when switching back
        app.record_incoming_event(NetworkEvent {
            timestamp: 101,
            app_path: r"C:\App\server.exe".into(),
            service_name: None,
            direction: RuleDirection::Inbound,
            process_id: 5678,
            parent_process_name: None,
            remote_ip: IpAddr::from_str("192.168.1.50").unwrap(),
            remote_port: 8080,
            protocol: "TCP".into(),
            is_blocked: false,
            zone: Zone::Lan,
        });
        // On Inbound, we have 1 item. Set selected_index = 10
        app.selected_index = 10;
        app.toggle_direction(); // switches to Outbound (which has 1 item: svchost)
        assert_eq!(app.selected_index, 0);
    }
}
