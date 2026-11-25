//! Керування правилами та політикою Windows Defender Firewall через COM (INetFwPolicy2 / INetFwRule).

use crate::core::rules::{
    make_app_key, normalize_registry_ra4, AllowedZoneScope, AppRule, NetProtocol, RuleAction,
    RuleDirection, RuleTargetKind,
};
use crate::core::zone::Zone;

pub const FIREWALL_RULE_GROUP: &str = "it's.fw";
pub const LEGACY_FIREWALL_RULE_GROUP: &str = "its.fw";
pub const WSL_VM_CREATOR_ID: &str = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRuleParams {
    pub name: String,
    pub description: String,
    pub grouping: String,
    pub app_path: String,
    pub service_name: Option<String>,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub remote_addresses: String,
    pub protocol: NetProtocol,
    pub local_ports: Option<String>,
    pub remote_ports: Option<String>,
    pub interface_name: Option<String>,
    pub display_name: Option<String>,
    pub rule_id: Option<String>,
}

impl FirewallRuleParams {
    /// Генерує параметри для правила у Windows Firewall із заданого правила додатку `AppRule`.
    pub fn from_app_rule(rule: &AppRule) -> Self {
        let kind = RuleTargetKind::from_app_path(&rule.app_path);
        let clean_display = rule
            .display_name
            .as_deref()
            .map(|s| {
                let t = s.trim();
                t.strip_prefix("[WSL] ")
                    .or_else(|| t.strip_prefix("[PORT] "))
                    .or_else(|| t.strip_prefix("[UWP] "))
                    .unwrap_or(t)
            })
            .filter(|s| !s.is_empty());

        let app_filename = rule
            .app_path
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("app.exe");

        let target = match &rule.service_name {
            Some(svc) if !svc.trim().is_empty() => format!("{} [{}]", app_filename, svc.trim()),
            _ => app_filename.to_string(),
        };

        let action_str = match rule.action {
            RuleAction::Allow => "Allow",
            RuleAction::Block => "Block",
        };

        let zone_str = match rule.zone_scope {
            AllowedZoneScope::LanOnly => "LAN",
            AllowedZoneScope::InternetOnly => "Internet",
            AllowedZoneScope::Both => "All",
        };

        let tag = match rule.direction {
            RuleDirection::Outbound => format!("{}:{}", action_str, zone_str),
            RuleDirection::Inbound => format!("In:{}:{}", action_str, zone_str),
        };

        let remote_addresses = if let Some(ref custom_ip) = rule.custom_remote_ip {
            let trimmed = custom_ip.trim();
            if !trimmed.is_empty() && trimmed != "*" && !trimmed.eq_ignore_ascii_case("any") {
                trimmed.to_string()
            } else {
                Zone::windows_firewall_all_subnets().to_string()
            }
        } else {
            match rule.zone_scope {
                AllowedZoneScope::LanOnly => Zone::windows_firewall_lan_subnets().to_string(),
                AllowedZoneScope::InternetOnly | AllowedZoneScope::Both => {
                    Zone::windows_firewall_all_subnets().to_string()
                }
            }
        };

        let (local_ports, remote_ports) = if rule.protocol == NetProtocol::Any
            || rule.ports.trim().is_empty()
            || rule.ports.trim() == "*"
            || rule.ports.trim().eq_ignore_ascii_case("any")
        {
            (None, None)
        } else {
            match rule.direction {
                RuleDirection::Inbound => (Some(rule.ports.trim().to_string()), None),
                RuleDirection::Outbound => (None, Some(rule.ports.trim().to_string())),
            }
        };

        let mut name = match kind {
            RuleTargetKind::HyperV | RuleTargetKind::PortRule => {
                let fallback_slug = rule
                    .app_path
                    .split_once("://")
                    .map(|(_, s)| s)
                    .unwrap_or(&rule.app_path);
                clean_display.unwrap_or(fallback_slug).to_string()
            }
            RuleTargetKind::Uwp => clean_display.unwrap_or(&rule.app_path).to_string(),
            RuleTargetKind::App => format!("{}: {} [{}]", LEGACY_FIREWALL_RULE_GROUP, target, tag),
        };
        if rule.is_temporary() && !name.contains("[TTL]") {
            name.push_str(" [TTL]");
        }

        Self {
            name,
            description: format!("Created by it's.fw for {}", rule.app_path),
            grouping: FIREWALL_RULE_GROUP.to_string(),
            app_path: rule.app_path.clone(),
            service_name: rule.service_name.clone(),
            direction: rule.direction,
            action: rule.action,
            remote_addresses,
            protocol: rule.protocol,
            local_ports,
            remote_ports,
            interface_name: rule.interface_name.clone(),
            display_name: rule.display_name.clone(),
            rule_id: rule.rule_id.clone(),
        }
    }
}

/// Формує аргументи для `netsh advfirewall firewall add rule` без невалідного параметра `group=`.
pub fn build_netsh_add_rule_args(params: &FirewallRuleParams) -> Vec<String> {
    let action = match params.action {
        RuleAction::Allow => "allow",
        RuleAction::Block => "block",
    };

    let protocol = match params.protocol {
        NetProtocol::Any => "any",
        NetProtocol::Tcp => "TCP",
        NetProtocol::Udp => "UDP",
    };

    let dir_arg = match params.direction {
        RuleDirection::Outbound => "dir=out",
        RuleDirection::Inbound => "dir=in",
    };

    let mut args = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={}", params.name),
        format!("description={}", params.description),
        dir_arg.to_string(),
        "enable=yes".to_string(),
        "profile=any".to_string(),
        format!("action={}", action),
        format!("program={}", params.app_path),
        format!("protocol={}", protocol),
        format!("remoteip={}", params.remote_addresses),
    ];

    if let Some(ref svc) = params.service_name {
        if !svc.is_empty() {
            args.push(format!("service={}", svc));
        }
    }

    if protocol != "any" {
        if let Some(ref lp) = params.local_ports {
            args.push(format!("localport={}", lp));
        }
        if let Some(ref rports) = params.remote_ports {
            args.push(format!("remoteport={}", rports));
        }
    }

    args
}

/// Парсить вивід `netsh advfirewall show allprofiles` та визначає, чи увімкнено блокування вихідного трафіку за замовчуванням (`BlockOutbound`).
pub fn parse_netsh_profiles_outbound_blocked(text: &str) -> bool {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Firewall Policy") {
            let lower = trimmed.to_lowercase();
            if lower.contains("blockoutbound") {
                return true;
            }
        }
    }
    false
}

/// Парсить вивід `netsh advfirewall show allprofiles` та визначає, чи увімкнено блокування вхідного трафіку за замовчуванням (`BlockInbound`).
pub fn parse_netsh_profiles_inbound_blocked(text: &str) -> bool {
    let mut found_policy_line = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Firewall Policy") {
            found_policy_line = true;
            let lower = trimmed.to_lowercase();
            if lower.contains("blockinbound") {
                return true;
            }
        }
    }
    !found_policy_line
}

/// Парсить вивід `netsh advfirewall firewall show rule name=all dir=out verbose`
/// та реконструює актуальні правила для додатків (Єдине Джерело Правди з Windows Firewall).
/// Парсить вивід `netsh advfirewall firewall show rule` для вказаного напрямку (`RuleDirection`).
pub fn parse_netsh_rules(
    text: &str,
    direction: RuleDirection,
) -> std::collections::HashMap<String, AppRule> {
    let mut rules: std::collections::HashMap<String, AppRule> = std::collections::HashMap::new();

    let mut current_name = String::new();
    let mut current_program = String::new();
    let mut current_action: Option<RuleAction> = None;
    let mut current_grouping = String::new();
    let mut current_remote_ip = String::new();
    let mut current_protocol = NetProtocol::Any;
    let mut current_port = String::from("*");
    let mut is_enabled = false;

    let mut flush_rule = |name: &str,
                          prog: &str,
                          action: Option<RuleAction>,
                          grouping: &str,
                          remote_ip: &str,
                          protocol: NetProtocol,
                          port_val: &str,
                          enabled: bool| {
        if !enabled || prog.is_empty() || prog.eq_ignore_ascii_case("Any") {
            return;
        }
        // Пропускаємо допоміжні правила ізоляції зон (створені разом із основним правилом Allow:LAN / Allow:Internet)
        if name.ends_with(": Block LAN") || name.ends_with(": Block Internet") {
            return;
        }
        let Some(act) = action else { return };
        let is_its_fw = grouping.eq_ignore_ascii_case(FIREWALL_RULE_GROUP)
            || grouping.eq_ignore_ascii_case(LEGACY_FIREWALL_RULE_GROUP)
            || name.starts_with(FIREWALL_RULE_GROUP)
            || name.starts_with(LEGACY_FIREWALL_RULE_GROUP);

        if act == RuleAction::Block || is_its_fw {
            let zone_scope = if name.contains("[Allow:LAN]")
                || name.contains("[In:Allow:LAN]")
                || remote_ip.contains("LocalSubnet")
                || remote_ip.contains("192.168.")
            {
                AllowedZoneScope::LanOnly
            } else if name.contains("[Allow:Internet]") || name.contains("[In:Allow:Internet]") {
                AllowedZoneScope::InternetOnly
            } else {
                AllowedZoneScope::Both
            };

            let key = make_app_key(prog, None, direction);
            if let Some(existing) = rules.get(&key) {
                if existing.action == RuleAction::Block && act == RuleAction::Allow {
                    return;
                }
            }

            rules.insert(
                key,
                AppRule {
                    app_path: prog.to_string(),
                    service_name: None,
                    direction,
                    action: act,
                    zone_scope,
                    custom_remote_ip: None,
                    protocol,
                    ports: if port_val.is_empty() || port_val.eq_ignore_ascii_case("Any") {
                        "*".into()
                    } else {
                        port_val.to_string()
                    },
                    interface_name: None,
                    created_at: 0,
                    duration: if name.contains("[TTL]") {
                        crate::core::rules::RuleDuration::UntilExit
                    } else {
                        crate::core::rules::RuleDuration::Permanent
                    },
                    expires_at: None,
                    display_name: None,
                    rule_id: None,
                    is_system_or_uwp: false,
                },
            );
        }
    };

    let port_header = match direction {
        RuleDirection::Outbound => "RemotePort:",
        RuleDirection::Inbound => "LocalPort:",
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Rule Name:") {
            flush_rule(
                &current_name,
                &current_program,
                current_action,
                &current_grouping,
                &current_remote_ip,
                current_protocol,
                &current_port,
                is_enabled,
            );
            current_name = trimmed.trim_start_matches("Rule Name:").trim().to_string();
            current_program.clear();
            current_action = None;
            current_grouping.clear();
            current_remote_ip.clear();
            current_protocol = NetProtocol::Any;
            current_port = String::from("*");
            is_enabled = false;
        } else if trimmed.starts_with("Enabled:") {
            let en = trimmed.trim_start_matches("Enabled:").trim();
            is_enabled = en.eq_ignore_ascii_case("Yes");
        } else if trimmed.starts_with("Grouping:") {
            current_grouping = trimmed.trim_start_matches("Grouping:").trim().to_string();
        } else if trimmed.starts_with("Program:") {
            current_program = trimmed.trim_start_matches("Program:").trim().to_string();
        } else if trimmed.starts_with("RemoteIP:") {
            current_remote_ip = trimmed.trim_start_matches("RemoteIP:").trim().to_string();
        } else if trimmed.starts_with("Protocol:") {
            let p = trimmed.trim_start_matches("Protocol:").trim();
            current_protocol = if p.eq_ignore_ascii_case("TCP") {
                NetProtocol::Tcp
            } else if p.eq_ignore_ascii_case("UDP") {
                NetProtocol::Udp
            } else {
                NetProtocol::Any
            };
        } else if trimmed.starts_with(port_header) {
            current_port = trimmed.trim_start_matches(port_header).trim().to_string();
        } else if trimmed.starts_with("Action:") {
            let act = trimmed.trim_start_matches("Action:").trim();
            if act.eq_ignore_ascii_case("Block") {
                current_action = Some(RuleAction::Block);
            } else if act.eq_ignore_ascii_case("Allow") {
                current_action = Some(RuleAction::Allow);
            }
        }
    }

    flush_rule(
        &current_name,
        &current_program,
        current_action,
        &current_grouping,
        &current_remote_ip,
        current_protocol,
        &current_port,
        is_enabled,
    );

    rules
}

/// Парсить вивід `netsh advfirewall firewall show rule name=all dir=out verbose`
/// та реконструює актуальні правила для додатків (Єдине Джерело Правди з Windows Firewall).
pub fn parse_netsh_outbound_rules(text: &str) -> std::collections::HashMap<String, AppRule> {
    parse_netsh_rules(text, RuleDirection::Outbound)
}

/// Результат виконання команди фаєрволу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Трейт для абстракції виклику утиліти керування фаєрволом (`netsh`).
/// Дозволяє ізолювати системні виклики та тестувати логіку правил детерміновано без реальної ОС.
pub trait FirewallCommandRunner: Send + Sync + 'static {
    fn execute(&self, args: &[&str]) -> anyhow::Result<CommandOutput>;
}

/// Стандартний виконавець команд у системі (викликає реальний `netsh`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl FirewallCommandRunner for SystemCommandRunner {
    fn execute(&self, args: &[&str]) -> anyhow::Result<CommandOutput> {
        if cfg!(test) {
            return Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        let output = std::process::Command::new("netsh").args(args).output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Парсить список заблокованих вихідних додатків із тексту виводу `netsh`.
pub fn parse_blocked_outbound_apps(text: &str) -> std::collections::HashSet<String> {
    let mut blocked = std::collections::HashSet::new();
    let mut current_program = String::new();
    let mut is_block_action = false;
    let mut is_enabled = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Program:") {
            let prog = trimmed.trim_start_matches("Program:").trim();
            if !prog.is_empty() && prog != "Any" {
                current_program = prog.to_string();
            }
        } else if trimmed.starts_with("Action:") {
            let act = trimmed.trim_start_matches("Action:").trim();
            if act.eq_ignore_ascii_case("Block") {
                is_block_action = true;
            }
        } else if trimmed.starts_with("Enabled:") {
            let en = trimmed.trim_start_matches("Enabled:").trim();
            if en.eq_ignore_ascii_case("Yes") {
                is_enabled = true;
            }
        } else if trimmed.starts_with("Rule Name:") {
            if is_block_action && is_enabled && !current_program.is_empty() {
                let filename = current_program
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(&current_program)
                    .to_string();
                if !filename.is_empty() {
                    blocked.insert(filename);
                }
                blocked.insert(current_program.clone());
            }
            current_program.clear();
            is_block_action = false;
            is_enabled = false;
        }
    }

    if is_block_action && is_enabled && !current_program.is_empty() {
        let filename = current_program
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&current_program)
            .to_string();
        if !filename.is_empty() {
            blocked.insert(filename);
        }
        blocked.insert(current_program);
    }

    blocked
}

/// Парсить активні правила групи `it's.fw` (або `its.fw`) із тексту виводу `netsh`.
pub fn parse_active_its_fw_rules(text: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut current_name = String::new();
    let mut current_program = String::new();
    let mut is_its_fw_group = false;
    let mut is_enabled = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Rule Name:") {
            if (is_its_fw_group
                || current_name.starts_with(FIREWALL_RULE_GROUP)
                || current_name.starts_with(LEGACY_FIREWALL_RULE_GROUP))
                && is_enabled
                && !current_program.is_empty()
            {
                map.insert(current_program.to_lowercase(), current_name.clone());
            }
            current_name = trimmed.trim_start_matches("Rule Name:").trim().to_string();
            current_program.clear();
            is_its_fw_group = false;
            is_enabled = false;
        } else if trimmed.starts_with("Grouping:") {
            let grp = trimmed.trim_start_matches("Grouping:").trim();
            if grp.eq_ignore_ascii_case(FIREWALL_RULE_GROUP)
                || grp.eq_ignore_ascii_case(LEGACY_FIREWALL_RULE_GROUP)
            {
                is_its_fw_group = true;
            }
        } else if trimmed.starts_with("Program:") {
            let prog = trimmed.trim_start_matches("Program:").trim();
            if !prog.is_empty() && prog != "Any" {
                current_program = prog.to_string();
            }
        } else if trimmed.starts_with("Enabled:") {
            let en = trimmed.trim_start_matches("Enabled:").trim();
            if en.eq_ignore_ascii_case("Yes") {
                is_enabled = true;
            }
        }
    }

    if (is_its_fw_group
        || current_name.starts_with(FIREWALL_RULE_GROUP)
        || current_name.starts_with(LEGACY_FIREWALL_RULE_GROUP))
        && is_enabled
        && !current_program.is_empty()
    {
        map.insert(current_program.to_lowercase(), current_name);
    }

    map
}

pub fn parse_registry_rule_entry(
    value_name: &str,
    raw_value: &str,
    is_hyperv_hive: bool,
) -> Option<AppRule> {
    let trimmed_val = raw_value.trim();
    if trimmed_val.is_empty() {
        return None;
    }

    let mut active = false;
    let mut action: Option<RuleAction> = None;
    let mut direction: Option<RuleDirection> = None;
    let mut protocol_raw: Option<String> = None;
    let mut lports: Vec<String> = Vec::new();
    let mut rports: Vec<String> = Vec::new();
    let mut remote_addrs: Vec<String> = Vec::new();
    let mut app = String::new();
    let mut svc = String::new();
    let mut pfn = String::new();
    let mut name = String::new();
    let mut embed_ctxt = String::new();

    for part in trimmed_val.split('|') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        if key.eq_ignore_ascii_case("Active") {
            active = val.eq_ignore_ascii_case("TRUE");
        } else if key.eq_ignore_ascii_case("Action") {
            if val.eq_ignore_ascii_case("Allow") {
                action = Some(RuleAction::Allow);
            } else if val.eq_ignore_ascii_case("Block") {
                action = Some(RuleAction::Block);
            }
        } else if key.eq_ignore_ascii_case("Dir") {
            if val.eq_ignore_ascii_case("In") {
                direction = Some(RuleDirection::Inbound);
            } else if val.eq_ignore_ascii_case("Out") {
                direction = Some(RuleDirection::Outbound);
            }
        } else if key.eq_ignore_ascii_case("Protocol") {
            protocol_raw = Some(val.to_string());
        } else if key.eq_ignore_ascii_case("LPort") {
            if !val.is_empty() {
                lports.push(val.to_string());
            }
        } else if key.eq_ignore_ascii_case("RPort") {
            if !val.is_empty() {
                rports.push(val.to_string());
            }
        } else if key.eq_ignore_ascii_case("RA4") || key.eq_ignore_ascii_case("RA6") {
            if !val.is_empty() {
                remote_addrs.push(val.to_string());
            }
        } else if key.eq_ignore_ascii_case("App") {
            app = val.to_string();
        } else if key.eq_ignore_ascii_case("Svc") {
            svc = val.to_string();
        } else if key.eq_ignore_ascii_case("PFN") {
            pfn = val.to_string();
        } else if key.eq_ignore_ascii_case("Name") {
            name = val.to_string();
        } else if key.eq_ignore_ascii_case("EmbedCtxt") {
            embed_ctxt = val.to_string();
        }
    }

    if !active {
        return None;
    }
    let action = action?;
    if name.ends_with(": Block LAN") || name.ends_with(": Block Internet") {
        return None;
    }

    let direction = match direction {
        Some(d) => d,
        None if is_hyperv_hive => RuleDirection::Inbound,
        None => return None,
    };

    let (app_path, display_name, is_system_or_uwp) = if is_hyperv_hive {
        let sys_uwp = name.starts_with('@')
            || value_name.starts_with("WslCore-")
            || value_name.starts_with("vm-monitoring-");
        let clean = if name.is_empty() || name.starts_with('@') {
            value_name
        } else {
            name.as_str()
        };
        (
            format!("wsl://{}", value_name),
            Some(format!("[WSL] {}", clean)),
            sys_uwp,
        )
    } else {
        if !app.is_empty() || !svc.is_empty() {
            return None;
        }
        if !pfn.is_empty() {
            let clean = if name.is_empty() || name.starts_with('@') {
                pfn.as_str()
            } else {
                name.as_str()
            };
            (
                format!("uwp://{}", pfn),
                Some(format!("[UWP] {}", clean)),
                true,
            )
        } else {
            let sys_uwp = name.starts_with('@')
                || embed_ctxt.starts_with('@')
                || value_name.starts_with("HNS Container Networking")
                || value_name.starts_with("CoreNet-")
                || value_name.starts_with("FPS-")
                || value_name.starts_with("NETDIS-");
            let clean = if name.is_empty() || name.starts_with('@') {
                value_name
            } else {
                name.as_str()
            };
            (
                format!("port://{}", value_name),
                Some(format!("[PORT] {}", clean)),
                sys_uwp,
            )
        }
    };

    let protocol = match protocol_raw.as_deref() {
        Some("6") => NetProtocol::Tcp,
        Some("17") => NetProtocol::Udp,
        Some("256") | None => NetProtocol::Any,
        Some(_) => {
            if is_hyperv_hive || !pfn.is_empty() {
                NetProtocol::Any
            } else if lports.is_empty() && rports.is_empty() {
                return None;
            } else {
                NetProtocol::Any
            }
        }
    };

    let ports_vec = match direction {
        RuleDirection::Inbound => lports,
        RuleDirection::Outbound => {
            if rports.is_empty() {
                lports
            } else {
                rports
            }
        }
    };
    let ports = if ports_vec.is_empty() {
        "*".to_string()
    } else {
        ports_vec.join(",")
    };

    let mut has_local_subnet = false;
    let mut custom_ips: Vec<String> = Vec::new();
    for ra in remote_addrs {
        if ra.eq_ignore_ascii_case("LocalSubnet")
            || ra.eq_ignore_ascii_case("LocalSubnet4")
            || ra.eq_ignore_ascii_case("LocalSubnet6")
        {
            has_local_subnet = true;
        } else if ra != "*" && !ra.eq_ignore_ascii_case("Any") {
            if let Some(norm) = normalize_registry_ra4(&ra) {
                if !custom_ips.contains(&norm) {
                    custom_ips.push(norm);
                }
            } else if !custom_ips.contains(&ra) {
                custom_ips.push(ra);
            }
        }
    }

    let is_standard_lan_cidr = |ip: &str| {
        matches!(
            ip.to_ascii_lowercase().as_str(),
            "10.0.0.0/8"
                | "172.16.0.0/12"
                | "192.168.0.0/16"
                | "169.254.0.0/16"
                | "100.64.0.0/10"
                | "fc00::/7"
                | "fe80::/10"
        )
    };
    let all_custom_are_lan =
        !custom_ips.is_empty() && custom_ips.iter().all(|s| is_standard_lan_cidr(s));

    let (zone_scope, custom_remote_ip) =
        if has_local_subnet && (custom_ips.is_empty() || all_custom_are_lan) {
            (AllowedZoneScope::LanOnly, None)
        } else if !custom_ips.is_empty() {
            (AllowedZoneScope::Both, Some(custom_ips.join(",")))
        } else {
            (AllowedZoneScope::Both, None)
        };

    Some(AppRule {
        app_path,
        service_name: None,
        direction,
        action,
        zone_scope,
        custom_remote_ip,
        protocol,
        ports,
        interface_name: None,
        created_at: 0,
        duration: if name.contains("[TTL]") {
            crate::core::rules::RuleDuration::UntilExit
        } else {
            crate::core::rules::RuleDuration::Permanent
        },
        expires_at: None,
        display_name,
        rule_id: Some(value_name.to_string()),
        is_system_or_uwp,
    })
}

pub fn sanitize_rule_slug(input: &str) -> String {
    let slug: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "itsfw-rule".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn escape_ps_single_quoted(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .replace('\'', "''")
}

pub fn build_hyperv_registry_rule_string(params: &FirewallRuleParams) -> (String, String) {
    let raw_slug = params
        .rule_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            params
                .app_path
                .split_once("://")
                .map(|(_, s)| s)
                .filter(|s| !s.is_empty() && !s.starts_with("knock/"))
        })
        .unwrap_or(&params.name);

    let rule_id = if raw_slug.contains(' ') || raw_slug.starts_with("knock/") {
        sanitize_rule_slug(raw_slug)
    } else {
        raw_slug.to_string()
    };

    let clean_name = params
        .display_name
        .as_deref()
        .map(|s| s.trim().strip_prefix("[WSL] ").unwrap_or(s.trim()))
        .filter(|s| !s.is_empty())
        .unwrap_or(&params.name);

    let mut parts = vec![
        "v2.33".to_string(),
        format!(
            "Action={}",
            match params.action {
                RuleAction::Allow => "Allow",
                RuleAction::Block => "Block",
            }
        ),
        "Active=TRUE".to_string(),
        format!(
            "Dir={}",
            match params.direction {
                RuleDirection::Inbound => "In",
                RuleDirection::Outbound => "Out",
            }
        ),
        format!("VMCreatorId={}", WSL_VM_CREATOR_ID),
    ];

    match params.protocol {
        NetProtocol::Tcp => parts.push("Protocol=6".to_string()),
        NetProtocol::Udp => parts.push("Protocol=17".to_string()),
        NetProtocol::Any => {}
    }

    let port_spec = match params.direction {
        RuleDirection::Inbound => params.local_ports.as_deref(),
        RuleDirection::Outbound => params.remote_ports.as_deref(),
    };
    if let Some(pspec) = port_spec {
        for p in pspec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if p != "*" && !p.eq_ignore_ascii_case("any") {
                match params.direction {
                    RuleDirection::Inbound => parts.push(format!("LPort={}", p)),
                    RuleDirection::Outbound => parts.push(format!("RPort={}", p)),
                }
            }
        }
    }

    let raddr = params.remote_addresses.trim();
    if !raddr.is_empty() && raddr != "*" && !raddr.eq_ignore_ascii_case("any") {
        let dotted = crate::core::rules::cidr_to_dotted_mask(raddr);
        for token in dotted.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if token.eq_ignore_ascii_case("LocalSubnet") {
                parts.push("RA4=LocalSubnet".to_string());
            } else if token.contains(':') {
                parts.push(format!("RA6={}", token));
            } else {
                parts.push(format!("RA4={}", token));
            }
        }
    }

    parts.push(format!("Name={}", clean_name));
    let mut reg_val = parts.join("|");
    reg_val.push('|');
    (rule_id, reg_val)
}

pub fn build_hyperv_powershell_upsert_cmd(rule_id: &str, params: &FirewallRuleParams) -> String {
    let escaped_id = escape_ps_single_quoted(rule_id);
    let clean_name = params
        .display_name
        .as_deref()
        .map(|s| s.trim().strip_prefix("[WSL] ").unwrap_or(s.trim()))
        .filter(|s| !s.is_empty())
        .unwrap_or(&params.name);
    let escaped_name = escape_ps_single_quoted(clean_name);

    let dir_str = match params.direction {
        RuleDirection::Inbound => "Inbound",
        RuleDirection::Outbound => "Outbound",
    };
    let act_str = match params.action {
        RuleAction::Allow => "Allow",
        RuleAction::Block => "Block",
    };

    let mut cmd = format!(
        "Remove-NetFirewallHyperVRule -Name '{}' -ErrorAction SilentlyContinue; New-NetFirewallHyperVRule -Name '{}' -DisplayName '{}' -Direction {} -VMCreatorId '{}' -Action {}",
        escaped_id, escaped_id, escaped_name, dir_str, WSL_VM_CREATOR_ID, act_str
    );

    match params.protocol {
        NetProtocol::Tcp => cmd.push_str(" -Protocol TCP"),
        NetProtocol::Udp => cmd.push_str(" -Protocol UDP"),
        NetProtocol::Any => {}
    }

    let port_spec = match params.direction {
        RuleDirection::Inbound => params.local_ports.as_deref(),
        RuleDirection::Outbound => params.remote_ports.as_deref(),
    };
    if let Some(pspec) = port_spec {
        let items: Vec<String> = pspec
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "*" && !s.eq_ignore_ascii_case("any"))
            .map(|s| format!("'{}'", escape_ps_single_quoted(s)))
            .collect();
        if !items.is_empty() {
            let flag = match params.direction {
                RuleDirection::Inbound => "-LocalPorts",
                RuleDirection::Outbound => "-RemotePorts",
            };
            cmd.push_str(&format!(" {} @({})", flag, items.join(",")));
        }
    }

    let raddr = params.remote_addresses.trim();
    if !raddr.is_empty() && raddr != "*" && !raddr.eq_ignore_ascii_case("any") {
        let items: Vec<String> = raddr
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("'{}'", escape_ps_single_quoted(s)))
            .collect();
        if !items.is_empty() {
            cmd.push_str(&format!(" -RemoteAddresses @({})", items.join(",")));
        }
    }

    cmd.push_str(" -ErrorAction Stop");
    cmd
}

#[cfg(windows)]
fn run_powershell_sync(ps_cmd: &str) -> anyhow::Result<()> {
    if cfg!(test) {
        return Ok(());
    }
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_cmd,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit code {:?}", output.status.code())
        };
        anyhow::bail!("Hyper-V Firewall PowerShell failed: {}", detail);
    }
    Ok(())
}

#[cfg(windows)]
fn for_each_registry_rule_raw<F: FnMut(&str, &str)>(subkey: windows::core::PCWSTR, mut f: F) {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let mut hkey = HKEY::default();
    let open_err =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, Some(0), KEY_READ, &mut hkey) };
    if open_err != ERROR_SUCCESS {
        return;
    }

    let mut index = 0u32;
    let mut name_buf = vec![0u16; 1024];
    let mut data_buf = vec![0u8; 8192];
    let mut retries = 0u8;

    loop {
        let mut name_len = name_buf.len() as u32;
        let mut val_type = 0u32;
        let mut data_len = data_buf.len() as u32;

        let res = unsafe {
            RegEnumValueW(
                hkey,
                index,
                Some(PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut val_type),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        };

        if res == ERROR_NO_MORE_ITEMS {
            break;
        }
        if res == ERROR_MORE_DATA && retries < 4 {
            retries += 1;
            data_buf.resize(data_buf.len().max(data_len as usize) + 4096, 0);
            if (name_len as usize) + 1 >= name_buf.len() {
                name_buf.resize(name_buf.len() * 2, 0);
            }
            continue;
        }
        retries = 0;
        index += 1;

        if res != ERROR_SUCCESS || val_type != REG_SZ.0 {
            continue;
        }

        let val_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let u16_count = (data_len as usize) / 2;
        let mut u16_slice = Vec::with_capacity(u16_count);
        for i in 0..u16_count {
            u16_slice.push(u16::from_le_bytes([data_buf[i * 2], data_buf[i * 2 + 1]]));
        }
        let raw_val = String::from_utf16_lossy(&u16_slice)
            .trim_end_matches('\0')
            .to_string();
        f(&val_name, &raw_val);
    }

    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

#[cfg(windows)]
fn read_registry_rules_hive(
    subkey: windows::core::PCWSTR,
    is_hyperv_hive: bool,
    target_dir: RuleDirection,
    map: &mut std::collections::HashMap<String, AppRule>,
) {
    for_each_registry_rule_raw(subkey, |val_name, raw_val| {
        if let Some(rule) = parse_registry_rule_entry(val_name, raw_val, is_hyperv_hive) {
            if rule.direction != target_dir {
                return;
            }
            let key = rule.composite_key();
            if let Some(existing) = map.get(&key) {
                if existing.action == RuleAction::Block && rule.action == RuleAction::Allow {
                    return;
                }
            }
            map.insert(key, rule);
        }
    });
}

#[cfg(windows)]
fn lookup_registry_rule_display_name(
    subkey: windows::core::PCWSTR,
    target_value_name: &str,
) -> Option<String> {
    let mut found = None;
    for_each_registry_rule_raw(subkey, |val_name, raw_val| {
        if val_name.eq_ignore_ascii_case(target_value_name) {
            for part in raw_val.split('|') {
                if let Some((k, v)) = part.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("Name") {
                        found = Some(v.trim().to_string());
                        break;
                    }
                }
            }
        }
    });
    found
}

#[cfg(windows)]
fn lookup_uwp_rule_names_by_pfn(pfn: &str, target_dir: RuleDirection) -> Vec<String> {
    let mut names = Vec::new();
    let dir_token = match target_dir {
        RuleDirection::Inbound => "In",
        RuleDirection::Outbound => "Out",
    };
    let subkey = windows::core::w!(
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    );
    for_each_registry_rule_raw(subkey, |_val_name, raw_val| {
        let mut pfn_match = false;
        let mut dir_match = false;
        let mut rule_name = String::new();
        for part in raw_val.split('|') {
            if let Some((k, v)) = part.split_once('=') {
                let kt = k.trim();
                let vt = v.trim();
                if kt.eq_ignore_ascii_case("PFN") && vt.eq_ignore_ascii_case(pfn) {
                    pfn_match = true;
                } else if kt.eq_ignore_ascii_case("Dir") && vt.eq_ignore_ascii_case(dir_token) {
                    dir_match = true;
                } else if kt.eq_ignore_ascii_case("Name") {
                    rule_name = vt.to_string();
                }
            }
        }
        if pfn_match && dir_match && !rule_name.is_empty() && !names.contains(&rule_name) {
            names.push(rule_name);
        }
    });
    names
}

#[cfg(windows)]
fn delete_hyperv_registry_rule(value_name: &str) -> anyhow::Result<()> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE,
    };
    let subkey = windows::core::w!(
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\HyperVRules"
    );
    let mut hkey = HKEY::default();
    let open_err =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, Some(0), KEY_WRITE, &mut hkey) };
    if open_err != ERROR_SUCCESS {
        anyhow::bail!("Failed to open HyperVRules registry key: {:?}", open_err);
    }
    let name_hstr = HSTRING::from(value_name);
    let del_err = unsafe { RegDeleteValueW(hkey, &name_hstr) };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if del_err != ERROR_SUCCESS {
        anyhow::bail!("Failed to delete HyperVRules value: {:?}", del_err);
    }
    Ok(())
}

static LOCKDOWN_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub trait FirewallBackend: Send + Sync {
    fn is_outbound_blocking(&self) -> bool;
    fn set_outbound_blocking(&self, block: bool) -> anyhow::Result<()>;
    fn is_inbound_blocking(&self) -> bool;
    fn set_inbound_blocking(&self, block: bool) -> anyhow::Result<()>;
    fn is_lockdown_active(&self) -> bool;
    fn set_lockdown(&self, active: bool) -> anyhow::Result<()>;
    fn load_rules(&self, direction: RuleDirection) -> std::collections::HashMap<String, AppRule>;
    fn load_active_its_fw_rules(&self) -> std::collections::HashMap<String, String>;
    fn apply_rule(&self, params: &FirewallRuleParams) -> anyhow::Result<()>;
    fn remove_app_rules(
        &self,
        app_path: &str,
        service_name: Option<&str>,
        direction: RuleDirection,
    ) -> anyhow::Result<usize>;
    fn remove_rule_by_name(&self, name: &str) -> anyhow::Result<()>;
    fn remove_all_group_rules(&self) -> anyhow::Result<()>;
    fn remove_temporary_rules(&self) -> anyhow::Result<usize>;
}

#[cfg(windows)]
pub struct ComFirewallBackend;

#[cfg(windows)]
impl ComFirewallBackend {
    pub fn new() -> anyhow::Result<Self> {
        if cfg!(test) {
            return Ok(Self);
        }
        unsafe {
            let _ = windows::Win32::System::Com::CoInitializeEx(
                None,
                windows::Win32::System::Com::COINIT_MULTITHREADED,
            );
        }
        Ok(Self)
    }

    fn policy(
        &self,
    ) -> anyhow::Result<windows::Win32::NetworkManagement::WindowsFirewall::INetFwPolicy2> {
        if cfg!(test) {
            anyhow::bail!("COM firewall access disabled in unit tests");
        }
        use windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2;
        use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
        unsafe {
            let policy = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
            Ok(policy)
        }
    }

    unsafe fn for_each_rule<
        F: FnMut(&windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule),
    >(
        rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
        mut f: F,
    ) {
        use windows::core::Interface;
        use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
        use windows::Win32::System::Ole::IEnumVARIANT;
        use windows::Win32::System::Variant::{
            VariantChangeType, VARIANT, VAR_CHANGE_FLAGS, VT_UNKNOWN,
        };

        if let Ok(unk) = rules._NewEnum() {
            if let Ok(enum_var) = unk.cast::<IEnumVARIANT>() {
                loop {
                    let mut var = [VARIANT::default()];
                    let mut fetched = 0u32;
                    let hr = enum_var.Next(&mut var, &mut fetched);
                    if hr.is_err() || fetched == 0 {
                        break;
                    }
                    let mut unk_var = VARIANT::default();
                    if VariantChangeType(&mut unk_var, &var[0], VAR_CHANGE_FLAGS(0), VT_UNKNOWN)
                        .is_ok()
                    {
                        if let Ok(item_unk) = windows::core::IUnknown::try_from(&unk_var) {
                            if let Ok(fw_rule) = item_unk.cast::<INetFwRule>() {
                                f(&fw_rule);
                            }
                        }
                    }
                }
            }
        }
    }

    fn add_single_rule(&self, params: &FirewallRuleParams) -> anyhow::Result<()> {
        use windows::core::BSTR;
        use windows::Win32::Foundation::VARIANT_TRUE;
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            INetFwRule, NetFwRule, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
            NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP,
            NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
        };
        use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

        let policy = self.policy()?;
        unsafe {
            let rules = policy.Rules()?;
            let fw_rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
            fw_rule.SetName(&BSTR::from(&params.name))?;
            fw_rule.SetDescription(&BSTR::from(&params.description))?;
            fw_rule.SetGrouping(&BSTR::from(&params.grouping))?;
            if RuleTargetKind::from_app_path(&params.app_path) == RuleTargetKind::App
                && !params.app_path.is_empty()
            {
                fw_rule.SetApplicationName(&BSTR::from(&params.app_path))?;
            }
            if let Some(ref svc) = params.service_name {
                if !svc.is_empty() {
                    fw_rule.SetServiceName(&BSTR::from(svc))?;
                }
            }
            fw_rule.SetDirection(match params.direction {
                RuleDirection::Outbound => NET_FW_RULE_DIR_OUT,
                RuleDirection::Inbound => NET_FW_RULE_DIR_IN,
            })?;
            fw_rule.SetAction(match params.action {
                RuleAction::Allow => NET_FW_ACTION_ALLOW,
                RuleAction::Block => NET_FW_ACTION_BLOCK,
            })?;
            let proto_num = match params.protocol {
                NetProtocol::Tcp => NET_FW_IP_PROTOCOL_TCP.0,
                NetProtocol::Udp => NET_FW_IP_PROTOCOL_UDP.0,
                NetProtocol::Any => NET_FW_IP_PROTOCOL_ANY.0,
            };
            fw_rule.SetProtocol(proto_num)?;
            if proto_num != NET_FW_IP_PROTOCOL_ANY.0 {
                if let Some(ref lp) = params.local_ports {
                    if !lp.is_empty() && lp != "*" && !lp.eq_ignore_ascii_case("any") {
                        fw_rule.SetLocalPorts(&BSTR::from(lp))?;
                    }
                }
                if let Some(ref rp) = params.remote_ports {
                    if !rp.is_empty() && rp != "*" && !rp.eq_ignore_ascii_case("any") {
                        fw_rule.SetRemotePorts(&BSTR::from(rp))?;
                    }
                }
            }
            if !params.remote_addresses.is_empty()
                && params.remote_addresses != "*"
                && !params.remote_addresses.eq_ignore_ascii_case("any")
            {
                fw_rule.SetRemoteAddresses(&BSTR::from(&params.remote_addresses))?;
            }
            fw_rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
            fw_rule.SetEnabled(VARIANT_TRUE)?;
            rules.Add(&fw_rule)?;
        }
        Ok(())
    }

    fn apply_uwp_rule(&self, params: &FirewallRuleParams) -> anyhow::Result<()> {
        use windows::core::{Interface, BSTR};
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            INetFwRule3, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_IN,
            NET_FW_RULE_DIR_OUT,
        };
        let pfn = params
            .app_path
            .split_once("://")
            .map(|(_, s)| s)
            .unwrap_or(&params.app_path);
        let target_names = lookup_uwp_rule_names_by_pfn(pfn, params.direction);
        let target_dir = match params.direction {
            RuleDirection::Outbound => NET_FW_RULE_DIR_OUT,
            RuleDirection::Inbound => NET_FW_RULE_DIR_IN,
        };
        let target_action = match params.action {
            RuleAction::Allow => NET_FW_ACTION_ALLOW,
            RuleAction::Block => NET_FW_ACTION_BLOCK,
        };
        let target_addr = if params.remote_addresses.trim().eq_ignore_ascii_case("any")
            || params.remote_addresses.trim().is_empty()
        {
            "*".to_string()
        } else {
            params.remote_addresses.clone()
        };

        let policy = self.policy()?;
        let mut updated = 0usize;
        unsafe {
            let rules = policy.Rules()?;
            Self::for_each_rule(&rules, |r| {
                if let Ok(dir) = r.Direction() {
                    if dir != target_dir {
                        return;
                    }
                }
                let prog = r
                    .ApplicationName()
                    .map(|b| b.to_string())
                    .unwrap_or_default();
                if !prog.is_empty() {
                    return;
                }
                let name = r.Name().map(|b| b.to_string()).unwrap_or_default();
                let pkg_match = r
                    .cast::<INetFwRule3>()
                    .and_then(|r3| r3.LocalAppPackageId())
                    .map(|b| b.to_string().eq_ignore_ascii_case(pfn))
                    .unwrap_or(false);
                if (pkg_match || target_names.iter().any(|n| n.eq_ignore_ascii_case(&name)))
                    && r.SetAction(target_action).is_ok()
                {
                    let _ = r.SetRemoteAddresses(&BSTR::from(&target_addr));
                    updated += 1;
                }
            });
        }
        if updated == 0 {
            anyhow::bail!("No matching UWP firewall rule found for {}", pfn);
        }
        Ok(())
    }
}

#[cfg(windows)]
impl FirewallBackend for ComFirewallBackend {
    fn is_outbound_blocking(&self) -> bool {
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_PUBLIC,
        };
        if let Ok(policy) = self.policy() {
            unsafe {
                if let Ok(action) = policy.get_DefaultOutboundAction(NET_FW_PROFILE2_PUBLIC) {
                    return action == NET_FW_ACTION_BLOCK;
                }
            }
        }
        false
    }

    fn set_outbound_blocking(&self, block: bool) -> anyhow::Result<()> {
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
        };
        let policy = self.policy()?;
        let action = if block {
            NET_FW_ACTION_BLOCK
        } else {
            NET_FW_ACTION_ALLOW
        };
        unsafe {
            policy.put_DefaultOutboundAction(NET_FW_PROFILE2_DOMAIN, action)?;
            policy.put_DefaultOutboundAction(NET_FW_PROFILE2_PRIVATE, action)?;
            policy.put_DefaultOutboundAction(NET_FW_PROFILE2_PUBLIC, action)?;
        }
        Ok(())
    }

    fn is_inbound_blocking(&self) -> bool {
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_PUBLIC,
        };
        if let Ok(policy) = self.policy() {
            unsafe {
                if let Ok(action) = policy.get_DefaultInboundAction(NET_FW_PROFILE2_PUBLIC) {
                    return action == NET_FW_ACTION_BLOCK;
                }
            }
        }
        true
    }

    fn set_inbound_blocking(&self, block: bool) -> anyhow::Result<()> {
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
        };
        let policy = self.policy()?;
        let action = if block {
            NET_FW_ACTION_BLOCK
        } else {
            NET_FW_ACTION_ALLOW
        };
        unsafe {
            policy.put_DefaultInboundAction(NET_FW_PROFILE2_DOMAIN, action)?;
            policy.put_DefaultInboundAction(NET_FW_PROFILE2_PRIVATE, action)?;
            policy.put_DefaultInboundAction(NET_FW_PROFILE2_PUBLIC, action)?;
        }
        Ok(())
    }

    fn is_lockdown_active(&self) -> bool {
        use windows::Win32::Foundation::VARIANT_TRUE;
        use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE2_PUBLIC;
        if let Ok(policy) = self.policy() {
            unsafe {
                if let Ok(b) = policy.get_BlockAllInboundTraffic(NET_FW_PROFILE2_PUBLIC) {
                    return b == VARIANT_TRUE;
                }
            }
        }
        false
    }

    fn set_lockdown(&self, active: bool) -> anyhow::Result<()> {
        use windows::core::BSTR;
        use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
        };
        let policy = self.policy()?;
        unsafe {
            let val = if active { VARIANT_TRUE } else { VARIANT_FALSE };
            for profile in [
                NET_FW_PROFILE2_DOMAIN,
                NET_FW_PROFILE2_PRIVATE,
                NET_FW_PROFILE2_PUBLIC,
            ] {
                policy.put_BlockAllInboundTraffic(profile, val)?;
                if active {
                    policy.put_DefaultOutboundAction(profile, NET_FW_ACTION_BLOCK)?;
                }
            }
            let group_enabled = if active { VARIANT_FALSE } else { VARIANT_TRUE };
            let _ = policy.EnableRuleGroup(
                NET_FW_PROFILE2_ALL.0,
                &BSTR::from(FIREWALL_RULE_GROUP),
                group_enabled,
            );
        }
        Ok(())
    }

    fn load_rules(&self, direction: RuleDirection) -> std::collections::HashMap<String, AppRule> {
        use windows::Win32::Foundation::VARIANT_TRUE;
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_TCP,
            NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
        };
        let mut map: std::collections::HashMap<String, AppRule> = std::collections::HashMap::new();
        if let Ok(policy) = self.policy() {
            let target_dir = match direction {
                RuleDirection::Outbound => NET_FW_RULE_DIR_OUT,
                RuleDirection::Inbound => NET_FW_RULE_DIR_IN,
            };
            unsafe {
                if let Ok(rules) = policy.Rules() {
                    Self::for_each_rule(&rules, |r| {
                        if let Ok(enabled) = r.Enabled() {
                            if enabled != VARIANT_TRUE {
                                return;
                            }
                        }
                        if let Ok(dir) = r.Direction() {
                            if dir != target_dir {
                                return;
                            }
                        }
                        let name = r.Name().map(|b| b.to_string()).unwrap_or_default();
                        if name.ends_with(": Block LAN") || name.ends_with(": Block Internet") {
                            return;
                        }
                        let prog = r
                            .ApplicationName()
                            .map(|b| b.to_string())
                            .unwrap_or_default();
                        let svc = r.ServiceName().map(|b| b.to_string()).unwrap_or_default();
                        if prog.is_empty() && svc.is_empty() {
                            return;
                        }
                        let svc_opt = if svc.is_empty() {
                            None
                        } else {
                            Some(svc.clone())
                        };

                        let action = match r.Action() {
                            Ok(NET_FW_ACTION_ALLOW) => RuleAction::Allow,
                            Ok(NET_FW_ACTION_BLOCK) => RuleAction::Block,
                            _ => return,
                        };

                        let grouping = r.Grouping().map(|b| b.to_string()).unwrap_or_default();
                        let is_its_fw = grouping.eq_ignore_ascii_case(FIREWALL_RULE_GROUP)
                            || grouping.eq_ignore_ascii_case(LEGACY_FIREWALL_RULE_GROUP)
                            || name.starts_with(FIREWALL_RULE_GROUP)
                            || name.starts_with(LEGACY_FIREWALL_RULE_GROUP);

                        if action == RuleAction::Block || is_its_fw {
                            let remote_ip = r
                                .RemoteAddresses()
                                .map(|b| b.to_string())
                                .unwrap_or_default();
                            let zone_scope = if name.contains("[Allow:LAN]")
                                || name.contains("[In:Allow:LAN]")
                                || remote_ip.contains("LocalSubnet")
                                || remote_ip.contains("192.168.")
                            {
                                AllowedZoneScope::LanOnly
                            } else if name.contains("[Allow:Internet]")
                                || name.contains("[In:Allow:Internet]")
                            {
                                AllowedZoneScope::InternetOnly
                            } else {
                                AllowedZoneScope::Both
                            };

                            let protocol = match r.Protocol() {
                                Ok(p) if p == NET_FW_IP_PROTOCOL_TCP.0 => NetProtocol::Tcp,
                                Ok(p) if p == NET_FW_IP_PROTOCOL_UDP.0 => NetProtocol::Udp,
                                _ => NetProtocol::Any,
                            };

                            let ports_str = match direction {
                                RuleDirection::Inbound => {
                                    r.LocalPorts().map(|b| b.to_string()).unwrap_or_default()
                                }
                                RuleDirection::Outbound => {
                                    r.RemotePorts().map(|b| b.to_string()).unwrap_or_default()
                                }
                            };
                            let ports =
                                if ports_str.is_empty() || ports_str.eq_ignore_ascii_case("any") {
                                    "*".to_string()
                                } else {
                                    ports_str
                                };

                            let custom_remote_ip = if !remote_ip.is_empty()
                                && remote_ip != "*"
                                && !remote_ip.eq_ignore_ascii_case("any")
                                && !remote_ip.contains("LocalSubnet")
                            {
                                Some(remote_ip)
                            } else {
                                None
                            };

                            let key = make_app_key(&prog, svc_opt.as_deref(), direction);
                            if let Some(existing) = map.get(&key) {
                                if existing.action == RuleAction::Block
                                    && action == RuleAction::Allow
                                {
                                    return;
                                }
                            }

                            map.insert(
                                key,
                                AppRule {
                                    app_path: prog,
                                    service_name: svc_opt,
                                    direction,
                                    action,
                                    zone_scope,
                                    custom_remote_ip,
                                    protocol,
                                    ports,
                                    interface_name: None,
                                    created_at: 0,
                                    duration: if name.contains("[TTL]") {
                                        crate::core::rules::RuleDuration::UntilExit
                                    } else {
                                        crate::core::rules::RuleDuration::Permanent
                                    },
                                    expires_at: None,
                                    display_name: None,
                                    rule_id: None,
                                    is_system_or_uwp: false,
                                },
                            );
                        }
                    });
                }
            }
        }
        read_registry_rules_hive(
            windows::core::w!(
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\HyperVRules"
            ),
            true,
            direction,
            &mut map,
        );
        read_registry_rules_hive(
            windows::core::w!(
                "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
            ),
            false,
            direction,
            &mut map,
        );
        map
    }

    fn load_active_its_fw_rules(&self) -> std::collections::HashMap<String, String> {
        use windows::Win32::Foundation::VARIANT_TRUE;
        use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIR_IN;
        let mut map = std::collections::HashMap::new();
        if let Ok(policy) = self.policy() {
            unsafe {
                if let Ok(rules) = policy.Rules() {
                    Self::for_each_rule(&rules, |r| {
                        if let Ok(enabled) = r.Enabled() {
                            if enabled != VARIANT_TRUE {
                                return;
                            }
                        }
                        let grouping = r.Grouping().map(|b| b.to_string()).unwrap_or_default();
                        let name = r.Name().map(|b| b.to_string()).unwrap_or_default();
                        let is_its_fw = grouping.eq_ignore_ascii_case(FIREWALL_RULE_GROUP)
                            || grouping.eq_ignore_ascii_case(LEGACY_FIREWALL_RULE_GROUP)
                            || name.starts_with(FIREWALL_RULE_GROUP)
                            || name.starts_with(LEGACY_FIREWALL_RULE_GROUP);
                        if !is_its_fw {
                            return;
                        }
                        let prog = r
                            .ApplicationName()
                            .map(|b| b.to_string())
                            .unwrap_or_default();
                        let svc = r.ServiceName().map(|b| b.to_string()).unwrap_or_default();
                        if prog.is_empty() && svc.is_empty() {
                            return;
                        }
                        let dir = match r.Direction() {
                            Ok(d) if d == NET_FW_RULE_DIR_IN => RuleDirection::Inbound,
                            _ => RuleDirection::Outbound,
                        };
                        let svc_opt = if svc.is_empty() {
                            None
                        } else {
                            Some(svc.as_str())
                        };
                        let key = make_app_key(&prog, svc_opt, dir);
                        map.insert(key, name.clone());
                        if dir == RuleDirection::Outbound && svc.is_empty() && !prog.is_empty() {
                            map.insert(prog.to_lowercase(), name);
                        }
                    });
                }
            }
        }
        map
    }

    fn apply_rule(&self, params: &FirewallRuleParams) -> anyhow::Result<()> {
        match RuleTargetKind::from_app_path(&params.app_path) {
            RuleTargetKind::HyperV => {
                let (rule_id, _) = build_hyperv_registry_rule_string(params);
                if cfg!(test) {
                    return Ok(());
                }
                let ps_cmd = build_hyperv_powershell_upsert_cmd(&rule_id, params);
                if let Err(first_err) = run_powershell_sync(&ps_cmd) {
                    // Self-heal: if an orphaned stale registry entry existed outside mpssvc, remove it and retry once.
                    if delete_hyperv_registry_rule(&rule_id).is_ok() {
                        run_powershell_sync(&ps_cmd)?;
                    } else {
                        return Err(first_err);
                    }
                }
                return Ok(());
            }
            RuleTargetKind::Uwp => {
                if cfg!(test) {
                    return Ok(());
                }
                return self.apply_uwp_rule(params);
            }
            RuleTargetKind::PortRule | RuleTargetKind::App => {}
        }

        let _ = self.remove_app_rules(
            &params.app_path,
            params.service_name.as_deref(),
            params.direction,
        );
        if RuleTargetKind::from_app_path(&params.app_path) == RuleTargetKind::PortRule {
            let _ = self.remove_rule_by_name(&params.name);
        }

        if params.action == RuleAction::Allow
            && (params.name.contains("[Allow:Internet]")
                || params.name.contains("[In:Allow:Internet]"))
        {
            let block_lan_params = FirewallRuleParams {
                name: format!("{}: Block LAN", params.name),
                description: format!("Block LAN isolation for {}", params.app_path),
                grouping: params.grouping.clone(),
                app_path: params.app_path.clone(),
                service_name: params.service_name.clone(),
                direction: params.direction,
                action: RuleAction::Block,
                remote_addresses: Zone::windows_firewall_lan_subnets().to_string(),
                protocol: params.protocol,
                local_ports: params.local_ports.clone(),
                remote_ports: params.remote_ports.clone(),
                interface_name: params.interface_name.clone(),
                display_name: params.display_name.clone(),
                rule_id: params.rule_id.clone(),
            };
            self.add_single_rule(&block_lan_params)?;
        }

        if params.action == RuleAction::Allow
            && (params.name.contains("[Allow:LAN]") || params.name.contains("[In:Allow:LAN]"))
        {
            let block_inet_params = FirewallRuleParams {
                name: format!("{}: Block Internet", params.name),
                description: format!("Block Internet isolation for {}", params.app_path),
                grouping: params.grouping.clone(),
                app_path: params.app_path.clone(),
                service_name: params.service_name.clone(),
                direction: params.direction,
                action: RuleAction::Block,
                remote_addresses: Zone::windows_firewall_internet_ranges().to_string(),
                protocol: params.protocol,
                local_ports: params.local_ports.clone(),
                remote_ports: params.remote_ports.clone(),
                interface_name: params.interface_name.clone(),
                display_name: params.display_name.clone(),
                rule_id: params.rule_id.clone(),
            };
            self.add_single_rule(&block_inet_params)?;
        }

        self.add_single_rule(params)
    }

    fn remove_app_rules(
        &self,
        app_path: &str,
        service_name: Option<&str>,
        direction: RuleDirection,
    ) -> anyhow::Result<usize> {
        use windows::core::BSTR;
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_ALLOW, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
        };

        match RuleTargetKind::from_app_path(app_path) {
            RuleTargetKind::HyperV => {
                if cfg!(test) {
                    return Ok(0);
                }
                let slug = app_path
                    .split_once("://")
                    .map(|(_, s)| s)
                    .unwrap_or(app_path);
                if slug.starts_with("knock/") {
                    return Ok(0);
                }
                let escaped = escape_ps_single_quoted(slug);
                let ps_cmd = format!(
                    "Remove-NetFirewallHyperVRule -Name '{}' -ErrorAction Stop",
                    escaped
                );
                if run_powershell_sync(&ps_cmd).is_ok() {
                    return Ok(1);
                }
                // Fallback: clean up orphaned stale registry value if mpssvc didn't know about it
                let removed = delete_hyperv_registry_rule(slug).is_ok();
                return Ok(if removed { 1 } else { 0 });
            }
            RuleTargetKind::PortRule => {
                if cfg!(test) {
                    return Ok(0);
                }
                let key_id = app_path
                    .split_once("://")
                    .map(|(_, s)| s)
                    .unwrap_or(app_path);
                let target_dir = match direction {
                    RuleDirection::Outbound => NET_FW_RULE_DIR_OUT,
                    RuleDirection::Inbound => NET_FW_RULE_DIR_IN,
                };
                let reg_name = lookup_registry_rule_display_name(
                    windows::core::w!(
                        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
                    ),
                    key_id,
                );
                let mut candidate_names = vec![key_id.to_string()];
                if let Some(rn) = reg_name {
                    candidate_names.push(rn.clone());
                    candidate_names.push(format!("{}: Block LAN", rn));
                    candidate_names.push(format!("{}: Block Internet", rn));
                }
                let policy = self.policy()?;
                let to_remove = unsafe {
                    let rules = policy.Rules()?;
                    let mut names = Vec::new();
                    Self::for_each_rule(&rules, |r| {
                        if let Ok(dir) = r.Direction() {
                            if dir != target_dir {
                                return;
                            }
                        }
                        let prog = r
                            .ApplicationName()
                            .map(|b| b.to_string())
                            .unwrap_or_default();
                        if !prog.is_empty() {
                            return;
                        }
                        let name = r.Name().map(|b| b.to_string()).unwrap_or_default();
                        if candidate_names
                            .iter()
                            .any(|c| c.eq_ignore_ascii_case(&name))
                        {
                            names.push(name);
                        }
                    });
                    names
                };
                let count = to_remove.len();
                unsafe {
                    let rules = policy.Rules()?;
                    for n in to_remove {
                        let _ = rules.Remove(&BSTR::from(&n));
                    }
                }
                return Ok(count);
            }
            RuleTargetKind::Uwp => {
                if cfg!(test) {
                    return Ok(0);
                }
                let pfn = app_path
                    .split_once("://")
                    .map(|(_, s)| s)
                    .unwrap_or(app_path);
                let target_names = lookup_uwp_rule_names_by_pfn(pfn, direction);
                let target_dir = match direction {
                    RuleDirection::Outbound => NET_FW_RULE_DIR_OUT,
                    RuleDirection::Inbound => NET_FW_RULE_DIR_IN,
                };
                let policy = self.policy()?;
                let mut count = 0usize;
                unsafe {
                    let rules = policy.Rules()?;
                    Self::for_each_rule(&rules, |r| {
                        if let Ok(dir) = r.Direction() {
                            if dir != target_dir {
                                return;
                            }
                        }
                        let prog = r
                            .ApplicationName()
                            .map(|b| b.to_string())
                            .unwrap_or_default();
                        if !prog.is_empty() {
                            return;
                        }
                        let name = r.Name().map(|b| b.to_string()).unwrap_or_default();
                        if target_names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                            if r.SetAction(NET_FW_ACTION_ALLOW).is_ok() {
                                count += 1;
                            }
                            let _ = r.SetRemoteAddresses(&BSTR::from("*"));
                        }
                    });
                }
                return Ok(count);
            }
            RuleTargetKind::App => {}
        }

        let policy = self.policy()?;
        let target_dir = match direction {
            RuleDirection::Outbound => NET_FW_RULE_DIR_OUT,
            RuleDirection::Inbound => NET_FW_RULE_DIR_IN,
        };
        let names_to_remove = unsafe {
            let rules = policy.Rules()?;
            let mut names = Vec::new();
            Self::for_each_rule(&rules, |r| {
                if let Ok(dir) = r.Direction() {
                    if dir != target_dir {
                        return;
                    }
                }
                let prog = r
                    .ApplicationName()
                    .map(|b| b.to_string())
                    .unwrap_or_default();
                let svc = r.ServiceName().map(|b| b.to_string()).unwrap_or_default();
                let name = r.Name().map(|b| b.to_string()).unwrap_or_default();

                let prog_matches = if app_path.is_empty() {
                    true
                } else {
                    prog.eq_ignore_ascii_case(app_path)
                };

                let svc_matches = match service_name {
                    Some(expected_svc) => svc.eq_ignore_ascii_case(expected_svc),
                    None => svc.is_empty(),
                };

                if prog_matches && svc_matches {
                    names.push(name.clone());
                }
            });
            names
        };

        let count = names_to_remove.len();
        unsafe {
            let rules = policy.Rules()?;
            for name in names_to_remove {
                let _ = rules.Remove(&BSTR::from(&name));
            }
        }
        Ok(count)
    }

    fn remove_rule_by_name(&self, name: &str) -> anyhow::Result<()> {
        use windows::core::BSTR;
        let policy = self.policy()?;
        unsafe {
            let rules = policy.Rules()?;
            rules.Remove(&BSTR::from(name))?;
        }
        Ok(())
    }

    fn remove_all_group_rules(&self) -> anyhow::Result<()> {
        use windows::core::BSTR;
        let policy = self.policy()?;
        let names_to_remove = unsafe {
            let rules = policy.Rules()?;
            let mut names = Vec::new();
            Self::for_each_rule(&rules, |r| {
                let name = r.Name().map(|b| b.to_string()).unwrap_or_default();
                let grp = r.Grouping().map(|b| b.to_string()).unwrap_or_default();
                if grp.eq_ignore_ascii_case(FIREWALL_RULE_GROUP)
                    || grp.eq_ignore_ascii_case(LEGACY_FIREWALL_RULE_GROUP)
                    || name.starts_with(FIREWALL_RULE_GROUP)
                    || name.starts_with(LEGACY_FIREWALL_RULE_GROUP)
                {
                    names.push(name);
                }
            });
            names
        };

        unsafe {
            let rules = policy.Rules()?;
            for name in names_to_remove {
                let _ = rules.Remove(&BSTR::from(&name));
            }
        }
        Ok(())
    }

    fn remove_temporary_rules(&self) -> anyhow::Result<usize> {
        use windows::core::BSTR;
        let policy = self.policy()?;
        let names_to_remove = unsafe {
            let rules = policy.Rules()?;
            let mut names = Vec::new();
            Self::for_each_rule(&rules, |r| {
                let name = r.Name().map(|b| b.to_string()).unwrap_or_default();
                let grp = r.Grouping().map(|b| b.to_string()).unwrap_or_default();
                let is_its_fw = grp.eq_ignore_ascii_case(FIREWALL_RULE_GROUP)
                    || grp.eq_ignore_ascii_case(LEGACY_FIREWALL_RULE_GROUP)
                    || name.starts_with(FIREWALL_RULE_GROUP)
                    || name.starts_with(LEGACY_FIREWALL_RULE_GROUP);
                if is_its_fw && name.contains("[TTL]") {
                    names.push(name);
                }
            });
            names
        };

        let count = names_to_remove.len();
        unsafe {
            let rules = policy.Rules()?;
            for name in names_to_remove {
                let _ = rules.Remove(&BSTR::from(&name));
            }
        }
        Ok(count)
    }
}

#[cfg(not(windows))]
pub struct ComFirewallBackend;

#[cfg(not(windows))]
impl ComFirewallBackend {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }
}

#[cfg(not(windows))]
impl FirewallBackend for ComFirewallBackend {
    fn is_outbound_blocking(&self) -> bool {
        false
    }
    fn set_outbound_blocking(&self, _block: bool) -> anyhow::Result<()> {
        Ok(())
    }
    fn is_inbound_blocking(&self) -> bool {
        true
    }
    fn set_inbound_blocking(&self, _block: bool) -> anyhow::Result<()> {
        Ok(())
    }
    fn is_lockdown_active(&self) -> bool {
        false
    }
    fn set_lockdown(&self, _active: bool) -> anyhow::Result<()> {
        Ok(())
    }
    fn load_rules(&self, _direction: RuleDirection) -> std::collections::HashMap<String, AppRule> {
        std::collections::HashMap::new()
    }
    fn load_active_its_fw_rules(&self) -> std::collections::HashMap<String, String> {
        std::collections::HashMap::new()
    }
    fn apply_rule(&self, _params: &FirewallRuleParams) -> anyhow::Result<()> {
        Ok(())
    }
    fn remove_app_rules(
        &self,
        _app_path: &str,
        _service_name: Option<&str>,
        _direction: RuleDirection,
    ) -> anyhow::Result<usize> {
        Ok(0)
    }
    fn remove_rule_by_name(&self, _name: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn remove_all_group_rules(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn remove_temporary_rules(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
}

pub struct WindowsFirewallManager<R: FirewallCommandRunner = SystemCommandRunner> {
    runner: R,
}

impl Default for WindowsFirewallManager<SystemCommandRunner> {
    fn default() -> Self {
        Self {
            runner: SystemCommandRunner,
        }
    }
}

impl WindowsFirewallManager<SystemCommandRunner> {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self::default())
    }

    pub fn is_outbound_policy_blocking() -> bool {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.is_outbound_blocking();
                }
            }
        }
        Self::is_outbound_policy_blocking_with(&SystemCommandRunner)
    }

    pub fn is_inbound_policy_blocking() -> bool {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.is_inbound_blocking();
                }
            }
        }
        Self::is_inbound_policy_blocking_with(&SystemCommandRunner)
    }

    pub fn set_inbound_policy(block: bool) -> anyhow::Result<()> {
        let _ = block;
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.set_inbound_blocking(block);
                }
            }
        }
        Ok(())
    }

    pub fn is_lockdown_active() -> bool {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.is_lockdown_active();
                }
            }
        }
        LOCKDOWN_ACTIVE.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_lockdown(active: bool) -> anyhow::Result<()> {
        LOCKDOWN_ACTIVE.store(active, std::sync::atomic::Ordering::SeqCst);
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.set_lockdown(active);
                }
            }
        }
        Ok(())
    }

    pub fn load_rules_from_os(
        direction: RuleDirection,
    ) -> std::collections::HashMap<String, AppRule> {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.load_rules(direction);
                }
            }
        }
        Self::load_rules_from_os_with(&SystemCommandRunner, direction)
    }

    pub fn load_outbound_rules_from_os() -> std::collections::HashMap<String, AppRule> {
        Self::load_rules_from_os(RuleDirection::Outbound)
    }

    pub fn load_all_rules_from_os() -> std::collections::HashMap<String, AppRule> {
        let mut all = Self::load_rules_from_os(RuleDirection::Outbound);
        all.extend(Self::load_rules_from_os(RuleDirection::Inbound));
        all
    }

    pub fn remove_all_temporary_rules() -> usize {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.remove_temporary_rules().unwrap_or(0);
                }
            }
        }
        0
    }

    pub fn load_blocked_outbound_apps() -> std::collections::HashSet<String> {
        Self::load_blocked_outbound_apps_with(&SystemCommandRunner)
    }

    pub fn load_active_its_fw_rules() -> std::collections::HashMap<String, String> {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.load_active_its_fw_rules();
                }
            }
        }
        Self::load_active_its_fw_rules_with(&SystemCommandRunner)
    }

    pub fn set_outbound_policy(block: bool) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.set_outbound_blocking(block);
                }
            }
        }
        Self::set_outbound_policy_with(&SystemCommandRunner, block)
    }

    pub fn remove_app_rules(
        app_path: &str,
        service_name: Option<&str>,
        direction: RuleDirection,
    ) -> anyhow::Result<usize> {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.remove_app_rules(app_path, service_name, direction);
                }
            }
        }
        Self::remove_app_rules_with(&SystemCommandRunner, app_path, service_name, direction)
    }
}

impl<R: FirewallCommandRunner> WindowsFirewallManager<R> {
    pub fn with_runner(runner: R) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    pub fn is_outbound_policy_blocking_with(runner: &R) -> bool {
        if let Ok(out) = runner.execute(&["advfirewall", "show", "allprofiles"]) {
            parse_netsh_profiles_outbound_blocked(&out.stdout)
        } else {
            false
        }
    }

    pub fn is_inbound_policy_blocking_with(runner: &R) -> bool {
        if let Ok(out) = runner.execute(&["advfirewall", "show", "allprofiles"]) {
            parse_netsh_profiles_inbound_blocked(&out.stdout)
        } else {
            true
        }
    }

    pub fn load_rules_from_os_with(
        runner: &R,
        direction: RuleDirection,
    ) -> std::collections::HashMap<String, AppRule> {
        let dir_str = match direction {
            RuleDirection::Outbound => "dir=out",
            RuleDirection::Inbound => "dir=in",
        };
        if let Ok(out) = runner.execute(&[
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            dir_str,
            "verbose",
        ]) {
            parse_netsh_rules(&out.stdout, direction)
        } else {
            std::collections::HashMap::new()
        }
    }

    pub fn load_outbound_rules_from_os_with(
        runner: &R,
    ) -> std::collections::HashMap<String, AppRule> {
        Self::load_rules_from_os_with(runner, RuleDirection::Outbound)
    }

    pub fn load_blocked_outbound_apps_with(runner: &R) -> std::collections::HashSet<String> {
        if let Ok(out) = runner.execute(&[
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            "dir=out",
            "verbose",
        ]) {
            parse_blocked_outbound_apps(&out.stdout)
        } else {
            std::collections::HashSet::new()
        }
    }

    pub fn load_active_its_fw_rules_with(runner: &R) -> std::collections::HashMap<String, String> {
        if let Ok(out) = runner.execute(&[
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            "dir=out",
            "verbose",
        ]) {
            parse_active_its_fw_rules(&out.stdout)
        } else {
            std::collections::HashMap::new()
        }
    }

    pub fn set_outbound_policy_with(runner: &R, block: bool) -> anyhow::Result<()> {
        let val = if block {
            "blockinbound,blockoutbound"
        } else {
            "blockinbound,allowoutbound"
        };
        let output =
            runner.execute(&["advfirewall", "set", "allprofiles", "firewallpolicy", val])?;
        if !output.success {
            let combined = format!("{} {}", output.stdout.trim(), output.stderr.trim())
                .trim()
                .to_string();
            anyhow::bail!("Failed to set outbound policy: {}", combined);
        }
        Ok(())
    }

    pub fn remove_app_rules_for(
        &self,
        app_path: &str,
        service_name: Option<&str>,
        direction: RuleDirection,
    ) -> anyhow::Result<usize> {
        #[cfg(windows)]
        {
            if !cfg!(test)
                && std::any::TypeId::of::<R>() == std::any::TypeId::of::<SystemCommandRunner>()
            {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.remove_app_rules(app_path, service_name, direction);
                }
            }
        }
        Self::remove_app_rules_with(&self.runner, app_path, service_name, direction)
    }

    pub fn remove_app_rules_with(
        runner: &R,
        app_path: &str,
        service_name: Option<&str>,
        direction: RuleDirection,
    ) -> anyhow::Result<usize> {
        let dir_arg = match direction {
            RuleDirection::Outbound => "dir=out",
            RuleDirection::Inbound => "dir=in",
        };
        let mut args = vec![
            "advfirewall".to_string(),
            "firewall".to_string(),
            "delete".to_string(),
            "rule".to_string(),
            "name=all".to_string(),
            dir_arg.to_string(),
        ];
        if !app_path.is_empty() {
            args.push(format!("program={}", app_path));
        }
        if let Some(svc) = service_name {
            if !svc.is_empty() {
                args.push(format!("service={}", svc));
            }
        }
        let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = runner.execute(&str_args)?;
        if output.success {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    /// Створює або оновлює правило у Windows Firewall через виконавець команд netsh або COM.
    pub fn apply_rule(&self, params: &FirewallRuleParams) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            if !cfg!(test)
                && std::any::TypeId::of::<R>() == std::any::TypeId::of::<SystemCommandRunner>()
            {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.apply_rule(params);
                }
            }
        }

        // Очищаємо попередні правила для цієї програми, щоб уникнути конфлікту блокувань (Block має вищий пріоритет за Allow)
        let _ = self.runner.execute(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=all",
            &format!("program={}", params.app_path),
        ]);

        let dir_arg = match params.direction {
            RuleDirection::Inbound => "dir=in",
            RuleDirection::Outbound => "dir=out",
        };

        // Якщо це правило Allow Internet Only: спочатку блокуємо доступ до LAN, потім дозволяємо any
        if params.action == RuleAction::Allow
            && (params.name.contains("[Allow:Internet]")
                || params.name.contains("[In:Allow:Internet]"))
        {
            let block_lan_name = format!("{}: Block LAN", params.name);
            let _ = self.runner.execute(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", block_lan_name),
                dir_arg,
                "enable=yes",
                "profile=any",
                "action=block",
                &format!("program={}", params.app_path),
                &format!("remoteip={}", Zone::windows_firewall_lan_subnets()),
            ]);
        }

        // Якщо це правило Allow LAN Only: додатково блокуємо публічні IP Інтернету
        if params.action == RuleAction::Allow
            && (params.name.contains("[Allow:LAN]") || params.name.contains("[In:Allow:LAN]"))
        {
            let block_inet_name = format!("{}: Block Internet", params.name);
            let _ = self.runner.execute(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", block_inet_name),
                dir_arg,
                "enable=yes",
                "profile=any",
                "action=block",
                &format!("program={}", params.app_path),
                &format!("remoteip={}", Zone::windows_firewall_internet_ranges()),
            ]);
        }

        let args = build_netsh_add_rule_args(params);
        let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = self.runner.execute(&str_args)?;
        if !output.success {
            let combined = format!("{} {}", output.stdout.trim(), output.stderr.trim())
                .trim()
                .to_string();
            anyhow::bail!("Failed to add firewall rule: {}", combined);
        }

        Ok(())
    }

    /// Видаляє правило за назвою.
    pub fn remove_rule_by_name(&self, name: &str) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            if !cfg!(test)
                && std::any::TypeId::of::<R>() == std::any::TypeId::of::<SystemCommandRunner>()
            {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.remove_rule_by_name(name);
                }
            }
        }

        let output = self.runner.execute(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", name),
        ])?;
        if !output.success {
            anyhow::bail!("Failed to delete firewall rule: {}", output.stderr.trim());
        }
        Ok(())
    }

    /// Видаляє всі правила групи `its.fw`.
    pub fn remove_all_rules(&self) -> anyhow::Result<()> {
        let _ = self.runner.execute(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=all",
            &format!("group={}", LEGACY_FIREWALL_RULE_GROUP),
        ]);
        Ok(())
    }

    /// Видаляє всі правила групи через COM або netsh.
    pub fn remove_all_group_rules(&self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            if !cfg!(test)
                && std::any::TypeId::of::<R>() == std::any::TypeId::of::<SystemCommandRunner>()
            {
                if let Ok(backend) = ComFirewallBackend::new() {
                    return backend.remove_all_group_rules();
                }
            }
        }
        self.remove_all_rules()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbound_and_service_firewall_rule_params() {
        let inbound_rule = AppRule {
            app_path: r"C:\App\node.exe".into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Inbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::LanOnly,
            custom_remote_ip: None,
            protocol: NetProtocol::Tcp,
            ports: "3000".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&inbound_rule);
        assert_eq!(params.name, "its.fw: node.exe [In:Allow:LAN]");
        assert_eq!(params.local_ports, Some("3000".into()));
        assert_eq!(params.remote_ports, None);

        let svc_rule = AppRule {
            app_path: r"C:\Windows\System32\svchost.exe".into(),
            service_name: Some("DiagTrack".into()),
            direction: crate::core::rules::RuleDirection::Outbound,
            action: RuleAction::Block,
            zone_scope: AllowedZoneScope::Both,
            custom_remote_ip: Some("20.190.159.0/24".into()),
            protocol: NetProtocol::Any,
            ports: "443".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let svc_params = FirewallRuleParams::from_app_rule(&svc_rule);
        assert_eq!(
            svc_params.name,
            "its.fw: svchost.exe [DiagTrack] [Block:All]"
        );
        assert_eq!(svc_params.service_name, Some("DiagTrack".into()));
        assert_eq!(svc_params.remote_addresses, "20.190.159.0/24");
        assert_eq!(
            svc_params.remote_ports, None,
            "NetProtocol::Any must clear ports"
        );
    }

    #[test]
    fn test_firewall_rule_params_generation() {
        let rule = AppRule {
            app_path: r"C:\Program Files\TestApp\test.exe".into(),
            service_name: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::LanOnly,
            custom_remote_ip: None,
            protocol: NetProtocol::Tcp,
            ports: "80,443".into(),
            interface_name: Some("Wi-Fi".into()),
            created_at: 1730000000,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };

        let params = FirewallRuleParams::from_app_rule(&rule);
        assert_eq!(params.name, "its.fw: test.exe [Allow:LAN]");
        assert!(params.remote_addresses.contains("LocalSubnet"));
        assert!(
            !params.remote_addresses.contains("127.0.0.0/8"),
            "loopback in remoteip is rejected by netsh"
        );
        assert!(
            !params.remote_addresses.contains("224.0.0.0/4"),
            "multicast in remoteip is rejected by netsh"
        );
        assert_eq!(params.remote_ports, Some("80,443".into()));
        assert_eq!(params.protocol, NetProtocol::Tcp);

        let args = build_netsh_add_rule_args(&params);
        assert!(
            !args.iter().any(|a| a.starts_with("group=")),
            "netsh add rule must NOT pass group= because netsh rejects it"
        );
        assert!(args.iter().any(|a| a == "profile=any"));
    }

    #[test]
    fn test_allow_all_uses_remoteip_any_not_asterisk() {
        let rule = AppRule {
            app_path: r"C:\Program Files\TestApp\test.exe".into(),
            service_name: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::Both,
            custom_remote_ip: None,
            protocol: NetProtocol::Any,
            ports: "*".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&rule);
        assert_eq!(params.remote_addresses, "any");
        let args = build_netsh_add_rule_args(&params);
        assert!(args.iter().any(|a| a == "remoteip=any"));
    }

    #[test]
    fn test_parse_netsh_profiles_outbound_blocked() {
        let allow_out = r#"
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
"#;
        assert!(!parse_netsh_profiles_outbound_blocked(allow_out));

        let block_out = r#"
Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,BlockOutbound
"#;
        assert!(parse_netsh_profiles_outbound_blocked(block_out));
    }

    #[test]
    fn test_parse_netsh_outbound_rules_reconstructs_its_fw_and_external_blocks() {
        let sample_netsh = r#"
Rule Name:                            Block Untrusted App [Out]
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Grouping:                             
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
Program:                              C:\Tools\untrusted.exe
Action:                               Block

Rule Name:                            its.fw: service.exe [Allow:LAN]
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Grouping:                             its.fw
LocalIP:                              Any
RemoteIP:                             LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
Protocol:                             TCP
RemotePort:                           443
Program:                              C:\Services\service.exe
Action:                               Allow

Rule Name:                            Disabled Block Rule
----------------------------------------------------------------------
Enabled:                              No
Direction:                            Out
Program:                              C:\Program Files\Other\other.exe
Action:                               Block
Ok.
"#;

        let rules = parse_netsh_outbound_rules(sample_netsh);
        assert_eq!(rules.len(), 2);

        let untrusted = rules
            .get(r"c:\tools\untrusted.exe")
            .expect("untrusted rule");
        assert_eq!(untrusted.action, RuleAction::Block);
        assert_eq!(untrusted.app_path, r"C:\Tools\untrusted.exe");

        let service = rules.get(r"c:\services\service.exe").expect("service rule");
        assert_eq!(service.action, RuleAction::Allow);
        assert_eq!(service.zone_scope, AllowedZoneScope::LanOnly);
        assert_eq!(service.protocol, NetProtocol::Tcp);
        assert_eq!(service.ports, "443");
    }

    // =========================================================================
    // Contract & Mock Tests за допомогою MockCommandRunner
    // =========================================================================

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct MockCommandRunner {
        executed: Arc<Mutex<Vec<Vec<String>>>>,
        responses: Arc<Mutex<VecDeque<anyhow::Result<CommandOutput>>>>,
    }

    impl FirewallCommandRunner for MockCommandRunner {
        fn execute(&self, args: &[&str]) -> anyhow::Result<CommandOutput> {
            self.executed
                .lock()
                .unwrap()
                .push(args.iter().map(|s| s.to_string()).collect());

            if let Some(res) = self.responses.lock().unwrap().pop_front() {
                res
            } else {
                Ok(CommandOutput {
                    success: true,
                    stdout: "Ok.\n".into(),
                    stderr: String::new(),
                })
            }
        }
    }

    #[test]
    fn test_apply_rule_allow_both_contract() {
        let runner = MockCommandRunner::default();
        let mgr = WindowsFirewallManager::with_runner(runner.clone());

        let rule = AppRule {
            app_path: r"C:\Apps\browser.exe".into(),
            service_name: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::Both,
            custom_remote_ip: None,
            protocol: NetProtocol::Any,
            ports: "*".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&rule);

        mgr.apply_rule(&params).expect("apply_rule should succeed");

        let executed = runner.executed.lock().unwrap().clone();
        assert_eq!(
            executed.len(),
            2,
            "Must delete existing rules then add new rule"
        );

        // 1. Очищення
        assert_eq!(
            executed[0],
            vec![
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=all",
                "program=C:\\Apps\\browser.exe"
            ]
        );

        // 2. Створення
        assert_eq!(
            executed[1][0..4],
            ["advfirewall", "firewall", "add", "rule"]
        );
        assert!(executed[1].contains(&"name=its.fw: browser.exe [Allow:All]".to_string()));
        assert!(executed[1].contains(&"action=allow".to_string()));
        assert!(executed[1].contains(&"remoteip=any".to_string()));
    }

    #[test]
    fn test_apply_rule_allow_internet_only_creates_block_lan_first() {
        let runner = MockCommandRunner::default();
        let mgr = WindowsFirewallManager::with_runner(runner.clone());

        let rule = AppRule {
            app_path: r"C:\Apps\game.exe".into(),
            service_name: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::InternetOnly,
            custom_remote_ip: None,
            protocol: NetProtocol::Tcp,
            ports: "80,443".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&rule);

        mgr.apply_rule(&params).expect("apply_rule should succeed");

        let executed = runner.executed.lock().unwrap().clone();
        assert_eq!(
            executed.len(),
            3,
            "Must delete, add Block LAN, then add Allow Internet"
        );

        // 1. Delete
        assert_eq!(executed[0][2], "delete");
        assert_eq!(executed[0][3], "rule");

        // 2. Block LAN
        assert!(
            executed[1].contains(&"name=its.fw: game.exe [Allow:Internet]: Block LAN".to_string())
        );
        assert!(executed[1].contains(&"action=block".to_string()));
        assert!(executed[1].contains(&format!(
            "remoteip={}",
            Zone::windows_firewall_lan_subnets()
        )));

        // 3. Allow rule
        assert!(executed[2].contains(&"name=its.fw: game.exe [Allow:Internet]".to_string()));
        assert!(executed[2].contains(&"action=allow".to_string()));
    }

    #[test]
    fn test_apply_rule_allow_lan_only_creates_block_internet_first() {
        let runner = MockCommandRunner::default();
        let mgr = WindowsFirewallManager::with_runner(runner.clone());

        let rule = AppRule {
            app_path: r"C:\Services\local_agent.exe".into(),
            service_name: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::LanOnly,
            custom_remote_ip: None,
            protocol: NetProtocol::Any,
            ports: "*".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&rule);

        mgr.apply_rule(&params).expect("apply_rule should succeed");

        let executed = runner.executed.lock().unwrap().clone();
        assert_eq!(
            executed.len(),
            3,
            "Must delete, add Block Internet, then add Allow LAN"
        );

        // 1. Delete
        assert_eq!(executed[0][2], "delete");
        assert_eq!(executed[0][3], "rule");

        // 2. Block Internet
        assert!(executed[1]
            .contains(&"name=its.fw: local_agent.exe [Allow:LAN]: Block Internet".to_string()));
        assert!(executed[1].contains(&"action=block".to_string()));
        assert!(executed[1].contains(&format!(
            "remoteip={}",
            Zone::windows_firewall_internet_ranges()
        )));

        // 3. Allow LAN
        assert!(executed[2].contains(&"name=its.fw: local_agent.exe [Allow:LAN]".to_string()));
        assert!(executed[2].contains(&"action=allow".to_string()));
        assert!(executed[2].contains(&format!(
            "remoteip={}",
            Zone::windows_firewall_lan_subnets()
        )));
    }

    #[test]
    fn test_apply_rule_inbound_allow_lan_only_uses_dir_in() {
        let runner = MockCommandRunner::default();
        let mgr = WindowsFirewallManager::with_runner(runner.clone());

        let rule = AppRule {
            app_path: r"C:\Services\listener.exe".into(),
            service_name: None,
            direction: RuleDirection::Inbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::LanOnly,
            custom_remote_ip: None,
            protocol: NetProtocol::Tcp,
            ports: "8080".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&rule);

        mgr.apply_rule(&params).expect("apply_rule should succeed");

        let executed = runner.executed.lock().unwrap().clone();
        assert_eq!(executed.len(), 3);
        // Delete
        assert_eq!(executed[0][2], "delete");
        // Block Internet auxiliary rule must use dir=in
        assert!(executed[1]
            .contains(&"name=its.fw: listener.exe [In:Allow:LAN]: Block Internet".to_string()));
        assert!(executed[1].contains(&"dir=in".to_string()));
        assert!(executed[1].contains(&"action=block".to_string()));
        // Allow rule must also use dir=in
        assert!(executed[2].contains(&"name=its.fw: listener.exe [In:Allow:LAN]".to_string()));
        assert!(executed[2].contains(&"dir=in".to_string()));
    }

    #[test]
    fn test_apply_rule_propagates_netsh_error_message() {
        let runner = MockCommandRunner::default();
        // Відповідь 1 (delete) - Ok
        runner
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }));
        // Відповідь 2 (add) - Error: Access denied
        runner
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "The requested operation requires elevation (Run as administrator).".into(),
            }));

        let mgr = WindowsFirewallManager::with_runner(runner);
        let rule = AppRule {
            app_path: r"C:\Apps\test.exe".into(),
            service_name: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Block,
            zone_scope: AllowedZoneScope::Both,
            custom_remote_ip: None,
            protocol: NetProtocol::Any,
            ports: "*".into(),
            interface_name: None,
            created_at: 0,
            duration: crate::core::rules::RuleDuration::Permanent,
            expires_at: None,
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&rule);

        let res = mgr.apply_rule(&params);
        assert!(res.is_err());
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("requires elevation"));
    }

    #[test]
    fn test_set_outbound_policy_contract() {
        let runner = MockCommandRunner::default();

        WindowsFirewallManager::set_outbound_policy_with(&runner, true)
            .expect("set_outbound_policy true should succeed");
        WindowsFirewallManager::set_outbound_policy_with(&runner, false)
            .expect("set_outbound_policy false should succeed");

        let executed = runner.executed.lock().unwrap().clone();
        assert_eq!(executed.len(), 2);
        assert_eq!(
            executed[0],
            vec![
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                "blockinbound,blockoutbound"
            ]
        );
        assert_eq!(
            executed[1],
            vec![
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                "blockinbound,allowoutbound"
            ]
        );
    }

    #[test]
    fn test_remove_rule_by_name_and_all_rules_contract() {
        let runner = MockCommandRunner::default();
        let mgr = WindowsFirewallManager::with_runner(runner.clone());

        mgr.remove_rule_by_name("its.fw: test.exe [Block:All]")
            .unwrap();
        mgr.remove_all_rules().unwrap();

        let executed = runner.executed.lock().unwrap().clone();
        assert_eq!(executed.len(), 2);
        assert_eq!(
            executed[0],
            vec![
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=its.fw: test.exe [Block:All]"
            ]
        );
        assert_eq!(
            executed[1],
            vec![
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=all",
                "group=its.fw"
            ]
        );
    }

    #[test]
    fn test_parse_active_its_fw_rules_contract() {
        let sample = r#"
Rule Name:                            its.fw: client.exe [Allow:All]
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Grouping:                             its.fw
Program:                              C:\Apps\client.exe

Rule Name:                            Other Group Rule
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Grouping:                             Windows Defender
Program:                              C:\Apps\other.exe
"#;

        let runner = MockCommandRunner::default();
        runner
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(CommandOutput {
                success: true,
                stdout: sample.into(),
                stderr: String::new(),
            }));

        let rules = WindowsFirewallManager::load_active_its_fw_rules_with(&runner);
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules.get(r"c:\apps\client.exe").unwrap(),
            "its.fw: client.exe [Allow:All]"
        );
    }

    #[test]
    fn test_load_blocked_outbound_apps_with_contract() {
        let sample = r#"
Rule Name:                            Custom Block Rule
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Program:                              C:\Suspicious\malware.exe
Action:                               Block

Rule Name:                            Disabled Rule
----------------------------------------------------------------------
Enabled:                              No
Direction:                            Out
Program:                              C:\Apps\good.exe
Action:                               Block
"#;

        let runner = MockCommandRunner::default();
        runner
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(CommandOutput {
                success: true,
                stdout: sample.into(),
                stderr: String::new(),
            }));

        let manager = WindowsFirewallManager::with_runner(runner);
        let blocked = WindowsFirewallManager::load_blocked_outbound_apps_with(manager.runner());

        assert!(blocked.contains(r"C:\Suspicious\malware.exe"));
        assert!(blocked.contains("malware.exe"));
        assert!(!blocked.contains(r"C:\Apps\good.exe"));
    }

    #[test]
    fn test_temporary_rule_name_has_ttl_tag() {
        let mut rule = AppRule {
            app_path: r"C:\App\installer.exe".into(),
            service_name: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::Both,
            custom_remote_ip: None,
            protocol: NetProtocol::Any,
            ports: "*".into(),
            interface_name: None,
            created_at: 100,
            duration: crate::core::rules::RuleDuration::Minutes5,
            expires_at: Some(400),
            display_name: None,
            rule_id: None,
            is_system_or_uwp: false,
        };
        let params = FirewallRuleParams::from_app_rule(&rule);
        assert_eq!(params.name, "its.fw: installer.exe [Allow:All] [TTL]");

        rule.duration = crate::core::rules::RuleDuration::Permanent;
        rule.expires_at = None;
        let perm_params = FirewallRuleParams::from_app_rule(&rule);
        assert_eq!(perm_params.name, "its.fw: installer.exe [Allow:All]");
    }

    #[test]
    fn test_parse_registry_rule_entry_hyperv_port_and_uwp() {
        let hv_raw = "v2.33|Name=kbot dev tcp|Dir=In|VMCreatorId={40E0AC32-46A5-438A-A0B2-2B479E8F2E90}|Protocol=6|RA4=192.168.128.0/255.255.252.0|LPort=5300|LPort=443|LPort=6443|Action=Allow|Active=TRUE|";
        let hv_rule = parse_registry_rule_entry("kbot-dev-tcp", hv_raw, true)
            .expect("should parse Hyper-V rule");
        assert_eq!(hv_rule.app_path, "wsl://kbot-dev-tcp");
        assert_eq!(hv_rule.display_name.as_deref(), Some("[WSL] kbot dev tcp"));
        assert_eq!(hv_rule.direction, RuleDirection::Inbound);
        assert_eq!(hv_rule.action, RuleAction::Allow);
        assert_eq!(hv_rule.protocol, NetProtocol::Tcp);
        assert_eq!(hv_rule.ports, "5300,443,6443");
        assert_eq!(
            hv_rule.custom_remote_ip.as_deref(),
            Some("192.168.128.0/22")
        );
        assert!(!hv_rule.is_system_or_uwp);

        let port_raw = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8443|LPort=8080|RA4=172.16.117.0/255.255.255.0|RA4=172.16.113.0/255.255.255.0|IF={AD179937}|Name=home.lab boot server on ctl (WSL)|";
        let port_rule = parse_registry_rule_entry("home-lab-boot", port_raw, false)
            .expect("should parse port-only rule");
        assert_eq!(port_rule.app_path, "port://home-lab-boot");
        assert_eq!(
            port_rule.display_name.as_deref(),
            Some("[PORT] home.lab boot server on ctl (WSL)")
        );
        assert_eq!(port_rule.ports, "8443,8080");
        assert_eq!(
            port_rule.custom_remote_ip.as_deref(),
            Some("172.16.117.0/24,172.16.113.0/24")
        );
        assert!(!port_rule.is_system_or_uwp);

        let uwp_raw = "v2.33|Action=Allow|Active=TRUE|Dir=Out|Profile=Domain|Profile=Private|Profile=Public|Name=Microsoft Store|Desc=Microsoft Store|PFN=Microsoft.WindowsStore_8wekyb3d8bbwe|";
        let uwp_rule =
            parse_registry_rule_entry("StoreRule", uwp_raw, false).expect("should parse UWP rule");
        assert_eq!(
            uwp_rule.app_path,
            "uwp://Microsoft.WindowsStore_8wekyb3d8bbwe"
        );
        assert_eq!(
            uwp_rule.display_name.as_deref(),
            Some("[UWP] Microsoft Store")
        );
        assert!(uwp_rule.is_system_or_uwp);

        let params = FirewallRuleParams::from_app_rule(&hv_rule);
        let (rule_id, built_reg) = build_hyperv_registry_rule_string(&params);
        assert_eq!(rule_id, "kbot-dev-tcp");
        assert!(built_reg.contains("Protocol=6|"));
        assert!(built_reg.contains("LPort=5300|LPort=443|LPort=6443|"));
        assert!(built_reg.contains("RA4=192.168.128.0/255.255.252.0|"));
        assert!(built_reg.contains("Name=kbot dev tcp|"));

        let ps_cmd = build_hyperv_powershell_upsert_cmd(&rule_id, &params);
        assert!(ps_cmd.contains("New-NetFirewallHyperVRule"));
        assert!(ps_cmd.contains("-ErrorAction Stop"));
        assert!(ps_cmd.contains("-LocalPorts @('5300','443','6443')"));

        // Verify LAN-only Hyper-V rule with LocalSubnet + standard LAN CIDRs parses as LanOnly
        let lan_raw = "v2.33|Action=Allow|Active=TRUE|Dir=Out|VMCreatorId={40E0AC32-46A5-438A-A0B2-2B479E8F2E90}|Protocol=17|RPort=53|RPort=67|RPort=123|RA4=LocalSubnet4|RA4=10.0.0.0/255.0.0.0|RA4=172.16.0.0/255.240.0.0|RA4=192.168.0.0/255.255.0.0|RA6=fe80::/10|Name=allow-dhcp-dns-ntp|";
        let lan_rule = parse_registry_rule_entry("allow-dhcp-dns-ntp", lan_raw, true)
            .expect("should parse LAN Hyper-V rule");
        assert_eq!(lan_rule.zone_scope, AllowedZoneScope::LanOnly);
        assert_eq!(lan_rule.custom_remote_ip, None);
        assert_eq!(lan_rule.ports, "53,67,123");
    }
}
