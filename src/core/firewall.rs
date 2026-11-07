//! Керування правилами та політикою Windows Defender Firewall через COM (INetFwPolicy2 / INetFwRule).

use crate::core::rules::{
    make_app_key, AllowedZoneScope, AppRule, NetProtocol, RuleAction, RuleDirection,
};
use crate::core::zone::Zone;

pub const FIREWALL_RULE_GROUP: &str = "it's.fw";
pub const LEGACY_FIREWALL_RULE_GROUP: &str = "its.fw";

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
}

impl FirewallRuleParams {
    /// Генерує параметри для правила у Windows Firewall із заданого правила додатку `AppRule`.
    pub fn from_app_rule(rule: &AppRule) -> Self {
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

        Self {
            name: format!("{}: {} [{}]", LEGACY_FIREWALL_RULE_GROUP, target, tag),
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

static LOCKDOWN_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub trait FirewallBackend: Send + Sync {
    fn is_outbound_blocking(&self) -> bool;
    fn set_outbound_blocking(&self, block: bool) -> anyhow::Result<()>;
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
        use windows::Win32::System::Variant::{VariantChangeType, VAR_CHANGE_FLAGS, VT_UNKNOWN};

        if let Ok(unk) = rules._NewEnum() {
            if let Ok(enum_var) = unk.cast::<IEnumVARIANT>() {
                loop {
                    let mut var = [windows::core::VARIANT::default()];
                    let mut fetched = 0u32;
                    let hr = enum_var.Next(&mut var, &mut fetched);
                    if hr.is_err() || fetched == 0 {
                        break;
                    }
                    let mut unk_var = windows::core::VARIANT::default();
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
            if !params.app_path.is_empty() {
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
                                },
                            );
                        }
                    });
                }
            }
        }
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
        let _ = self.remove_app_rules(
            &params.app_path,
            params.service_name.as_deref(),
            params.direction,
        );

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
            NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
        };
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
}
