//! Керування правилами та політикою Windows Defender Firewall через COM (INetFwPolicy2 / INetFwRule).

use crate::core::rules::{AllowedZoneScope, AppRule, NetProtocol, RuleAction};
use crate::core::zone::Zone;

pub const FIREWALL_RULE_GROUP: &str = "its.fw";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRuleParams {
    pub name: String,
    pub description: String,
    pub app_path: String,
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

        let action_str = match rule.action {
            RuleAction::Allow => "Allow",
            RuleAction::Block => "Block",
        };

        let zone_str = match rule.zone_scope {
            AllowedZoneScope::LanOnly => "LAN",
            AllowedZoneScope::InternetOnly => "Internet",
            AllowedZoneScope::Both => "All",
        };

        let remote_addresses = match rule.zone_scope {
            AllowedZoneScope::LanOnly => Zone::windows_firewall_lan_subnets().to_string(),
            AllowedZoneScope::InternetOnly | AllowedZoneScope::Both => {
                Zone::windows_firewall_all_subnets().to_string()
            }
        };

        let remote_ports = if rule.ports.trim().is_empty() || rule.ports.trim() == "*" {
            None
        } else {
            Some(rule.ports.trim().to_string())
        };

        Self {
            name: format!(
                "{}: {} [{}:{}]",
                FIREWALL_RULE_GROUP, app_filename, action_str, zone_str
            ),
            description: format!("Created by it's.fw for {}", rule.app_path),
            app_path: rule.app_path.clone(),
            action: rule.action,
            remote_addresses,
            protocol: rule.protocol,
            local_ports: None,
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

    let mut args = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={}", params.name),
        format!("description={}", params.description),
        "dir=out".to_string(),
        "enable=yes".to_string(),
        "profile=any".to_string(),
        format!("action={}", action),
        format!("program={}", params.app_path),
        format!("protocol={}", protocol),
        format!("remoteip={}", params.remote_addresses),
    ];

    if let Some(ref rports) = params.remote_ports {
        if protocol != "any" {
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
pub fn parse_netsh_outbound_rules(text: &str) -> std::collections::HashMap<String, AppRule> {
    let mut rules: std::collections::HashMap<String, AppRule> = std::collections::HashMap::new();

    let mut current_name = String::new();
    let mut current_program = String::new();
    let mut current_action: Option<RuleAction> = None;
    let mut current_grouping = String::new();
    let mut current_remote_ip = String::new();
    let mut current_protocol = NetProtocol::Any;
    let mut current_remote_port = String::from("*");
    let mut is_enabled = false;

    let mut flush_rule = |name: &str,
                          prog: &str,
                          action: Option<RuleAction>,
                          grouping: &str,
                          remote_ip: &str,
                          protocol: NetProtocol,
                          remote_port: &str,
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
            || name.starts_with(FIREWALL_RULE_GROUP);

        if act == RuleAction::Block || is_its_fw {
            let zone_scope = if name.contains("[Allow:LAN]")
                || remote_ip.contains("LocalSubnet")
                || remote_ip.contains("192.168.")
            {
                AllowedZoneScope::LanOnly
            } else if name.contains("[Allow:Internet]") {
                AllowedZoneScope::InternetOnly
            } else {
                AllowedZoneScope::Both
            };

            let key = prog.to_lowercase();
            if let Some(existing) = rules.get(&key) {
                if existing.action == RuleAction::Block && act == RuleAction::Allow {
                    return;
                }
            }

            rules.insert(
                key,
                AppRule {
                    app_path: prog.to_string(),
                    action: act,
                    zone_scope,
                    protocol,
                    ports: if remote_port.is_empty() || remote_port.eq_ignore_ascii_case("Any") {
                        "*".into()
                    } else {
                        remote_port.to_string()
                    },
                    interface_name: None,
                    created_at: 0,
                },
            );
        }
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
                &current_remote_port,
                is_enabled,
            );
            current_name = trimmed.trim_start_matches("Rule Name:").trim().to_string();
            current_program.clear();
            current_action = None;
            current_grouping.clear();
            current_remote_ip.clear();
            current_protocol = NetProtocol::Any;
            current_remote_port = String::from("*");
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
        } else if trimmed.starts_with("RemotePort:") {
            current_remote_port = trimmed.trim_start_matches("RemotePort:").trim().to_string();
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
        &current_remote_port,
        is_enabled,
    );

    rules
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
pub trait FirewallCommandRunner: Send + Sync {
    fn execute(&self, args: &[&str]) -> anyhow::Result<CommandOutput>;
}

/// Стандартний виконавець команд у системі (викликає реальний `netsh`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl FirewallCommandRunner for SystemCommandRunner {
    fn execute(&self, args: &[&str]) -> anyhow::Result<CommandOutput> {
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

/// Парсить активні правила grupy `its.fw` із тексту виводу `netsh`.
pub fn parse_active_its_fw_rules(text: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut current_name = String::new();
    let mut current_program = String::new();
    let mut is_its_fw_group = false;
    let mut is_enabled = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Rule Name:") {
            if (is_its_fw_group || current_name.starts_with(FIREWALL_RULE_GROUP))
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
            if grp.eq_ignore_ascii_case(FIREWALL_RULE_GROUP) {
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

    if (is_its_fw_group || current_name.starts_with(FIREWALL_RULE_GROUP))
        && is_enabled
        && !current_program.is_empty()
    {
        map.insert(current_program.to_lowercase(), current_name);
    }

    map
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
        Self::is_outbound_policy_blocking_with(&SystemCommandRunner)
    }

    pub fn load_outbound_rules_from_os() -> std::collections::HashMap<String, AppRule> {
        Self::load_outbound_rules_from_os_with(&SystemCommandRunner)
    }

    pub fn load_blocked_outbound_apps() -> std::collections::HashSet<String> {
        Self::load_blocked_outbound_apps_with(&SystemCommandRunner)
    }

    pub fn load_active_its_fw_rules() -> std::collections::HashMap<String, String> {
        Self::load_active_its_fw_rules_with(&SystemCommandRunner)
    }

    pub fn set_outbound_policy(block: bool) -> anyhow::Result<()> {
        Self::set_outbound_policy_with(&SystemCommandRunner, block)
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

    pub fn load_outbound_rules_from_os_with(
        runner: &R,
    ) -> std::collections::HashMap<String, AppRule> {
        if let Ok(out) = runner.execute(&[
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            "dir=out",
            "verbose",
        ]) {
            parse_netsh_outbound_rules(&out.stdout)
        } else {
            std::collections::HashMap::new()
        }
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

    /// Створює або оновлює правило у Windows Firewall через виконавець команд netsh.
    pub fn apply_rule(&self, params: &FirewallRuleParams) -> anyhow::Result<()> {
        // Очищаємо попередні правила для цієї програми, щоб уникнути конфлікту блокувань (Block має вищий пріоритет за Allow)
        let _ = self.runner.execute(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=all",
            &format!("program={}", params.app_path),
        ]);

        // Якщо це правило Allow Internet Only: спочатку блокуємо доступ до LAN, потім дозволяємо any
        if params.action == RuleAction::Allow && params.name.contains("[Allow:Internet]") {
            let block_lan_name = format!("{}: Block LAN", params.name);
            let _ = self.runner.execute(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", block_lan_name),
                "dir=out",
                "enable=yes",
                "profile=any",
                "action=block",
                &format!("program={}", params.app_path),
                &format!("remoteip={}", Zone::windows_firewall_lan_subnets()),
            ]);
        }

        // Якщо це правило Allow LAN Only: додатково блокуємо публічні IP Інтернету
        if params.action == RuleAction::Allow && params.name.contains("[Allow:LAN]") {
            let block_inet_name = format!("{}: Block Internet", params.name);
            let _ = self.runner.execute(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", block_inet_name),
                "dir=out",
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
            &format!("group={}", FIREWALL_RULE_GROUP),
        ]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_rule_params_generation() {
        let rule = AppRule {
            app_path: r"C:\Program Files\TestApp\test.exe".into(),
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::LanOnly,
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
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::Both,
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
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::Both,
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
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::InternetOnly,
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
            action: RuleAction::Allow,
            zone_scope: AllowedZoneScope::LanOnly,
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
            action: RuleAction::Block,
            zone_scope: AllowedZoneScope::Both,
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
