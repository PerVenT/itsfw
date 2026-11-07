use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum RuleDirection {
    #[default]
    Outbound,
    Inbound,
}

impl RuleDirection {
    pub fn label(&self) -> &'static str {
        match self {
            RuleDirection::Outbound => "Outbound",
            RuleDirection::Inbound => "Inbound",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllowedZoneScope {
    LanOnly,
    InternetOnly,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetProtocol {
    Any,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRule {
    pub app_path: String,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub zone_scope: AllowedZoneScope,
    #[serde(default)]
    pub custom_remote_ip: Option<String>,
    pub protocol: NetProtocol,
    pub ports: String, // наприклад "80,443" або "*"
    pub interface_name: Option<String>,
    pub created_at: i64,
}

impl AppRule {
    pub fn composite_key(&self) -> String {
        make_app_key(&self.app_path, self.service_name.as_deref(), self.direction)
    }
}

pub fn make_app_key(app_path: &str, service_name: Option<&str>, direction: RuleDirection) -> String {
    let lower_path = app_path.to_lowercase();
    let base_key = match service_name {
        Some(svc) if !svc.trim().is_empty() => {
            format!("{}::svc:{}", lower_path, svc.trim().to_lowercase())
        }
        _ => lower_path,
    };
    match direction {
        RuleDirection::Outbound => base_key,
        RuleDirection::Inbound => format!("in::{}", base_key),
    }
}

pub fn validate_ports_spec(spec: &str, protocol: NetProtocol) -> Result<String, String> {
    if protocol == NetProtocol::Any {
        return Ok("*".into());
    }
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("Port specification cannot be empty".into());
    }
    if trimmed == "*" || trimmed.eq_ignore_ascii_case("any") {
        return Ok("*".into());
    }

    let tokens: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
    if tokens.is_empty() {
        return Err("Port specification cannot be empty".into());
    }

    let mut validated_tokens = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token.is_empty() {
            return Err("Empty port entry in list".into());
        }
        if token.contains('-') {
            let parts: Vec<&str> = token.split('-').map(|s| s.trim()).collect();
            if parts.len() != 2 {
                return Err(format!("Invalid port range format: '{}'", token));
            }
            let start = parts[0]
                .parse::<u16>()
                .map_err(|_| format!("Invalid range start port: '{}'", parts[0]))?;
            let end = parts[1]
                .parse::<u16>()
                .map_err(|_| format!("Invalid range end port: '{}'", parts[1]))?;
            if start == 0 {
                return Err("Port number cannot be 0".into());
            }
            if start > end {
                return Err(format!(
                    "Invalid port range: start ({}) cannot be greater than end ({})",
                    start, end
                ));
            }
            validated_tokens.push(format!("{}-{}", start, end));
        } else {
            let port = token
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: '{}'", token))?;
            if port == 0 {
                return Err("Port number cannot be 0".into());
            }
            validated_tokens.push(port.to_string());
        }
    }

    Ok(validated_tokens.join(","))
}

pub fn validate_ip_or_cidr_spec(spec: &str) -> Result<String, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("IP / CIDR specification cannot be empty".into());
    }
    if trimmed == "*" || trimmed.eq_ignore_ascii_case("any") {
        return Ok("any".into());
    }

    let tokens: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
    if tokens.is_empty() {
        return Err("IP / CIDR specification cannot be empty".into());
    }

    let mut validated_tokens = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token.is_empty() {
            return Err("Empty IP entry in list".into());
        }
        if token.contains('/') {
            let parts: Vec<&str> = token.split('/').map(|s| s.trim()).collect();
            if parts.len() != 2 {
                return Err(format!("Invalid CIDR format: '{}'", token));
            }
            let ip = parts[0]
                .parse::<std::net::IpAddr>()
                .map_err(|_| format!("Invalid IP address in CIDR: '{}'", parts[0]))?;
            let prefix = parts[1]
                .parse::<u8>()
                .map_err(|_| format!("Invalid prefix length in CIDR: '{}'", parts[1]))?;

            match ip {
                std::net::IpAddr::V4(_) => {
                    if prefix > 32 {
                        return Err(format!("IPv4 CIDR prefix must be 0..=32, got {}", prefix));
                    }
                }
                std::net::IpAddr::V6(_) => {
                    if prefix > 128 {
                        return Err(format!("IPv6 CIDR prefix must be 0..=128, got {}", prefix));
                    }
                }
            }
            validated_tokens.push(format!("{}/{}", ip, prefix));
        } else {
            let ip = token
                .parse::<std::net::IpAddr>()
                .map_err(|_| format!("Invalid IP address: '{}'", token))?;
            validated_tokens.push(ip.to_string());
        }
    }

    Ok(validated_tokens.join(","))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ActiveTheme {
    #[default]
    MonokaiProRistretto,
    GruvboxDarkSoft,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserConfig {
    pub theme: ActiveTheme,
}

impl UserConfig {
    pub fn config_path_from_home(home: &std::path::Path) -> std::path::PathBuf {
        home.join(".config").join("itsfw").join("config.toml")
    }

    pub fn config_path() -> std::path::PathBuf {
        if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
            Self::config_path_from_home(std::path::Path::new(&home))
        } else {
            std::path::PathBuf::from(".config")
                .join("itsfw")
                .join("config.toml")
        }
    }

    pub fn load_or_create_at(path: &std::path::Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let cfg = Self::from_toml(&content)?;
            Ok(cfg)
        } else {
            let default_cfg = Self::default();
            default_cfg.save_at(path)?;
            Ok(default_cfg)
        }
    }

    pub fn load_or_create() -> Self {
        let path = Self::config_path();
        Self::load_or_create_at(&path).unwrap_or_default()
    }

    pub fn save_at(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let toml_str = self.to_toml()?;
        std::fs::write(path, toml_str)?;
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path();
        self.save_at(&path)
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_path_uses_dot_config_itsfw_toml() {
        let fake_home = std::path::Path::new("/tmp/fake_user");
        let p = UserConfig::config_path_from_home(fake_home);
        assert_eq!(
            p,
            std::path::PathBuf::from("/tmp/fake_user/.config/itsfw/config.toml")
        );
    }

    #[test]
    fn test_load_or_create_creates_toml_file_when_missing_and_reads_when_present() {
        let temp_dir = std::env::temp_dir().join(format!("itsfw_test_toml_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let cfg_path = UserConfig::config_path_from_home(&temp_dir);

        assert!(!cfg_path.exists());
        let loaded =
            UserConfig::load_or_create_at(&cfg_path).expect("should create default config");
        assert!(cfg_path.exists(), "config file must be created on disk");
        assert_eq!(loaded.theme, ActiveTheme::MonokaiProRistretto);

        let mut modified = loaded;
        modified.theme = ActiveTheme::GruvboxDarkSoft;
        modified
            .save_at(&cfg_path)
            .expect("should save modified config");

        let reloaded =
            UserConfig::load_or_create_at(&cfg_path).expect("should read existing config");
        assert_eq!(reloaded.theme, ActiveTheme::GruvboxDarkSoft);

        // Перевірка серіалізації: "Parse, don't validate"
        // Замість крихкого рядкового пошуку підрядків розбираємо як TOML через схему UserConfig
        let raw_toml =
            std::fs::read_to_string(&cfg_path).expect("config file must be readable from disk");
        let parsed_config = UserConfig::from_toml(&raw_toml)
            .expect("config must be valid TOML deserializable into UserConfig schema");
        assert_eq!(parsed_config.theme, ActiveTheme::GruvboxDarkSoft);

        // Перевірка контракту: файл конфігурації не повинен зберігати правила фаєрволу
        let toml_tree: toml::Value =
            toml::from_str(&raw_toml).expect("raw content must be valid TOML syntax");
        assert!(
            toml_tree.get("rules").is_none(),
            "config file must not store firewall rules (rules are managed in rules.toml or Windows Firewall)"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_make_app_key_and_validators() {
        assert_eq!(
            make_app_key(r"C:\Windows\System32\svchost.exe", None, RuleDirection::Outbound),
            r"c:\windows\system32\svchost.exe"
        );
        assert_eq!(
            make_app_key(r"C:\Windows\System32\svchost.exe", Some("Dnscache"), RuleDirection::Outbound),
            r"c:\windows\system32\svchost.exe::svc:dnscache"
        );
        assert_eq!(
            make_app_key(r"C:\App\server.exe", None, RuleDirection::Inbound),
            r"in::c:\app\server.exe"
        );

        assert_eq!(validate_ports_spec("80, 443, 8000-8080", NetProtocol::Tcp).unwrap(), "80,443,8000-8080");
        assert_eq!(validate_ports_spec("443", NetProtocol::Any).unwrap(), "*");
        assert!(validate_ports_spec("0", NetProtocol::Tcp).is_err());
        assert!(validate_ports_spec("9000-8000", NetProtocol::Tcp).is_err());
        assert!(validate_ports_spec("70000", NetProtocol::Udp).is_err());

        assert_eq!(validate_ip_or_cidr_spec("192.168.1.1, 10.0.0.0/8").unwrap(), "192.168.1.1,10.0.0.0/8");
        assert!(validate_ip_or_cidr_spec("999.999.1.1").is_err());
        assert!(validate_ip_or_cidr_spec("10.0.0.1/33").is_err());
    }
}
