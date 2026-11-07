use serde::{Deserialize, Serialize};

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
    pub action: RuleAction,
    pub zone_scope: AllowedZoneScope,
    pub protocol: NetProtocol,
    pub ports: String, // наприклад "80,443" або "*"
    pub interface_name: Option<String>,
    pub created_at: i64,
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
}
