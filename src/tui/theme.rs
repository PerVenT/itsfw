//! Колірні теми для TUI: Monokai Pro Ristretto (default) та Gruvbox Dark Soft у стилі superfile / dtop.

use crate::core::rules::ActiveTheme;
use ratatui::style::Color;

#[derive(Debug, Clone)]
pub struct ThemePalette {
    pub bg: Color,
    pub surface: Color,
    pub fg: Color,
    pub fg_muted: Color,
    pub border: Color,
    pub border_focus: Color,
    pub alert_red: Color, // Knocking / Blocked
    pub warning_orange: Color,
    pub lan_yellow: Color,    // LAN badge
    pub allowed_green: Color, // Allowed
    pub internet_cyan: Color, // Internet badge
    pub port_purple: Color,   // Port / protocol
}

impl ThemePalette {
    /// Точна палітра Monokai Pro Ristretto з WezTerm (C:\Users\PerVenT\.config\wezterm\colors\monokai-pro-ristretto.toml)
    pub fn monokai_pro_ristretto() -> Self {
        Self {
            bg: Color::Reset,
            surface: Color::Rgb(91, 83, 83), // #5b5353 (selection_bg / split)
            fg: Color::Rgb(255, 241, 243),   // #fff1f3 (foreground)
            fg_muted: Color::Rgb(114, 105, 106), // #72696a (brights[0] muted gray)
            border: Color::Rgb(91, 83, 83),  // #5b5353 (split / unfocused border)
            border_focus: Color::Rgb(249, 204, 108), // #f9cc6c (brights[3] yellow / cursor)
            alert_red: Color::Rgb(253, 104, 131), // #fd6883 (brights[1] red)
            warning_orange: Color::Rgb(243, 141, 112), // #f38d70 (brights[4] orange)
            lan_yellow: Color::Rgb(249, 204, 108), // #f9cc6c (brights[3] yellow)
            allowed_green: Color::Rgb(173, 218, 120), // #adda78 (brights[2] green)
            internet_cyan: Color::Rgb(133, 218, 204), // #85dacc (brights[6] cyan)
            port_purple: Color::Rgb(168, 169, 235), // #a8a9eb (brights[5] purple)
        }
    }

    /// Точна палітра Gruvbox Dark Soft з WezTerm (C:\Users\PerVenT\.config\wezterm\colors\gruvbox-dark-soft.toml)
    pub fn gruvbox_dark_soft() -> Self {
        Self {
            bg: Color::Reset,
            surface: Color::Rgb(102, 92, 84), // #665c54 (selection_bg)
            fg: Color::Rgb(235, 219, 178),    // #ebdbb2 (foreground)
            fg_muted: Color::Rgb(146, 131, 116), // #928374 (brights[0] muted gray)
            border: Color::Rgb(80, 73, 69),   // #504945 (scrollbar_thumb unfocused)
            border_focus: Color::Rgb(250, 189, 47), // #fabd2f (brights[3] yellow focus)
            alert_red: Color::Rgb(251, 73, 52), // #fb4934 (brights[1] red)
            warning_orange: Color::Rgb(254, 128, 25), // #fe8019 (orange)
            lan_yellow: Color::Rgb(250, 189, 47), // #fabd2f (brights[3] yellow)
            allowed_green: Color::Rgb(184, 187, 38), // #b8bb26 (brights[2] green)
            internet_cyan: Color::Rgb(131, 165, 152), // #83a598 (brights[4] blue for clear contrast)
            port_purple: Color::Rgb(211, 134, 155),   // #d3869b (brights[5] purple)
        }
    }

    pub fn for_theme(theme: ActiveTheme) -> Self {
        match theme {
            ActiveTheme::MonokaiProRistretto => Self::monokai_pro_ristretto(),
            ActiveTheme::GruvboxDarkSoft => Self::gruvbox_dark_soft(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_palette_for_theme_mapping() {
        let monokai = ThemePalette::for_theme(ActiveTheme::MonokaiProRistretto);
        let gruvbox = ThemePalette::for_theme(ActiveTheme::GruvboxDarkSoft);

        assert_eq!(monokai.bg, Color::Reset);
        assert_eq!(gruvbox.bg, Color::Reset);

        // Verification of distinct palette attributes
        assert_ne!(monokai.fg, gruvbox.fg);
        assert_ne!(monokai.surface, gruvbox.surface);
        assert_ne!(monokai.border, gruvbox.border);
        assert_ne!(monokai.alert_red, gruvbox.alert_red);
        assert_ne!(monokai.internet_cyan, gruvbox.internet_cyan);
    }

    #[test]
    fn test_theme_palette_rgb_contract() {
        let palettes = [
            ThemePalette::monokai_pro_ristretto(),
            ThemePalette::gruvbox_dark_soft(),
        ];

        for p in &palettes {
            for color in [
                p.surface,
                p.fg,
                p.fg_muted,
                p.border,
                p.border_focus,
                p.alert_red,
                p.warning_orange,
                p.lan_yellow,
                p.allowed_green,
                p.internet_cyan,
                p.port_purple,
            ] {
                assert!(matches!(color, Color::Rgb(..)));
            }
        }
    }
}
