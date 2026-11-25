//! Відображення інтерфейсу TUI на базі Ratatui у стилі superfile / dtop.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::core::zone::Zone;
use crate::tui::app::{App, EditorTargetOption, RuleEditorField, ViewFilter};

fn styled_app_name_spans(
    app_name: &str,
    width: usize,
    is_selected: bool,
    is_dimmed_selection: bool,
    palette: &crate::tui::theme::ThemePalette,
) -> Vec<Span<'static>> {
    let padded = fit_width(app_name, width);
    let mut base_mod = Modifier::empty();
    if is_selected {
        base_mod |= Modifier::BOLD;
        if is_dimmed_selection {
            base_mod |= Modifier::UNDERLINED;
        }
    }

    let prefixes: [(&str, ratatui::style::Color, ratatui::style::Color); 3] = [
        ("[WSL] ", palette.warning_orange, palette.internet_cyan),
        ("[PORT] ", palette.port_purple, palette.fg),
        ("[UWP] ", palette.lan_yellow, palette.fg),
    ];

    for (pfx, tag_color, rest_color) in prefixes {
        if let Some(rest) = padded.strip_prefix(pfx) {
            return vec![
                Span::styled(
                    pfx.to_string(),
                    Style::default().fg(tag_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    rest.to_string(),
                    Style::default().fg(rest_color).add_modifier(base_mod),
                ),
            ];
        }
    }

    vec![Span::styled(
        padded,
        Style::default().fg(palette.fg).add_modifier(base_mod),
    )]
}

/// Допоміжна функція для строгого обрізання або доповнення рядка пробілами до заданої ширини.
fn fit_width(s: &str, width: usize) -> String {
    let char_count = s.chars().count();
    if char_count > width {
        if width > 3 {
            let mut res: String = s.chars().take(width - 2).collect();
            res.push_str("..");
            res
        } else {
            s.chars().take(width).collect()
        }
    } else {
        format!("{:<width$}", s, width = width)
    }
}

pub fn render(f: &mut Frame, app: &mut App) {
    // Головний вертикальний лейаут (v5): Шапка (3) -> Таблиця (100% Min) -> Нижній спліт (8) -> Футер (1)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    render_header(f, app, chunks[0]);
    render_table(f, app, chunks[1]);
    render_bottom_split(f, app, chunks[2]);
    render_footer(f, app, chunks[3]);

    if app.search_active {
        render_search_or_listener_overlay(f, app);
    }

    if app.sort_menu_open {
        render_sort_modal(f, app);
    }

    if app.edit_mode {
        render_edit_modal(f, app);
    }

    if app.args_modal_open {
        render_args_modal(f, app);
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let palette = app.current_palette();
    let dir_label = app.active_direction.label();

    let fw_status = match app.active_direction {
        crate::tui::app::FirewallDirection::Outbound => {
            if app.firewall_active {
                Span::styled(
                    format!("● {}: BLOCK (Whitelist Mode)", dir_label),
                    Style::default()
                        .fg(palette.warning_orange)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    format!("● {}: ALLOW (Default Mode)", dir_label),
                    Style::default()
                        .fg(palette.allowed_green)
                        .add_modifier(Modifier::BOLD),
                )
            }
        }
        crate::tui::app::FirewallDirection::Inbound => {
            if app.inbound_firewall_active {
                Span::styled(
                    format!("● {}: BLOCK (Default Mode)", dir_label),
                    Style::default()
                        .fg(palette.warning_orange)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    format!("● {}: ALLOW (Open Mode)", dir_label),
                    Style::default()
                        .fg(palette.allowed_green)
                        .add_modifier(Modifier::BOLD),
                )
            }
        }
    };

    let mut title_spans = vec![Span::styled(
        " it's.fw",
        Style::default()
            .fg(palette.border_focus)
            .add_modifier(Modifier::BOLD),
    )];

    if !app.is_admin {
        title_spans.push(Span::styled(" │ ", Style::default().fg(palette.border)));
        title_spans.push(Span::styled(
            "[READ-ONLY: NO ADMIN]",
            Style::default()
                .bg(palette.alert_red)
                .fg(palette.fg)
                .add_modifier(Modifier::BOLD),
        ));
    }

    title_spans.push(Span::styled(" │ ", Style::default().fg(palette.border)));
    title_spans.push(fw_status);

    if app.lockdown_active {
        title_spans.push(Span::styled(" │ ", Style::default().fg(palette.border)));
        title_spans.push(Span::styled(
            "[🚨 LOCKDOWN ACTIVE]",
            Style::default()
                .bg(palette.alert_red)
                .fg(palette.fg)
                .add_modifier(Modifier::BOLD),
        ));
    }

    if app.stream_paused {
        title_spans.push(Span::styled(" │ ", Style::default().fg(palette.border)));
        title_spans.push(Span::styled(
            "[⏸ PAUSED]",
            Style::default()
                .bg(palette.warning_orange)
                .fg(palette.surface)
                .add_modifier(Modifier::BOLD),
        ));
    }

    if let Some((ref msg, time)) = app.status_message {
        if time.elapsed().as_secs() < 5 {
            let msg_color = if msg.starts_with("DENIED")
                || msg.starts_with("ERROR")
                || msg.starts_with("NON-ADMIN")
            {
                palette.alert_red
            } else {
                palette.allowed_green
            };
            title_spans.push(Span::styled(" │ ", Style::default().fg(palette.border)));
            title_spans.push(Span::styled(
                msg,
                Style::default().fg(msg_color).add_modifier(Modifier::BOLD),
            ));
        }
    }

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(palette.border))
        .title_top(
            Line::from(Span::styled(
                format!(" {} ", env!("ITSFW_VERSION")),
                Style::default().fg(palette.fg_muted),
            ))
            .right_aligned(),
        );
    let paragraph = Paragraph::new(Line::from(title_spans)).block(header_block);
    f.render_widget(paragraph, area);
}

fn render_table(f: &mut Frame, app: &mut App, area: Rect) {
    let palette = app.current_palette();
    let filtered_apps = app.visible_apps();

    let knocking_label = if app.unseen_knocking_count() > 0 {
        format!("[2] Knocking ({} ●)", app.unseen_knocking_count())
    } else {
        "[2] Knocking".to_string()
    };

    let filter_tabs = [
        (ViewFilter::All, "[1] All"),
        (ViewFilter::KnockingOnly, knocking_label.as_str()),
        (ViewFilter::AllowedOnly, "[3] Allowed"),
        (ViewFilter::BlockedOnly, "[4] Blocked"),
    ];

    let mut list_title_spans = vec![Span::raw(" ")];
    for (i, (flt, label)) in filter_tabs.iter().enumerate() {
        if i > 0 {
            list_title_spans.push(Span::styled("   ", Style::default().fg(palette.border)));
        }
        if app.current_filter == *flt {
            list_title_spans.push(Span::styled(
                format!("● {} ({})", label, filtered_apps.len()),
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            list_title_spans.push(Span::styled(
                (*label).to_string(),
                Style::default().fg(palette.fg_muted),
            ));
        }
    }
    list_title_spans.push(Span::raw(" "));

    let table_border_style = if app.active_pane == crate::tui::app::ActivePane::Applications {
        Style::default().fg(palette.border_focus)
    } else {
        Style::default().fg(palette.border)
    };

    let sys_uwp_tag = if app.show_system_uwp {
        Span::styled(
            " [u] Sys/UWP: ON ",
            Style::default()
                .fg(palette.internet_cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" [u] Sys/UWP: off ", Style::default().fg(palette.fg_muted))
    };

    let table_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Line::from(list_title_spans))
        .title_top(Line::from(sys_uwp_tag).right_aligned())
        .border_style(table_border_style);

    let inner = table_block.inner(area);
    f.render_widget(table_block, area);

    if inner.height >= 2 {
        let table_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(inner);

        let (port_w, speed_w, vol_w, pps_w) = if inner.width < 100 {
            (8, 8, 8, 5)
        } else {
            (14, 10, 9, 7)
        };

        let (sort_col, is_asc) = app.sort_mode.column_indicator();
        let sort_arrow = if is_asc { " ▲" } else { " ▼" };
        let app_hdr = if sort_col == "APPLICATION" {
            format!("APPLICATION{}", sort_arrow)
        } else {
            "APPLICATION".to_string()
        };
        let hits_hdr = if sort_col == "HITS" {
            format!("HITS{}", sort_arrow)
        } else {
            "HITS".to_string()
        };
        let speed_hdr = if sort_col == "SPEED" {
            format!("SPEED{}", sort_arrow)
        } else {
            "SPEED".to_string()
        };
        let vol_hdr = if sort_col == "VOLUME" {
            format!("VOLUME{}", sort_arrow)
        } else {
            "VOLUME".to_string()
        };
        let pps_hdr = if sort_col == "P/S" {
            format!("P/S{}", sort_arrow)
        } else {
            "P/S".to_string()
        };

        // Фіксований заголовок колонок таблиці на 100% ширини
        let table_header = Line::from(vec![
            Span::raw("  "),
            Span::styled(
                fit_width(&app_hdr, 26),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width("STATUS", 10),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width("TRAFFIC", 9),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width("PORTS", port_w),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width(&hits_hdr, 6),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width(&speed_hdr, speed_w),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width(&vol_hdr, vol_w),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width(&pps_hdr, pps_w),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        f.render_widget(Paragraph::new(table_header), table_layout[0]);

        if filtered_apps.is_empty() {
            let empty_msg = Paragraph::new("  No applications detected yet. Scanning network...")
                .style(Style::default().fg(palette.fg_muted));
            f.render_widget(empty_msg, table_layout[1]);
        } else {
            let items: Vec<ListItem> = filtered_apps
                .iter()
                .enumerate()
                .map(|(idx, item)| {
                    let is_selected = idx == app.selected_index;

                    let configured_rule = app.rule_for_app_entry(item);
                    let is_explicit_block_rule = configured_rule
                        .map(|r| r.action == crate::core::rules::RuleAction::Block)
                        .unwrap_or(false);

                    let (indicator_str, indicator_color, status_text, status_color, is_bold) =
                        if is_explicit_block_rule {
                            ("● ", palette.alert_red, "DENY", palette.alert_red, true)
                        } else if item.is_knocking {
                            (
                                "▲ ",
                                palette.warning_orange,
                                "KNOCKING",
                                palette.warning_orange,
                                true,
                            )
                        } else if let Some(rule) = configured_rule {
                            match (rule.action, rule.zone_scope) {
                                (
                                    crate::core::rules::RuleAction::Allow,
                                    crate::core::rules::AllowedZoneScope::LanOnly,
                                ) => (
                                    "✓ ",
                                    palette.lan_yellow,
                                    "LAN ONLY",
                                    palette.lan_yellow,
                                    true,
                                ),
                                (crate::core::rules::RuleAction::Allow, _) => (
                                    "✓ ",
                                    palette.allowed_green,
                                    "ALLOW",
                                    palette.allowed_green,
                                    true,
                                ),
                                (crate::core::rules::RuleAction::Block, _) => {
                                    ("● ", palette.alert_red, "DENY", palette.alert_red, true)
                                }
                            }
                        } else {
                            ("○ ", palette.fg_muted, "ALLOW", palette.fg_muted, false)
                        };

                    let is_table_active =
                        app.active_pane == crate::tui::app::ActivePane::Applications;
                    let mut stat_style = Style::default().fg(status_color);
                    if is_bold {
                        stat_style = stat_style.add_modifier(Modifier::BOLD);
                    }

                    let zone_str = item.zones_display();
                    let zone_color = match zone_str {
                        "LAN+WAN" => palette.allowed_green,
                        "WAN" => palette.internet_cyan,
                        "LAN" => palette.lan_yellow,
                        _ => palette.fg_muted,
                    };

                    let port_str = item.ports_display();

                    let mut row_spans = vec![Span::styled(
                        indicator_str,
                        Style::default()
                            .fg(indicator_color)
                            .add_modifier(Modifier::BOLD),
                    )];
                    row_spans.extend(styled_app_name_spans(
                        &item.app_name,
                        26,
                        is_selected,
                        is_selected && !is_table_active,
                        &palette,
                    ));
                    row_spans.extend([
                        Span::raw(" "),
                        Span::styled(fit_width(status_text, 10), stat_style),
                        Span::raw(" "),
                        Span::styled(fit_width(zone_str, 9), Style::default().fg(zone_color)),
                        Span::raw(" "),
                        Span::styled(
                            fit_width(&port_str, port_w),
                            Style::default().fg(palette.port_purple),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            fit_width(&format!("{}", item.total_hits), 6),
                            Style::default().fg(palette.internet_cyan),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            fit_width(
                                &crate::core::monitor::format_speed(
                                    item.current_speed_bytes_per_sec,
                                ),
                                speed_w,
                            ),
                            Style::default().fg(palette.fg_muted),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            fit_width(
                                &crate::core::monitor::format_bytes(
                                    item.total_rx_bytes.saturating_add(item.total_tx_bytes),
                                ),
                                vol_w,
                            ),
                            Style::default().fg(palette.fg_muted),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            fit_width(&item.packets_per_sec_display(), pps_w),
                            Style::default().fg(palette.fg_muted),
                        ),
                    ]);

                    let line = Line::from(row_spans);

                    let item_style = if is_selected && is_table_active {
                        Style::default().bg(palette.surface)
                    } else {
                        Style::default()
                    };

                    ListItem::new(line).style(item_style)
                })
                .collect();

            let list_widget = List::new(items);
            let mut list_state = ListState::default().with_selected(Some(app.selected_index));
            f.render_stateful_widget(list_widget, table_layout[1], &mut list_state);
        }
    }
}

fn render_bottom_split(f: &mut Frame, app: &mut App, area: Rect) {
    let palette = app.current_palette();
    let selected_app = app
        .visible_apps()
        .get(app.selected_index)
        .map(|s| (*s).clone());

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let details_border_color = if app.active_pane == crate::tui::app::ActivePane::ProcessDetails {
        palette.border_focus
    } else {
        palette.border
    };

    let mut details_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            " Process Details ",
            Style::default()
                .fg(palette.border_focus)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(details_border_color));
    if app.active_pane == crate::tui::app::ActivePane::ProcessDetails {
        let hint = match app.details_focused_field {
            crate::tui::app::ProcessDetailsField::Policy => " [Enter: Edit  Ctrl+Enter: wf.msc] ",
            crate::tui::app::ProcessDetailsField::App => " [Enter: Copy Info] ",
            crate::tui::app::ProcessDetailsField::Desc => " [Enter: Copy Desc] ",
            crate::tui::app::ProcessDetailsField::Path => " [Enter: Copy  Ctrl+Enter: Explorer] ",
            crate::tui::app::ProcessDetailsField::Args => " [Enter: View All] ",
        };
        details_block = details_block.title_bottom(
            Line::from(Span::styled(
                hint,
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .right_aligned(),
        );
    }

    if let Some(selected_app) = selected_app {
        let parent_display = match &selected_app.parent_process_name {
            Some(p) => format!("{} (PID: {})", p, selected_app.process_id),
            None => {
                if selected_app.process_id > 0 {
                    format!("PID: {}", selected_app.process_id)
                } else {
                    "Not running".into()
                }
            }
        };

        let configured_rule = app.rule_for_app_entry(&selected_app).cloned();
        let is_explicit_block_rule = configured_rule
            .as_ref()
            .map(|r| r.action == crate::core::rules::RuleAction::Block)
            .unwrap_or(false);

        let (rule_display, rule_color) = if is_explicit_block_rule {
            ("DENY (Explicit Firewall Rule)", palette.alert_red)
        } else if selected_app.is_knocking {
            (
                "KNOCKING (Packets Dropped by Firewall)",
                palette.warning_orange,
            )
        } else if let Some(ref rule) = configured_rule {
            match (rule.action, rule.zone_scope) {
                (
                    crate::core::rules::RuleAction::Allow,
                    crate::core::rules::AllowedZoneScope::LanOnly,
                ) => ("LAN ONLY (Explicit Rule)", palette.lan_yellow),
                (
                    crate::core::rules::RuleAction::Allow,
                    crate::core::rules::AllowedZoneScope::InternetOnly,
                ) => ("INT ONLY (Explicit Rule)", palette.internet_cyan),
                (crate::core::rules::RuleAction::Allow, _) => {
                    ("ALLOW (Explicit Rule)", palette.allowed_green)
                }
                (crate::core::rules::RuleAction::Block, _) => {
                    ("DENY (Explicit Rule)", palette.alert_red)
                }
            }
        } else {
            ("ALLOW (Default Policy)", palette.fg_muted)
        };

        let composite_key = crate::core::rules::make_app_key(
            &selected_app.app_path,
            selected_app.service_name.as_deref(),
            selected_app.direction,
        );
        let path_lower = selected_app.app_path.to_lowercase();
        let verified_rule_name = app.verified_fw_rules.get(&composite_key).or_else(|| {
            if selected_app.direction == crate::core::rules::RuleDirection::Outbound
                && selected_app.service_name.is_none()
            {
                app.verified_fw_rules.get(&path_lower)
            } else {
                None
            }
        });
        let (fw_sync_status, fw_sync_color) = if let Some(rule_name) = verified_rule_name {
            (format!("✓ ENFORCED ({})", rule_name), palette.allowed_green)
        } else if is_explicit_block_rule {
            (
                "● BLOCKED (Active Rule in Windows Firewall)".into(),
                palette.alert_red,
            )
        } else if selected_app.is_knocking {
            (
                "▲ DROPPED (Blocked by Default Outbound / Zone Policy)".into(),
                palette.warning_orange,
            )
        } else if configured_rule.is_some() {
            (
                "✓ ENFORCED (Active in Windows Firewall)".into(),
                palette.allowed_green,
            )
        } else {
            (
                "○ UNMANAGED (Standard Windows Policy)".into(),
                palette.fg_muted,
            )
        };

        let meta =
            app.get_or_load_metadata_with_pid(&selected_app.app_path, selected_app.process_id);
        let desc_display = meta.description.as_deref().unwrap_or("-");
        let sign_badge = meta.signature.badge();
        let sign_color = match meta.signature {
            crate::core::process::SignatureStatus::Verified(_) => palette.allowed_green,
            crate::core::process::SignatureStatus::Unsigned => palette.warning_orange,
            crate::core::process::SignatureStatus::Untrusted => palette.alert_red,
            crate::core::process::SignatureStatus::Unknown => palette.fg_muted,
        };

        let is_in_details = app.active_pane == crate::tui::app::ActivePane::ProcessDetails;
        let pfx = |field: crate::tui::app::ProcessDetailsField| -> &'static str {
            if is_in_details && app.details_focused_field == field {
                "▶ "
            } else {
                "  "
            }
        };
        let row_bg = |field: crate::tui::app::ProcessDetailsField| -> Style {
            if is_in_details && app.details_focused_field == field {
                Style::default().bg(palette.surface)
            } else {
                Style::default()
            }
        };

        let target_kind = crate::core::rules::RuleTargetKind::from_app_path(&selected_app.app_path);
        let now_ts = crate::core::monitor::current_timestamp_secs() as i64;
        let zone_str = selected_app.zones_display();
        let zone_color = match zone_str {
            "LAN+WAN" => palette.allowed_green,
            "WAN" => palette.internet_cyan,
            "LAN" => palette.lan_yellow,
            _ => palette.fg_muted,
        };

        // Row 1: Policy & Zone
        let mut row1_spans = vec![Span::styled(
            pfx(crate::tui::app::ProcessDetailsField::Policy),
            Style::default()
                .fg(palette.internet_cyan)
                .add_modifier(Modifier::BOLD),
        )];
        if let Some(ref svc) = selected_app.service_name {
            row1_spans.push(Span::styled(
                "Service: ",
                Style::default().fg(palette.fg_muted),
            ));
            row1_spans.push(Span::styled(
                svc,
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ));
            row1_spans.push(Span::styled(
                "  │  Policy: ",
                Style::default().fg(palette.fg_muted),
            ));
            row1_spans.push(Span::styled(
                rule_display,
                Style::default().fg(rule_color).add_modifier(Modifier::BOLD),
            ));
        } else {
            row1_spans.push(Span::styled(
                "Policy: ",
                Style::default().fg(palette.fg_muted),
            ));
            row1_spans.push(Span::styled(
                rule_display,
                Style::default().fg(rule_color).add_modifier(Modifier::BOLD),
            ));
        }
        if let Some(ref rule) = configured_rule {
            if let Some(rem) = rule.remaining_display(now_ts) {
                row1_spans.push(Span::styled(
                    format!(" ({})", rem),
                    Style::default()
                        .fg(palette.lan_yellow)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        }
        if let Some(custom_ip) = configured_rule
            .as_ref()
            .and_then(|r| r.custom_remote_ip.as_deref())
            .filter(|_| target_kind != crate::core::rules::RuleTargetKind::App)
        {
            row1_spans.push(Span::styled(
                "  │  Scope: ",
                Style::default().fg(palette.fg_muted),
            ));
            row1_spans.push(Span::styled(
                fit_width(custom_ip, 22),
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            row1_spans.push(Span::styled(
                "  │  Zone: ",
                Style::default().fg(palette.fg_muted),
            ));
            row1_spans.push(Span::styled(
                zone_str,
                Style::default().fg(zone_color).add_modifier(Modifier::BOLD),
            ));
        }
        let (row2_spans, row3_spans, row4_spans, row5_spans) =
            if target_kind == crate::core::rules::RuleTargetKind::App {
                // Row 2: App & Parent
                let r2 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::App),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("App: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        &selected_app.app_name,
                        Style::default()
                            .fg(palette.border_focus)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(" ({}) │ Parent: ", selected_app.process_id),
                        Style::default().fg(palette.fg_muted),
                    ),
                    Span::styled(parent_display, Style::default().fg(palette.internet_cyan)),
                ];

                // Row 3: Desc & Signature
                let mut r3 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::Desc),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Desc: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(fit_width(desc_display, 24), Style::default().fg(palette.fg)),
                    Span::styled("  │  Sign: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        sign_badge,
                        Style::default().fg(sign_color).add_modifier(Modifier::BOLD),
                    ),
                ];
                if meta.is_suspicious_path {
                    r3.push(Span::styled(
                        " [⚠ SUSPICIOUS PATH]",
                        Style::default()
                            .bg(palette.alert_red)
                            .fg(palette.fg)
                            .add_modifier(Modifier::BOLD),
                    ));
                }

                // Row 4: Path
                let r4 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::Path),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Path: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        fit_width(
                            &selected_app.app_path,
                            cols[0].width.saturating_sub(10) as usize,
                        ),
                        Style::default().fg(palette.fg),
                    ),
                ];

                // Row 5: Args (Single row, pure arguments without redundant binary path)
                let (clean_args, _flags) = meta
                    .command_line
                    .as_deref()
                    .map(crate::core::process::extract_process_arguments)
                    .unwrap_or((None, Vec::new()));
                let args_display = clean_args.unwrap_or_else(|| "(none)".to_string());
                let max_args_w = cols[0].width.saturating_sub(10) as usize;
                let r5 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::Args),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Args: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        fit_width(&args_display, max_args_w),
                        Style::default().fg(palette.fg),
                    ),
                ];

                (r2, r3, r4, r5)
            } else {
                let engine_label = match target_kind {
                    crate::core::rules::RuleTargetKind::HyperV => "Hyper-V Firewall (WSL)",
                    crate::core::rules::RuleTargetKind::PortRule => "Windows Firewall (Port)",
                    crate::core::rules::RuleTargetKind::Uwp => "Windows Firewall (UWP)",
                    crate::core::rules::RuleTargetKind::App => "",
                };
                let r2 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::App),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Name: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        fit_width(&selected_app.app_name, 22),
                        Style::default()
                            .fg(palette.border_focus)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" │ ", Style::default().fg(palette.fg_muted)),
                    Span::styled(engine_label, Style::default().fg(palette.internet_cyan)),
                ];

                let ports_str = configured_rule
                    .as_ref()
                    .map(|r| r.ports.clone())
                    .unwrap_or_else(|| selected_app.all_ports_list());
                let r3 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::Desc),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Proto: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        selected_app.protocols_display(),
                        Style::default()
                            .fg(palette.port_purple)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("  │  Ports: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(fit_width(&ports_str, 24), Style::default().fg(palette.fg)),
                ];

                let remote_str = configured_rule
                    .as_ref()
                    .and_then(|r| r.custom_remote_ip.as_deref())
                    .unwrap_or("Any");
                let r4 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::Path),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Remote IP: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        fit_width(remote_str, cols[0].width.saturating_sub(16) as usize),
                        Style::default().fg(palette.fg),
                    ),
                ];

                let rule_id_str = configured_rule
                    .as_ref()
                    .and_then(|r| r.rule_id.as_deref())
                    .unwrap_or(&selected_app.app_path);
                let r5 = vec![
                    Span::styled(
                        pfx(crate::tui::app::ProcessDetailsField::Args),
                        Style::default()
                            .fg(palette.internet_cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("Rule ID: ", Style::default().fg(palette.fg_muted)),
                    Span::styled(
                        fit_width(rule_id_str, cols[0].width.saturating_sub(14) as usize),
                        Style::default().fg(palette.fg_muted),
                    ),
                ];

                (r2, r3, r4, r5)
            };

        // Row 6: Windows / Hyper-V Firewall enforcement status
        let fw_label = if target_kind == crate::core::rules::RuleTargetKind::HyperV {
            "Hyper-V FW: "
        } else {
            "Win Firewall: "
        };
        let row6_spans = vec![
            Span::raw("  "),
            Span::styled(fw_label, Style::default().fg(palette.fg_muted)),
            Span::styled(
                fw_sync_status,
                Style::default()
                    .fg(fw_sync_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ];

        let detail_lines = vec![
            Line::from(row1_spans).style(row_bg(crate::tui::app::ProcessDetailsField::Policy)),
            Line::from(row2_spans).style(row_bg(crate::tui::app::ProcessDetailsField::App)),
            Line::from(row3_spans).style(row_bg(crate::tui::app::ProcessDetailsField::Desc)),
            Line::from(row4_spans).style(row_bg(crate::tui::app::ProcessDetailsField::Path)),
            Line::from(row5_spans).style(row_bg(crate::tui::app::ProcessDetailsField::Args)),
            Line::from(row6_spans),
        ];

        let detail_para = Paragraph::new(detail_lines).block(details_block);
        f.render_widget(detail_para, cols[0]);

        // Права половинка: Recent Activity (до 5 подій)
        let count = selected_app.recent_events.len().min(5);
        let activity_title = format!(" Recent Activity ({}) ", count);
        let is_in_recent = app.active_pane == crate::tui::app::ActivePane::RecentActivity;
        let activity_border_color = if is_in_recent {
            palette.border_focus
        } else {
            palette.border
        };
        let mut activity_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(Span::styled(
                activity_title,
                Style::default()
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(activity_border_color));
        if is_in_recent {
            activity_block = activity_block.title_bottom(
                Line::from(Span::styled(
                    " [Enter: Copy  e: Rule] ",
                    Style::default()
                        .fg(palette.internet_cyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .right_aligned(),
            );
        }

        let mut event_lines = Vec::new();
        for (idx, event) in selected_app.recent_events.iter().rev().take(5).enumerate() {
            let is_row_sel = is_in_recent && idx == app.recent_selected_index;
            let (badge, act_color) = if event.is_blocked {
                ("[DROP]", palette.alert_red)
            } else {
                ("[PASS]", palette.allowed_green)
            };
            let (zone_badge, zone_color) = match event.zone {
                Zone::Lan => ("[LAN]", palette.lan_yellow),
                Zone::Internet => ("[WAN]", palette.internet_cyan),
            };
            let domain = if event.remote_ip.is_loopback() {
                crate::core::scanner::lookup_loopback_peer(event.remote_port, &event.protocol)
                    .or_else(|| {
                        app.listening_sockets
                            .iter()
                            .find(|s| {
                                s.port == event.remote_port
                                    && s.protocol.eq_ignore_ascii_case(&event.protocol)
                            })
                            .map(|s| format!("-> {}", s.process_name))
                    })
                    .or_else(|| app.dns_resolver.resolve_or_enqueue(event.remote_ip))
            } else {
                app.dns_resolver.resolve_or_enqueue(event.remote_ip)
            };
            let extra_info = match domain.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(d) if d.starts_with("->") || d.starts_with('(') => d.to_string(),
                Some(d) => format!("({})", d),
                None => String::new(),
            };
            let endpoint = format!("{}:{}", event.remote_ip, event.remote_port);
            let proto = event.protocol.to_uppercase();

            let mut spans = Vec::new();
            if is_in_recent {
                spans.push(Span::styled(
                    if is_row_sel { "▶ " } else { "  " },
                    Style::default()
                        .fg(palette.border_focus)
                        .add_modifier(Modifier::BOLD),
                ));
            }
            spans.extend([
                Span::styled(
                    badge,
                    Style::default().fg(act_color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(zone_badge, Style::default().fg(zone_color)),
                Span::raw("  "),
                Span::styled(fit_width(&endpoint, 21), Style::default().fg(palette.fg)),
                Span::raw(" "),
                Span::styled(fit_width(&proto, 4), Style::default().fg(palette.fg)),
            ]);
            if !extra_info.is_empty() {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(
                    extra_info,
                    Style::default().fg(palette.fg_muted),
                ));
            }
            let line = if is_row_sel {
                Line::from(spans).style(Style::default().bg(palette.surface))
            } else {
                Line::from(spans)
            };
            event_lines.push(line);
        }

        if event_lines.is_empty() {
            let empty_act = Paragraph::new("No recent activity recorded for this process.")
                .style(Style::default().fg(palette.fg_muted))
                .block(activity_block);
            f.render_widget(empty_act, cols[1]);
        } else {
            let act_para = Paragraph::new(event_lines).block(activity_block);
            f.render_widget(act_para, cols[1]);
        }
    } else {
        let empty_msg = Paragraph::new("No process selected.")
            .style(Style::default().fg(palette.fg_muted))
            .block(details_block);
        f.render_widget(empty_msg, cols[0]);

        let empty_act_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(Span::styled(
                " Recent Activity (0) ",
                Style::default()
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(palette.border));
        let empty_act = Paragraph::new("No recent activity.")
            .style(Style::default().fg(palette.fg_muted))
            .block(empty_act_block);
        f.render_widget(empty_act, cols[1]);
    }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let palette = app.current_palette();

    let shortcuts = if app.is_admin {
        Line::from(vec![
            Span::styled(
                "[Tab] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("mode  "),
            Span::styled(
                "[f] ",
                Style::default()
                    .fg(palette.warning_orange)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("policy  "),
            Span::styled(
                "[n] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("new  "),
            Span::styled(
                "[a] ",
                Style::default()
                    .fg(palette.allowed_green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("allow  "),
            Span::styled(
                "[l] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("lan  "),
            Span::styled(
                "[i] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("wan  "),
            Span::styled(
                "[d] ",
                Style::default()
                    .fg(palette.alert_red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("deny  "),
            Span::styled(
                "[x] ",
                Style::default()
                    .fg(palette.warning_orange)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("reset  "),
            Span::styled(
                "[/] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("find  "),
            Span::styled(
                "[s] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("sort  "),
            Span::styled(
                "[q] ",
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("quit"),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "[READ-ONLY] ",
                Style::default()
                    .bg(palette.surface)
                    .fg(palette.alert_red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("│ "),
            Span::styled(
                "[Tab] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("switch mode │ "),
            Span::styled(
                "[/] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("search │ "),
            Span::styled(
                "[1-4] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("filter │ "),
            Span::styled(
                "[s] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("sort │ "),
            Span::styled(
                "[q] ",
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("quit"),
        ])
    };

    let footer_p = Paragraph::new(shortcuts);
    f.render_widget(footer_p, area);
}

fn render_search_or_listener_overlay(f: &mut Frame, app: &App) {
    if !app.search_active {
        return;
    }

    let palette = app.current_palette();
    let area = f.area();

    if app.listening_mode {
        // Modal Listening Ports Inspector
        let width = 90.min(area.width.saturating_sub(4));
        let height = 18.min(area.height.saturating_sub(4));
        let popup_area = Rect {
            x: (area.width.saturating_sub(width)) / 2,
            y: (area.height.saturating_sub(height)) / 2,
            width,
            height,
        };

        f.render_widget(Clear, popup_area);

        let filter_text = if app.search_query.len() > 1 {
            format!(" [Filter: {}] ", &app.search_query[1..])
        } else {
            String::new()
        };

        let modal_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(Span::styled(
                format!(" Listening Ports Inspector (netstat){} ", filter_text),
                Style::default()
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(palette.border_focus))
            .style(Style::default().bg(palette.surface));

        let inner = modal_block.inner(popup_area);
        f.render_widget(modal_block, popup_area);

        if inner.height >= 3 {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(1),
                    Constraint::Length(1),
                ])
                .split(inner);

            let header = Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    fit_width("PORT", 8),
                    Style::default()
                        .fg(palette.fg_muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    fit_width("PROTO", 6),
                    Style::default()
                        .fg(palette.fg_muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    fit_width("PID", 8),
                    Style::default()
                        .fg(palette.fg_muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    fit_width("PROCESS", 22),
                    Style::default()
                        .fg(palette.fg_muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    "PATH",
                    Style::default()
                        .fg(palette.fg_muted)
                        .add_modifier(Modifier::BOLD),
                ),
            ]);
            f.render_widget(Paragraph::new(header), layout[0]);

            let listeners = app.filtered_listening_sockets();
            if listeners.is_empty() {
                let empty_msg = Paragraph::new("  No listening sockets matching filter")
                    .style(Style::default().fg(palette.fg_muted));
                f.render_widget(empty_msg, layout[1]);
            } else {
                let items: Vec<ListItem> = listeners
                    .iter()
                    .enumerate()
                    .map(|(idx, s)| {
                        let is_sel = idx == app.listening_selected_index;
                        let line = Line::from(vec![
                            Span::styled(
                                if is_sel { "▶ " } else { "  " },
                                Style::default().fg(palette.warning_orange),
                            ),
                            Span::styled(
                                fit_width(&format!(":{}", s.port), 8),
                                Style::default()
                                    .fg(palette.port_purple)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(" "),
                            Span::styled(
                                fit_width(&s.protocol, 6),
                                Style::default().fg(palette.internet_cyan),
                            ),
                            Span::raw(" "),
                            Span::styled(
                                fit_width(&s.pid.to_string(), 8),
                                Style::default().fg(palette.fg_muted),
                            ),
                            Span::raw(" "),
                            Span::styled(
                                fit_width(&s.process_name, 22),
                                Style::default()
                                    .fg(if is_sel {
                                        palette.border_focus
                                    } else {
                                        palette.fg
                                    })
                                    .add_modifier(if is_sel {
                                        Modifier::BOLD
                                    } else {
                                        Modifier::empty()
                                    }),
                            ),
                            Span::raw(" "),
                            Span::styled(&s.app_path, Style::default().fg(palette.fg_muted)),
                        ]);
                        let item_style = if is_sel {
                            Style::default().bg(palette.surface)
                        } else {
                            Style::default()
                        };
                        ListItem::new(line).style(item_style)
                    })
                    .collect();

                let list = List::new(items);
                let mut state =
                    ListState::default().with_selected(Some(app.listening_selected_index));
                f.render_stateful_widget(list, layout[1], &mut state);
            }

            let footer = Line::from(vec![
                Span::styled(
                    " [a] ",
                    Style::default()
                        .fg(palette.allowed_green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Allow In  "),
                Span::styled(
                    " [l] ",
                    Style::default()
                        .fg(palette.lan_yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("LAN Only In  "),
                Span::styled(
                    " [i] ",
                    Style::default()
                        .fg(palette.internet_cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Int Only In  "),
                Span::styled(
                    " [d] ",
                    Style::default()
                        .fg(palette.alert_red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Block In  "),
                Span::styled(
                    " [k] ",
                    Style::default()
                        .fg(palette.alert_red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Kill PID  "),
                Span::styled(
                    " [↑/↓] ",
                    Style::default()
                        .fg(palette.lan_yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Navigate  "),
                Span::styled(
                    " [Esc] ",
                    Style::default()
                        .fg(palette.fg_muted)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Close  "),
            ]);
            f.render_widget(Paragraph::new(footer), layout[2]);
        }
    } else {
        // Compact search bar floating top right
        let width = 36.min(area.width.saturating_sub(4));
        let height = 3;
        let search_area = Rect {
            x: area.width.saturating_sub(width + 2),
            y: 0,
            width,
            height,
        };

        f.render_widget(Clear, search_area);

        let search_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(Span::styled(
                " Search [/] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(palette.border_focus))
            .style(Style::default().bg(palette.surface));

        let p = Paragraph::new(Line::from(vec![
            Span::raw(" /"),
            Span::styled(
                &app.search_query,
                Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
            ),
            Span::styled("█", Style::default().fg(palette.internet_cyan)),
        ]))
        .block(search_block);

        f.render_widget(p, search_area);
    }
}

fn render_sort_modal(f: &mut Frame, app: &App) {
    let palette = app.current_palette();
    let area = f.area();

    let width = 52.min(area.width.saturating_sub(4));
    let height = 12.min(area.height.saturating_sub(4));
    let popup_area = Rect {
        x: 4.min(area.width.saturating_sub(width)),
        y: 4.min(area.height.saturating_sub(height)),
        width,
        height,
    };

    f.render_widget(Clear, popup_area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            " Sort Applications [j/k, 1-8, Enter, Esc] ",
            Style::default()
                .fg(palette.border_focus)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(palette.border_focus))
        .style(Style::default().bg(palette.surface));

    let mut lines: Vec<Line> = crate::tui::app::SORT_MENU_OPTIONS
        .iter()
        .enumerate()
        .map(|(idx, opt)| {
            let is_cursor = idx == app.sort_menu_index;
            let is_active = idx == app.sort_mode.menu_index();
            let bullet = if is_active { "●" } else { " " };
            let display_label = if is_active {
                app.sort_mode.label()
            } else {
                opt.default_mode.label()
            };
            let prefix = format!(" {} [{}] {} ", bullet, idx + 1, display_label);
            let style = if is_cursor {
                Style::default()
                    .bg(palette.border)
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(palette.fg)
            };
            Line::from(Span::styled(
                fit_width(&prefix, (width.saturating_sub(2)) as usize),
                style,
            ))
        })
        .collect();

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        " Order is pinned on selection (no list jumping)",
        Style::default().fg(palette.fg_muted),
    )));

    let p = Paragraph::new(lines).block(modal_block);
    f.render_widget(p, popup_area);
}

fn render_args_modal(f: &mut Frame, app: &App) {
    let palette = app.current_palette();
    let area = f.area();

    let width = 74.min(area.width.saturating_sub(4));
    let height = 18.min(area.height.saturating_sub(4));
    let popup_area = Rect {
        x: (area.width.saturating_sub(width)) / 2,
        y: (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    f.render_widget(Clear, popup_area);

    let visible = app.visible_apps();
    let selected_app = visible.get(app.selected_index);
    let app_title = selected_app
        .map(|a| a.app_name.as_str())
        .unwrap_or("Process");
    let pid_str = selected_app.map(|a| a.process_id).unwrap_or(0);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            format!(" Arguments: {} (PID: {}) ", app_title, pid_str),
            Style::default()
                .fg(palette.border_focus)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(palette.border_focus))
        .style(Style::default().bg(palette.surface));

    let inner = modal_block.inner(popup_area);
    f.render_widget(modal_block, popup_area);

    let mut lines = Vec::new();

    let cmd_line_opt = selected_app.and_then(|a| {
        let key = a.app_path.to_lowercase();
        app.metadata_cache
            .get(&key)
            .and_then(|m| m.command_line.clone())
    });

    if let Some(cmd) = cmd_line_opt {
        let (pure_args, flags) = crate::core::process::extract_process_arguments(&cmd);
        lines.push(Line::from(vec![
            Span::styled("Command: ", Style::default().fg(palette.fg_muted)),
            Span::styled(cmd, Style::default().fg(palette.fg)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("Parsed Flags ({} item(s)):", flags.len()),
            Style::default()
                .fg(palette.internet_cyan)
                .add_modifier(Modifier::BOLD),
        )));

        if flags.is_empty() {
            if let Some(a) = pure_args {
                lines.push(Line::from(vec![
                    Span::styled("  [1] ", Style::default().fg(palette.fg_muted)),
                    Span::styled(a, Style::default().fg(palette.fg)),
                ]));
            } else {
                lines.push(Line::from(Span::styled(
                    "  (no additional arguments)",
                    Style::default().fg(palette.fg_muted),
                )));
            }
        } else {
            for (idx, flag) in flags.iter().enumerate() {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  [{}] ", idx + 1),
                        Style::default().fg(palette.fg_muted),
                    ),
                    Span::styled(flag.clone(), Style::default().fg(palette.fg)),
                ]));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No command line arguments detected for this process.",
            Style::default().fg(palette.fg_muted),
        )));
    }

    lines.push(Line::raw(""));

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let max_scroll = lines.len().saturating_sub(inner_chunks[0].height as usize);
    let scroll = app.args_modal_scroll.min(max_scroll);
    let visible_lines: Vec<Line> = lines.into_iter().skip(scroll).collect();
    let para = Paragraph::new(visible_lines);
    f.render_widget(para, inner_chunks[0]);

    let footer_line = Line::from(vec![
        Span::styled(
            "[Enter]",
            Style::default()
                .fg(palette.allowed_green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(": Copy & Close   ", Style::default().fg(palette.fg_muted)),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(palette.alert_red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(": Close   ", Style::default().fg(palette.fg_muted)),
        Span::styled(
            "[↑/↓/j/k]",
            Style::default()
                .fg(palette.internet_cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(": Scroll", Style::default().fg(palette.fg_muted)),
    ]);
    f.render_widget(Paragraph::new(footer_line), inner_chunks[1]);
}

fn render_edit_modal(f: &mut Frame, app: &App) {
    let palette = app.current_palette();
    let area = f.area();

    let width = 78.min(area.width.saturating_sub(4));
    let height = 17.min(area.height.saturating_sub(2));
    let popup_area = Rect {
        x: (area.width.saturating_sub(width)) / 2,
        y: (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    f.render_widget(Clear, popup_area);

    let modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            " Custom Rule Editor [Enter: Save, Del: Reset, Esc: Cancel] ",
            Style::default()
                .fg(palette.border_focus)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(palette.border_focus))
        .style(Style::default().bg(palette.surface));

    let focus_cursor = |field: RuleEditorField| -> (&'static str, Style) {
        if app.edit_focused_field == field {
            (
                "▶ ",
                Style::default()
                    .fg(palette.warning_orange)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            ("  ", Style::default().fg(palette.fg_muted))
        }
    };

    let opt_style = |selected: bool| -> Style {
        if selected {
            Style::default()
                .fg(palette.internet_cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(palette.fg_muted)
        }
    };

    use crate::core::rules::{AllowedZoneScope, RuleAction, RuleDirection, RuleDuration};
    let mut lines = Vec::new();

    // Target Kind selector field
    let (cur, cur_style) = focus_cursor(RuleEditorField::TargetKind);
    let mut target_spans = vec![
        Span::styled(cur, cur_style),
        Span::styled("Target:      ", Style::default().fg(palette.fg)),
    ];
    if crate::core::rules::RuleTargetKind::from_app_path(&app.edit_app_path)
        == crate::core::rules::RuleTargetKind::App
        && !app.edit_app_path.is_empty()
    {
        target_spans.extend([
            Span::styled(
                "[App (.exe)]",
                opt_style(app.edit_target_option == EditorTargetOption::App),
            ),
            Span::raw(" "),
            Span::styled(
                "[Port Rule]",
                opt_style(app.edit_target_option == EditorTargetOption::PortRule),
            ),
            Span::raw(" "),
            Span::styled(
                "[Hyper-V / WSL]",
                opt_style(app.edit_target_option == EditorTargetOption::HyperV),
            ),
            Span::raw(" "),
            Span::styled(
                "[Both]",
                opt_style(app.edit_target_option == EditorTargetOption::BothWinAndHyperV),
            ),
        ]);
    } else if app.edit_target_option == EditorTargetOption::Uwp {
        target_spans.push(Span::styled("[UWP Package]", opt_style(true)));
    } else {
        target_spans.extend([
            Span::styled(
                "[Port Rule (Win FW)]",
                opt_style(app.edit_target_option == EditorTargetOption::PortRule),
            ),
            Span::raw(" "),
            Span::styled(
                "[Hyper-V / WSL]",
                opt_style(app.edit_target_option == EditorTargetOption::HyperV),
            ),
            Span::raw(" "),
            Span::styled(
                "[Both (Win FW + WSL)]",
                opt_style(app.edit_target_option == EditorTargetOption::BothWinAndHyperV),
            ),
        ]);
    }
    lines.push(Line::from(target_spans));

    // App path OR Rule Name line
    if matches!(
        app.edit_target_option,
        EditorTargetOption::App | EditorTargetOption::Uwp
    ) {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("App:         ", Style::default().fg(palette.fg_muted)),
            Span::styled(
                fit_width(&app.edit_app_path, (width.saturating_sub(18)) as usize),
                Style::default()
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    } else {
        let (cur, cur_style) = focus_cursor(RuleEditorField::RuleName);
        let cursor_char = if app.edit_focused_field == RuleEditorField::RuleName {
            "█"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(cur, cur_style),
            Span::styled("Rule Name:   ", Style::default().fg(palette.fg)),
            Span::styled(
                &app.edit_rule_name,
                Style::default()
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(cursor_char, Style::default().fg(palette.warning_orange)),
        ]));
    }

    // Action field
    let (cur, cur_style) = focus_cursor(RuleEditorField::Action);
    lines.push(Line::from(vec![
        Span::styled(cur, cur_style),
        Span::styled("Action:      ", Style::default().fg(palette.fg)),
        Span::styled("[Allow]", opt_style(app.edit_action == RuleAction::Allow)),
        Span::raw("  "),
        Span::styled("[Block]", opt_style(app.edit_action == RuleAction::Block)),
    ]));

    // Direction field
    let (cur, cur_style) = focus_cursor(RuleEditorField::Direction);
    lines.push(Line::from(vec![
        Span::styled(cur, cur_style),
        Span::styled("Direction:   ", Style::default().fg(palette.fg)),
        Span::styled(
            "[Outbound]",
            opt_style(app.edit_direction == RuleDirection::Outbound),
        ),
        Span::raw("  "),
        Span::styled(
            "[Inbound]",
            opt_style(app.edit_direction == RuleDirection::Inbound),
        ),
    ]));

    // Duration field
    let (cur, cur_style) = focus_cursor(RuleEditorField::Duration);
    lines.push(Line::from(vec![
        Span::styled(cur, cur_style),
        Span::styled("Duration:    ", Style::default().fg(palette.fg)),
        Span::styled(
            "[Permanent]",
            opt_style(app.edit_duration == RuleDuration::Permanent),
        ),
        Span::raw(" "),
        Span::styled(
            "[5m]",
            opt_style(app.edit_duration == RuleDuration::Minutes5),
        ),
        Span::raw(" "),
        Span::styled(
            "[15m]",
            opt_style(app.edit_duration == RuleDuration::Minutes15),
        ),
        Span::raw(" "),
        Span::styled("[1h]", opt_style(app.edit_duration == RuleDuration::Hour1)),
        Span::raw(" "),
        Span::styled(
            "[Until Exit]",
            opt_style(app.edit_duration == RuleDuration::UntilExit),
        ),
    ]));

    // Zone / Scope field
    let (cur, cur_style) = focus_cursor(RuleEditorField::ZoneScope);
    lines.push(Line::from(vec![
        Span::styled(cur, cur_style),
        Span::styled("Zone / Scope:", Style::default().fg(palette.fg)),
        Span::raw(" "),
        Span::styled(
            "[All (LAN+WAN)]",
            opt_style(!app.edit_custom_ip_mode && app.edit_zone_scope == AllowedZoneScope::Both),
        ),
        Span::raw(" "),
        Span::styled(
            "[LAN Only]",
            opt_style(!app.edit_custom_ip_mode && app.edit_zone_scope == AllowedZoneScope::LanOnly),
        ),
        Span::raw(" "),
        Span::styled(
            "[WAN Only]",
            opt_style(
                !app.edit_custom_ip_mode && app.edit_zone_scope == AllowedZoneScope::InternetOnly,
            ),
        ),
        Span::raw(" "),
        Span::styled("[Custom IP]", opt_style(app.edit_custom_ip_mode)),
    ]));

    // Custom IP field (if Custom IP mode is active)
    if app.edit_custom_ip_mode {
        let (cur, cur_style) = focus_cursor(RuleEditorField::CustomIp);
        let cursor_char = if app.edit_focused_field == RuleEditorField::CustomIp {
            "█"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(cur, cur_style),
            Span::styled("Custom IP:   ", Style::default().fg(palette.fg)),
            Span::styled(
                &app.edit_custom_ip,
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(cursor_char, Style::default().fg(palette.warning_orange)),
            Span::styled(
                " (e.g. 1.1.1.1 or 192.168.1.0/24)",
                Style::default().fg(palette.fg_muted),
            ),
        ]));
    }

    // Protocol field
    let (cur, cur_style) = focus_cursor(RuleEditorField::Protocol);
    let proto_cur = app.edit_protocol.to_uppercase();
    lines.push(Line::from(vec![
        Span::styled(cur, cur_style),
        Span::styled("Protocol:    ", Style::default().fg(palette.fg)),
        Span::styled("[TCP]", opt_style(proto_cur == "TCP")),
        Span::raw("  "),
        Span::styled("[UDP]", opt_style(proto_cur == "UDP")),
        Span::raw("  "),
        Span::styled("[Any]", opt_style(proto_cur == "ANY")),
    ]));

    // Ports field (if Protocol is not ANY)
    if proto_cur != "ANY" {
        let (cur, cur_style) = focus_cursor(RuleEditorField::Ports);
        let cursor_char = if app.edit_focused_field == RuleEditorField::Ports {
            "█"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(cur, cur_style),
            Span::styled(
                "Specify ports (e.g. 80,443 or *): ",
                Style::default().fg(palette.fg),
            ),
            Span::styled(
                &app.edit_ports,
                Style::default()
                    .fg(palette.port_purple)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(cursor_char, Style::default().fg(palette.warning_orange)),
        ]));
    }

    // Service Target field (if service_name is present on App)
    if app.edit_target_option == EditorTargetOption::App {
        if let Some(ref svc) = app.edit_service_name {
            let (cur, cur_style) = focus_cursor(RuleEditorField::ServiceOnly);
            lines.push(Line::from(vec![
                Span::styled(cur, cur_style),
                Span::styled("Svc Scope:   ", Style::default().fg(palette.fg)),
                Span::styled("[App Binary]", opt_style(!app.edit_apply_to_service)),
                Span::raw("  "),
                Span::styled(
                    format!("[Service: {}]", svc),
                    opt_style(app.edit_apply_to_service),
                ),
            ]));
        }
    }

    // Error line
    if let Some(ref err) = app.edit_error {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("⚠ {}", err),
                Style::default()
                    .fg(palette.alert_red)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    } else {
        lines.push(Line::raw(""));
    }

    // Footer actions
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            "[Enter] ",
            Style::default()
                .fg(palette.allowed_green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Save   "),
        Span::styled(
            "[Del] ",
            Style::default()
                .fg(palette.warning_orange)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Remove Rule   "),
        Span::styled(
            "[Esc] ",
            Style::default()
                .fg(palette.fg_muted)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Cancel"),
    ]));

    let p = Paragraph::new(lines).block(modal_block);
    f.render_widget(p, popup_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::monitor::NetworkEvent;
    use crate::core::rules::{AllowedZoneScope, AppRule, NetProtocol, RuleAction};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn buffer_to_string(buffer: &ratatui::buffer::Buffer) -> String {
        let mut s = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                s.push_str(cell.symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn test_fit_width_equivalence_partitions() {
        // Partition 1: char_count == width -> unchanged string
        assert_eq!(fit_width("hello", 5), "hello");

        // Partition 2: char_count < width -> padded with trailing spaces
        assert_eq!(fit_width("abc", 6), "abc   ");
        assert_eq!(fit_width("", 4), "    ");

        // Partition 3: char_count > width (width > 3) -> truncated with ".." suffix
        assert_eq!(fit_width("abcdefgh", 6), "abcd..");
        assert_eq!(fit_width("123456789", 5), "123..");

        // Multi-byte UTF-8 test (Ukrainian characters)
        assert_eq!(fit_width("Браузер", 10), "Браузер   ");
        let truncated_utf8 = fit_width("МережевийСвітлячок", 8);
        assert_eq!(truncated_utf8.chars().count(), 8);
        assert!(truncated_utf8.ends_with(".."));
    }

    #[test]
    fn test_fit_width_boundary_values() {
        // Boundary: width == 3 (width <= 3 branch)
        assert_eq!(fit_width("abcdef", 3), "abc");

        // Boundary: width == 2
        assert_eq!(fit_width("abcdef", 2), "ab");

        // Boundary: width == 1
        assert_eq!(fit_width("abcdef", 1), "a");

        // Boundary: width == 0
        assert_eq!(fit_width("abcdef", 0), "");

        // Boundary: width == 4 (first width where ".." suffix is used)
        assert_eq!(fit_width("abcdef", 4), "ab..");
    }

    #[test]
    fn test_render_header_states() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Admin mode + Default outbound policy (Allow)
        let mut app = App::new_with_privilege(true);
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out = buffer_to_string(terminal.backend().buffer());

        assert!(out.contains("it's.fw"));
        assert!(out.contains("Outbound: ALLOW"));
        assert!(!out.contains("[READ-ONLY: NO ADMIN]"));

        // 2. Non-admin mode + Outbound Block policy
        app.is_admin = false;
        app.firewall_active = true;
        app.set_status("Denial Notice".into());

        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out = buffer_to_string(terminal.backend().buffer());

        assert!(out.contains("Outbound: BLOCK"));
        assert!(out.contains("[READ-ONLY: NO ADMIN]"));
        assert!(out.contains("Denial Notice"));

        // 3. Switching direction to Inbound shows Inbound default policy (BLOCK) independently of Outbound
        app.firewall_active = false;
        app.inbound_firewall_active = true;
        app.toggle_direction();
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out_in = buffer_to_string(terminal.backend().buffer());
        assert!(out_in.contains("Inbound: BLOCK (Default Mode)"));
    }

    #[test]
    fn test_render_body_empty_and_populated_inspection() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // Empty state
        let mut app = App::new_with_privilege(true);
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out = buffer_to_string(terminal.backend().buffer());
        assert!(out.contains("No applications detected yet. Scanning network..."));
        assert!(out.contains("[1] All"));
        assert!(out.contains("[2] Knocking"));

        // Populated state with events
        let app_path = r"C:\Windows\System32\svchost.exe";
        app.aggregator.record_event(NetworkEvent {
            timestamp: 100,
            app_path: app_path.into(),
            service_name: None,
            direction: crate::core::rules::RuleDirection::Outbound,
            process_id: 1024,
            parent_process_name: Some("services.exe".into()),
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            remote_port: 53,
            protocol: "UDP".into(),
            is_blocked: false,
            zone: Zone::Internet,
        });

        // Add a configured rule
        app.active_rules.insert(
            app_path.to_lowercase(),
            AppRule {
                app_path: app_path.into(),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Outbound,
                action: RuleAction::Allow,
                zone_scope: AllowedZoneScope::LanOnly,
                custom_remote_ip: None,
                protocol: NetProtocol::Udp,
                ports: "53".into(),
                interface_name: None,
                created_at: 0,
                duration: crate::core::rules::RuleDuration::Permanent,
                expires_at: None,
                display_name: None,
                rule_id: None,
                is_system_or_uwp: false,
            },
        );

        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out = buffer_to_string(terminal.backend().buffer());

        // Header column markers
        assert!(out.contains("APPLICATION"));
        assert!(out.contains("STATUS"));
        assert!(out.contains("TRAFFIC"));
        assert!(out.contains("SPEED"));
        assert!(out.contains("VOLUME"));
        assert!(out.contains("P/S"));

        // App row and inspector fields
        assert!(out.contains("svchost.exe"));
        assert!(out.contains("Process Details"));
        assert!(out.contains("services.exe"));
        assert!(out.contains("Path:"));
        assert!(out.contains("Args:"));
        assert!(out.contains("LAN ONLY (Explicit Rule)"));
        assert!(out.contains("Recent Activity"));
        assert!(out.contains("[PASS]"));
        assert!(out.contains("[WAN]"));
        assert!(out.contains("1.1.1.1:53"));
    }

    #[test]
    fn test_render_footer_shortcuts_admin_vs_readonly() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // Admin mode
        let mut app = App::new_with_privilege(true);
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out_admin = buffer_to_string(terminal.backend().buffer());
        assert!(out_admin.contains("[f] policy"));
        assert!(out_admin.contains("[n] new"));
        assert!(out_admin.contains("allow"));
        assert!(out_admin.contains("lan"));
        assert!(out_admin.contains("mode"));
        assert!(out_admin.contains("quit"));

        // Read-only mode
        let mut app_ro = App::new_with_privilege(false);
        terminal.draw(|f| render(f, &mut app_ro)).unwrap();
        let out_ro = buffer_to_string(terminal.backend().buffer());
        assert!(out_ro.contains("[READ-ONLY]"));
        assert!(out_ro.contains("filter"));
        assert!(!out_ro.contains("[f] policy"));
    }

    #[test]
    fn test_render_modals_sort_and_edit() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // 1. Sort modal
        let mut app = App::new_with_privilege(true);
        app.sort_menu_open = true;
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out_sort = buffer_to_string(terminal.backend().buffer());
        assert!(out_sort.contains("Sort Applications"));
        assert!(out_sort.contains("Order is pinned on selection"));

        // 2. Custom rule editor modal
        app.sort_menu_open = false;
        app.edit_mode = true;
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out_edit = buffer_to_string(terminal.backend().buffer());
        assert!(out_edit.contains("Custom Rule Editor"));
        assert!(out_edit.contains("Duration:"));
        assert!(out_edit.contains("Specify ports"));
    }

    #[test]
    fn test_render_boundary_small_dimensions() {
        // Ensure rendering in extremely constrained terminal sizes does not panic
        let small_sizes = [(20, 6), (10, 4), (1, 1), (80, 10)];
        let mut app = App::new_with_privilege(true);

        for (width, height) in small_sizes {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            let res = terminal.draw(|f| render(f, &mut app));
            assert!(res.is_ok(), "render panicked at size {}x{}", width, height);
        }
    }

    #[test]
    fn test_render_v8_wsl_port_uwp_details_recent_focus_and_pinned_args_footer() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_with_privilege(true);

        let mut os_rules = std::collections::HashMap::new();
        os_rules.insert(
            "in::wsl://kbot-dev-tcp".into(),
            AppRule {
                app_path: "wsl://kbot-dev-tcp".into(),
                service_name: None,
                direction: crate::core::rules::RuleDirection::Inbound,
                action: RuleAction::Allow,
                zone_scope: AllowedZoneScope::Both,
                custom_remote_ip: Some("192.168.128.0/22".into()),
                protocol: NetProtocol::Tcp,
                ports: "5300".into(),
                interface_name: None,
                created_at: 0,
                duration: crate::core::rules::RuleDuration::Permanent,
                expires_at: None,
                display_name: Some("[WSL] kbot dev tcp".into()),
                rule_id: Some("kbot-dev-tcp".into()),
                is_system_or_uwp: false,
            },
        );
        app.sync_from_os_rules(os_rules);
        app.active_direction = crate::tui::app::FirewallDirection::Inbound;
        app.sync_selection();

        app.active_pane = crate::tui::app::ActivePane::ProcessDetails;
        app.details_focused_field = crate::tui::app::ProcessDetailsField::Policy;
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out = buffer_to_string(terminal.backend().buffer());
        assert!(out.contains("[WSL] kbot dev tcp"));
        assert!(out.contains("Hyper-V Firewall (WSL)"));
        assert!(out.contains("Ctrl+Enter: wf.msc"));

        // Pinned Args modal footer even when scrolled deep with many flags
        let mut meta = crate::core::process::query_process_metadata(r"C:\test.exe");
        let long_cmd = format!(
            "\"C:\\test.exe\" {}",
            (0..30)
                .map(|i| format!("--flag-number-{}", i))
                .collect::<Vec<_>>()
                .join(" ")
        );
        meta.command_line = Some(long_cmd);
        app.metadata_cache.insert("wsl://kbot-dev-tcp".into(), meta);
        app.args_modal_open = true;
        app.args_modal_scroll = 25;
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out_args = buffer_to_string(terminal.backend().buffer());
        assert!(
            out_args.contains("[Enter]: Copy & Close"),
            "Args modal footer must remain pinned regardless of scroll"
        );
    }
}
