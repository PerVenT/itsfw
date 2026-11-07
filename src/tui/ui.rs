//! Відображення інтерфейсу TUI на базі Ratatui у стилі superfile / dtop.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::core::zone::Zone;
use crate::tui::app::{App, SortMode, ViewFilter};

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
    // Головний вертикальний лейаут (v4): Шапка (1) -> Таблиця (100% Min) -> Нижній спліт (7) -> Футер (1)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(7),
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
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let palette = app.current_palette();
    let dir_label = app.active_direction.label();

    let fw_status = if app.firewall_active {
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
    };

    let mut title_spans = vec![Span::styled(
        "it's.fw",
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

    let paragraph = Paragraph::new(Line::from(title_spans));
    f.render_widget(paragraph, area);
}

fn render_table(f: &mut Frame, app: &mut App, area: Rect) {
    let palette = app.current_palette();
    let filtered_apps = app.visible_apps();

    let filter_tabs = [
        (ViewFilter::All, "[1] All"),
        (ViewFilter::KnockingOnly, "[2] Knocking"),
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

    let table_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Line::from(list_title_spans))
        .border_style(Style::default().fg(palette.border_focus));

    let inner = table_block.inner(area);
    f.render_widget(table_block, area);

    if inner.height >= 2 {
        let table_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(inner);

        // Фіксований заголовок колонок таблиці на 100% ширини
        let table_header = Line::from(vec![
            Span::raw("  "),
            Span::styled(
                fit_width("APPLICATION", 26),
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
                fit_width("PORTS", 14),
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                fit_width("HITS", 6),
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

                    let configured_rule = app.rule_for_app(&item.app_path);
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

                    let mut name_style = Style::default().fg(palette.fg);
                    if is_selected {
                        name_style = name_style.add_modifier(Modifier::BOLD);
                    }

                    let mut stat_style = Style::default().fg(status_color);
                    if is_bold {
                        stat_style = stat_style.add_modifier(Modifier::BOLD);
                    }

                    let zone_str = item.zones_display();
                    let zone_color = match zone_str {
                        "LAN+INET" => palette.allowed_green,
                        "INET" => palette.internet_cyan,
                        "LAN" => palette.lan_yellow,
                        _ => palette.fg_muted,
                    };

                    let port_str = item.ports_display();

                    let line = Line::from(vec![
                        Span::styled(
                            indicator_str,
                            Style::default()
                                .fg(indicator_color)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(fit_width(&item.app_name, 26), name_style),
                        Span::raw(" "),
                        Span::styled(fit_width(status_text, 10), stat_style),
                        Span::raw(" "),
                        Span::styled(fit_width(zone_str, 9), Style::default().fg(zone_color)),
                        Span::raw(" "),
                        Span::styled(
                            fit_width(&port_str, 14),
                            Style::default().fg(palette.port_purple),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            fit_width(&format!("{}", item.total_hits), 6),
                            Style::default().fg(palette.internet_cyan),
                        ),
                    ]);

                    let item_style = if is_selected {
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

fn render_bottom_split(f: &mut Frame, app: &App, area: Rect) {
    let palette = app.current_palette();
    let filtered_apps = app.visible_apps();

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let details_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            " Process Details ",
            Style::default()
                .fg(palette.border_focus)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(palette.border));

    if let Some(selected_app) = filtered_apps.get(app.selected_index) {
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

        let configured_rule = app.rule_for_app(&selected_app.app_path);
        let is_explicit_block_rule = configured_rule
            .map(|r| r.action == crate::core::rules::RuleAction::Block)
            .unwrap_or(false);

        let (rule_display, rule_color) = if is_explicit_block_rule {
            ("DENY (Explicit Firewall Rule)", palette.alert_red)
        } else if selected_app.is_knocking {
            (
                "KNOCKING (Packets Dropped by Firewall)",
                palette.warning_orange,
            )
        } else if let Some(rule) = configured_rule {
            match (rule.action, rule.zone_scope) {
                (
                    crate::core::rules::RuleAction::Allow,
                    crate::core::rules::AllowedZoneScope::LanOnly,
                ) => ("LAN ONLY (Explicit Rule)", palette.lan_yellow),
                (crate::core::rules::RuleAction::Allow, _) => {
                    ("ALLOW (Explicit Rule)", palette.allowed_green)
                }
                (crate::core::rules::RuleAction::Block, _) => {
                    ("DENY (Explicit Rule)", palette.alert_red)
                }
            }
        } else {
            ("ALLOW (Default Outbound Policy)", palette.fg_muted)
        };

        let path_lower = selected_app.app_path.to_lowercase();
        let (fw_sync_status, fw_sync_color) =
            if let Some(rule_name) = app.verified_fw_rules.get(&path_lower) {
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

        let detail_lines = vec![
            Line::from(vec![
                Span::styled("App: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    &selected_app.app_name,
                    Style::default()
                        .fg(palette.border_focus)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({})  ", selected_app.process_id),
                    Style::default().fg(palette.fg_muted),
                ),
                Span::styled("Parent: ", Style::default().fg(palette.fg_muted)),
                Span::styled(parent_display, Style::default().fg(palette.internet_cyan)),
            ]),
            Line::from(vec![
                Span::styled("Path: ", Style::default().fg(palette.fg_muted)),
                Span::styled(&selected_app.app_path, Style::default().fg(palette.fg)),
            ]),
            Line::from(vec![
                Span::styled("Policy: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    rule_display,
                    Style::default().fg(rule_color).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Win Firewall: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    fw_sync_status,
                    Style::default()
                        .fg(fw_sync_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Actions: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    "[a] ",
                    Style::default()
                        .fg(palette.allowed_green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Allow  "),
                Span::styled(
                    "[l] ",
                    Style::default()
                        .fg(palette.lan_yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("LAN only  "),
                Span::styled(
                    "[d] ",
                    Style::default()
                        .fg(palette.alert_red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Deny  "),
                Span::styled(
                    "[Enter] ",
                    Style::default()
                        .fg(palette.internet_cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Rule Builder"),
            ]),
        ];

        let detail_para = Paragraph::new(detail_lines).block(details_block);
        f.render_widget(detail_para, cols[0]);

        // Права половинка: Recent Activity (до 5 подій)
        let count = selected_app.recent_events.len().min(5);
        let activity_title = format!(" Recent Activity ({}) ", count);
        let activity_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(Span::styled(
                activity_title,
                Style::default()
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(palette.border));

        let mut event_lines = Vec::new();
        for event in selected_app.recent_events.iter().rev().take(5) {
            let zone_tag = match event.zone {
                Zone::Lan => "LAN",
                Zone::Internet => "INET",
            };
            let (act_tag, act_color) = if event.is_blocked {
                ("DROP", palette.alert_red)
            } else {
                ("OK  ", palette.allowed_green)
            };
            let ev_line = Line::from(vec![
                Span::styled(
                    format!("[{}] ", act_tag),
                    Style::default().fg(act_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<4} ", event.protocol),
                    Style::default().fg(palette.port_purple),
                ),
                Span::styled(
                    format!(
                        "{:<21} ",
                        format!("{}:{}", event.remote_ip, event.remote_port)
                    ),
                    Style::default().fg(palette.fg),
                ),
                Span::styled(
                    format!("[{}]", zone_tag),
                    Style::default().fg(palette.lan_yellow),
                ),
            ]);
            event_lines.push(ev_line);
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
            Span::raw("switch mode │ "),
            Span::styled(
                "[a] ",
                Style::default()
                    .fg(palette.allowed_green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("allow │ "),
            Span::styled(
                "[l] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("lan only │ "),
            Span::styled(
                "[d] ",
                Style::default()
                    .fg(palette.alert_red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("deny │ "),
            Span::styled(
                "[/] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("search / listeners │ "),
            Span::styled(
                "[s] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("sort │ "),
            Span::styled(
                "[r] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("sync │ "),
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
            Span::raw("search / listeners │ "),
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
                "[r] ",
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("sync │ "),
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

    let width = 48.min(area.width.saturating_sub(4));
    let height = 9.min(area.height.saturating_sub(4));
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
            " Sort Applications [j/k, 1-5, Enter, Esc] ",
            Style::default()
                .fg(palette.border_focus)
                .add_modifier(Modifier::BOLD),
        ))
        .border_style(Style::default().fg(palette.border_focus))
        .style(Style::default().bg(palette.surface));

    let mut lines: Vec<Line> = SortMode::ALL
        .iter()
        .enumerate()
        .map(|(idx, mode)| {
            let is_cursor = idx == app.sort_menu_index;
            let is_active = *mode == app.sort_mode;
            let bullet = if is_active { "●" } else { " " };
            let prefix = format!(" {} [{}] {} ", bullet, idx + 1, mode.label());
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

fn render_edit_modal(f: &mut Frame, app: &App) {
    let palette = app.current_palette();
    let area = f.area();

    let width = 64.min(area.width.saturating_sub(4));
    let height = 10.min(area.height.saturating_sub(4));
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
        .title(" Custom Rule Editor [Enter to apply, Esc to cancel] ")
        .border_style(Style::default().fg(palette.border_focus))
        .style(Style::default().bg(palette.surface));

    let remote_ip_str = app.edit_remote_ip.as_deref().unwrap_or("any");
    let content = vec![
        Line::from(vec![
            Span::styled("App: ", Style::default().fg(palette.fg_muted)),
            Span::styled(
                fit_width(&app.edit_app_path, (width.saturating_sub(10)) as usize),
                Style::default()
                    .fg(palette.border_focus)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Remote IP: ", Style::default().fg(palette.fg_muted)),
            Span::styled(
                remote_ip_str,
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Specify ports (e.g. 80,443 or *): ",
                Style::default().fg(palette.fg_muted),
            ),
            Span::styled(
                &app.edit_ports,
                Style::default()
                    .fg(palette.port_purple)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Protocol: ", Style::default().fg(palette.fg_muted)),
            Span::styled(
                &app.edit_protocol,
                Style::default()
                    .fg(palette.lan_yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                "[Enter] ",
                Style::default()
                    .fg(palette.allowed_green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Apply Rule   "),
            Span::styled(
                "[Esc] ",
                Style::default()
                    .fg(palette.fg_muted)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Cancel"),
        ]),
    ];

    let p = Paragraph::new(content).block(modal_block);
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
                action: RuleAction::Allow,
                zone_scope: AllowedZoneScope::LanOnly,
                protocol: NetProtocol::Udp,
                ports: "53".into(),
                interface_name: None,
                created_at: 0,
            },
        );

        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out = buffer_to_string(terminal.backend().buffer());

        // Header column markers
        assert!(out.contains("APPLICATION"));
        assert!(out.contains("STATUS"));
        assert!(out.contains("TRAFFIC"));

        // App row and inspector fields
        assert!(out.contains("svchost.exe"));
        assert!(out.contains("Process Details"));
        assert!(out.contains("services.exe (PID: 1024)"));
        assert!(out.contains("LAN ONLY (Explicit Rule)"));
        assert!(out.contains("Recent Activity"));
    }

    #[test]
    fn test_render_footer_shortcuts_admin_vs_readonly() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        // Admin mode
        let mut app = App::new_with_privilege(true);
        terminal.draw(|f| render(f, &mut app)).unwrap();
        let out_admin = buffer_to_string(terminal.backend().buffer());
        assert!(out_admin.contains("allow"));
        assert!(out_admin.contains("lan only"));
        assert!(out_admin.contains("switch mode"));
        assert!(out_admin.contains("quit"));

        // Read-only mode
        let mut app_ro = App::new_with_privilege(false);
        terminal.draw(|f| render(f, &mut app_ro)).unwrap();
        let out_ro = buffer_to_string(terminal.backend().buffer());
        assert!(out_ro.contains("[READ-ONLY]"));
        assert!(out_ro.contains("filter"));
        assert!(!out_ro.contains("lan only"));
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
}
