//! Відображення інтерфейсу TUI на базі Ratatui у стилі superfile / dtop.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::core::zone::Zone;
use crate::tui::app::{App, RuleEditorField, SortMode, ViewFilter};

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

fn render_bottom_split(f: &mut Frame, app: &mut App, area: Rect) {
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

        let configured_rule = app.rule_for_app_entry(selected_app);
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

        let meta = app.get_or_load_metadata(&selected_app.app_path);
        let desc_display = meta.description.as_deref().unwrap_or("-");
        let sign_badge = meta.signature.badge();
        let sign_color = match meta.signature {
            crate::core::process::SignatureStatus::Verified(_) => palette.allowed_green,
            crate::core::process::SignatureStatus::Unsigned => palette.warning_orange,
            crate::core::process::SignatureStatus::Untrusted => palette.alert_red,
            crate::core::process::SignatureStatus::Unknown => palette.fg_muted,
        };

        let mut desc_sign_spans = vec![
            Span::styled("Desc: ", Style::default().fg(palette.fg_muted)),
            Span::styled(fit_width(desc_display, 24), Style::default().fg(palette.fg)),
            Span::styled("  Sign: ", Style::default().fg(palette.fg_muted)),
            Span::styled(
                sign_badge,
                Style::default().fg(sign_color).add_modifier(Modifier::BOLD),
            ),
        ];
        if meta.is_suspicious_path {
            desc_sign_spans.push(Span::styled(
                " [⚠ SUSPICIOUS PATH]",
                Style::default()
                    .bg(palette.alert_red)
                    .fg(palette.fg)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        let policy_spans = if let Some(ref svc) = selected_app.service_name {
            vec![
                Span::styled("Service: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    svc,
                    Style::default()
                        .fg(palette.internet_cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  Policy: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    rule_display,
                    Style::default().fg(rule_color).add_modifier(Modifier::BOLD),
                ),
            ]
        } else {
            vec![
                Span::styled("Policy: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    rule_display,
                    Style::default().fg(rule_color).add_modifier(Modifier::BOLD),
                ),
            ]
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
            Line::from(desc_sign_spans),
            Line::from(policy_spans),
            Line::from(vec![
                Span::styled("Win Firewall: ", Style::default().fg(palette.fg_muted)),
                Span::styled(
                    fw_sync_status,
                    Style::default()
                        .fg(fw_sync_color)
                        .add_modifier(Modifier::BOLD),
                ),
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
            let endpoint = crate::core::dns::format_recent_activity_endpoint(
                &event.remote_ip,
                event.remote_port,
                &event.protocol,
                domain.as_deref(),
            );
            let ev_line = Line::from(vec![
                Span::styled(
                    format!("[{}] ", act_tag),
                    Style::default().fg(act_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{} ", endpoint), Style::default().fg(palette.fg)),
                Span::styled(
                    format!("[{}]", zone_tag),
                    Style::default().fg(match event.zone {
                        Zone::Lan => palette.lan_yellow,
                        Zone::Internet => palette.internet_cyan,
                    }),
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
                "[i] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("int only │ "),
            Span::styled(
                "[d] ",
                Style::default()
                    .fg(palette.alert_red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("deny │ "),
            Span::styled(
                "[x] ",
                Style::default()
                    .fg(palette.warning_orange)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("reset │ "),
            Span::styled(
                "[/] ",
                Style::default()
                    .fg(palette.internet_cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("search │ "),
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

    let width = 76.min(area.width.saturating_sub(4));
    let height = 15.min(area.height.saturating_sub(2));
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

    use crate::core::rules::{AllowedZoneScope, RuleAction, RuleDirection};
    let mut lines = Vec::new();

    // App path line
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("App: ", Style::default().fg(palette.fg_muted)),
        Span::styled(
            fit_width(&app.edit_app_path, (width.saturating_sub(12)) as usize),
            Style::default()
                .fg(palette.border_focus)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

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

    // Zone / Scope field
    let (cur, cur_style) = focus_cursor(RuleEditorField::ZoneScope);
    lines.push(Line::from(vec![
        Span::styled(cur, cur_style),
        Span::styled("Zone / Scope:", Style::default().fg(palette.fg)),
        Span::raw(" "),
        Span::styled(
            "[All (LAN+Inet)]",
            opt_style(!app.edit_custom_ip_mode && app.edit_zone_scope == AllowedZoneScope::Both),
        ),
        Span::raw(" "),
        Span::styled(
            "[LAN Only]",
            opt_style(!app.edit_custom_ip_mode && app.edit_zone_scope == AllowedZoneScope::LanOnly),
        ),
        Span::raw(" "),
        Span::styled(
            "[Internet Only]",
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

    // Service Target field (if service_name is present)
    if let Some(ref svc) = app.edit_service_name {
        let (cur, cur_style) = focus_cursor(RuleEditorField::ServiceOnly);
        lines.push(Line::from(vec![
            Span::styled(cur, cur_style),
            Span::styled("Target:      ", Style::default().fg(palette.fg)),
            Span::styled("[App Binary]", opt_style(!app.edit_apply_to_service)),
            Span::raw("  "),
            Span::styled(
                format!("[Service: {}]", svc),
                opt_style(app.edit_apply_to_service),
            ),
        ]));
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
