#![allow(dead_code)]

mod core;
mod tui;

use crate::core::admin::is_running_as_admin;
use crate::core::scanner::{scan_current_network_connections, WfpDropMonitor};
use crate::tui::app::{App, SortMode, ViewFilter};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

const APP_VERSION: &str = env!("ITSFW_VERSION");

fn format_cli_flag_output(arg: &str) -> Option<String> {
    match arg {
        "-V" | "--version" => Some(format!("it's.fw {}", APP_VERSION)),
        "-h" | "--help" => Some(format!(
            "it's.fw {}\nInteractive Windows Filtering Platform & Zero-Trust Firewall TUI\n\nUSAGE:\n    itsfw [OPTIONS]\n\nOPTIONS:\n    -V, --version    Print version information\n    -h, --help       Print help information",
            APP_VERSION
        )),
        _ => None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for arg in std::env::args().skip(1) {
        if let Some(out) = format_cli_flag_output(&arg) {
            println!("{}", out);
            return Ok(());
        }
    }

    let is_admin = is_running_as_admin();

    // Встановлюємо Panic Hook, щоб при будь-якій аварії термінал гарантовано відновлювався!
    std::panic::set_hook(Box::new(|info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        eprintln!("\n[it's.fw PANIC]: {:?}", info);
    }));

    // Ініціалізація терміналу
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new_with_privilege(is_admin);
    if !is_admin {
        app.set_status(
            "NON-ADMIN: Read-Only Mode. Run as Administrator to modify firewall rules.".into(),
        );
    }

    // 1. Завантажуємо чинні вихідні правила безпосередньо з Windows Firewall (Єдине Джерело Правди)
    let active_its_fw_rules =
        crate::core::firewall::WindowsFirewallManager::load_active_its_fw_rules();
    app.verified_fw_rules = active_its_fw_rules;
    let os_rules = crate::core::firewall::WindowsFirewallManager::load_outbound_rules_from_os();
    app.sync_from_os_rules(os_rules);

    // 2. Ініціалізуємо WFP Drop Monitor та Registry Watcher
    let mut wfp_monitor = WfpDropMonitor::new();
    let watcher = crate::core::watcher::FirewallRegistryWatcher::start();
    app.set_watcher(watcher.clone());

    // 3. Початкове сканування всіх активних та відкинутих мережевих з'єднань у системі
    let initial_events = scan_current_network_connections();
    for ev in initial_events {
        app.aggregator.record_event(ev);
    }
    for drop_ev in wfp_monitor.poll_dropped_events() {
        app.aggregator.record_event(drop_ev);
    }
    app.latch_sort_snapshot();
    app.sync_selection();

    // Запуск головного циклу подій TUI
    let res = run_app(&mut terminal, &mut app, &mut wfp_monitor, &watcher);

    // Відновлення терміналу
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Application error: {:?}", err);
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    wfp_monitor: &mut WfpDropMonitor,
    watcher: &crate::core::watcher::FirewallRegistryWatcher,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    let mut last_scan = std::time::Instant::now();

    loop {
        // Фонова перевірка зовнішніх змін у реєстрі Windows Firewall
        if let Some(crate::core::watcher::FirewallWatchEvent::ExternalChangeDetected) =
            watcher.try_recv()
        {
            let active_its_fw_rules =
                crate::core::firewall::WindowsFirewallManager::load_active_its_fw_rules();
            app.verified_fw_rules = active_its_fw_rules;
            let dir = match app.active_direction {
                crate::tui::app::FirewallDirection::Outbound => {
                    crate::core::rules::RuleDirection::Outbound
                }
                crate::tui::app::FirewallDirection::Inbound => {
                    crate::core::rules::RuleDirection::Inbound
                }
            };
            let os_rules = crate::core::firewall::WindowsFirewallManager::load_rules_from_os(dir);
            app.sync_from_os_rules(os_rules);
            app.set_status("Synced external firewall changes".into());
        }

        // Періодичне фонове підсканування активних з'єднань та WFP Drop подій кожні 2 секунди
        if last_scan.elapsed() >= std::time::Duration::from_secs(2) {
            if !app.stream_paused {
                let events = scan_current_network_connections();
                for ev in events {
                    app.record_incoming_event(ev);
                }
                for drop_ev in wfp_monitor.poll_dropped_events() {
                    app.record_incoming_event(drop_ev);
                }
                app.sync_selection();
            }
            last_scan = std::time::Instant::now();
        }

        terminal.draw(|f| tui::ui::render(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // У Windows Terminal генеруються події Press та Release. Обробляємо ТІЛЬКИ Press, щоб не було подвійних натискань.
                if key.kind != crossterm::event::KeyEventKind::Press {
                    continue;
                }

                if app.sort_menu_open {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('s') => {
                            app.sort_menu_open = false;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.sort_menu_index = (app.sort_menu_index + 1) % SortMode::ALL.len();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.sort_menu_index == 0 {
                                app.sort_menu_index = SortMode::ALL.len() - 1;
                            } else {
                                app.sort_menu_index -= 1;
                            }
                        }
                        KeyCode::Enter => {
                            let mode = SortMode::ALL[app.sort_menu_index];
                            app.sort_menu_open = false;
                            app.set_sort_mode(mode);
                        }
                        KeyCode::Char('1') => {
                            app.sort_menu_open = false;
                            app.set_sort_mode(SortMode::NameAsc);
                        }
                        KeyCode::Char('2') => {
                            app.sort_menu_open = false;
                            app.set_sort_mode(SortMode::ActivityHitsDesc);
                        }
                        KeyCode::Char('3') => {
                            app.sort_menu_open = false;
                            app.set_sort_mode(SortMode::RecentActivityDesc);
                        }
                        KeyCode::Char('4') => {
                            app.sort_menu_open = false;
                            app.set_sort_mode(SortMode::StatusPriority);
                        }
                        KeyCode::Char('5') => {
                            app.sort_menu_open = false;
                            app.set_sort_mode(SortMode::ZoneInternetFirst);
                        }
                        _ => {}
                    }
                    continue;
                }

                if app.edit_mode {
                    match key.code {
                        KeyCode::Esc => {
                            app.edit_mode = false;
                            app.edit_error = None;
                        }
                        KeyCode::Tab | KeyCode::Down => {
                            app.editor_next_field();
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            app.editor_prev_field();
                        }
                        KeyCode::Left => {
                            app.editor_cycle_option(false);
                        }
                        KeyCode::Right => {
                            app.editor_cycle_option(true);
                        }
                        KeyCode::Char(' ') => match app.edit_focused_field {
                            crate::tui::app::RuleEditorField::CustomIp
                            | crate::tui::app::RuleEditorField::Ports => {}
                            _ => {
                                app.editor_cycle_option(true);
                            }
                        },
                        KeyCode::Enter => {
                            app.save_prefilled_rule();
                        }
                        KeyCode::Delete => {
                            app.delete_rule_from_editor();
                        }
                        KeyCode::Char('d')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            app.delete_rule_from_editor();
                        }
                        KeyCode::Backspace => {
                            app.editor_backspace();
                        }
                        KeyCode::Char(c) => {
                            app.editor_input_char(c);
                        }
                        _ => {}
                    }
                    continue;
                }

                if app.search_active {
                    match key.code {
                        KeyCode::Esc => {
                            app.search_active = false;
                            app.search_query.clear();
                            app.listening_mode = false;
                        }
                        KeyCode::Enter => {
                            app.search_active = false;
                            app.listening_mode = false;
                        }
                        KeyCode::Backspace => {
                            app.search_query.pop();
                            if !app.search_query.starts_with(':') {
                                app.listening_mode = false;
                            }
                            if app.search_query.is_empty() {
                                app.search_active = false;
                            }
                        }
                        KeyCode::Down => {
                            if app.listening_mode {
                                app.next_listening_socket();
                            }
                        }
                        KeyCode::Up => {
                            if app.listening_mode {
                                app.prev_listening_socket();
                            }
                        }
                        KeyCode::Char('a') if app.listening_mode => {
                            app.apply_listener_inbound_rule(
                                crate::core::rules::RuleAction::Allow,
                                crate::core::rules::AllowedZoneScope::Both,
                            );
                        }
                        KeyCode::Char('l') if app.listening_mode => {
                            app.apply_listener_inbound_rule(
                                crate::core::rules::RuleAction::Allow,
                                crate::core::rules::AllowedZoneScope::LanOnly,
                            );
                        }
                        KeyCode::Char('i') if app.listening_mode => {
                            app.apply_listener_inbound_rule(
                                crate::core::rules::RuleAction::Allow,
                                crate::core::rules::AllowedZoneScope::InternetOnly,
                            );
                        }
                        KeyCode::Char('d') if app.listening_mode => {
                            app.apply_listener_inbound_rule(
                                crate::core::rules::RuleAction::Block,
                                crate::core::rules::AllowedZoneScope::Both,
                            );
                        }
                        KeyCode::Char('k') if app.listening_mode => {
                            let _ = app.kill_selected_listening_pid();
                        }
                        KeyCode::Char(c) => {
                            app.search_query.push(c);
                            if app.search_query.starts_with(':') && !app.listening_mode {
                                app.listening_mode = true;
                                app.refresh_listening_sockets();
                            }
                        }
                        _ => {}
                    }
                    continue;
                }

                // Отримуємо поточний вибраний додаток із ВІДФІЛЬТРОВАНОГО списку
                let visible_apps = app.visible_apps();
                let selected_app_info = visible_apps.get(app.selected_index).map(|a| {
                    (
                        a.app_path.clone(),
                        a.last_target_port,
                        a.last_protocol.clone(),
                    )
                });

                match key.code {
                    KeyCode::Tab => {
                        app.toggle_direction();
                    }
                    KeyCode::Char('/') => {
                        app.search_active = true;
                        app.search_query.clear();
                        app.listening_mode = false;
                        app.refresh_listening_sockets();
                    }
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('t') => {
                        app.toggle_theme();
                    }
                    KeyCode::Char('1') => {
                        app.set_filter(ViewFilter::All, "All");
                    }
                    KeyCode::Char('2') => {
                        app.set_filter(ViewFilter::KnockingOnly, "Knocking");
                    }
                    KeyCode::Char('3') => {
                        app.set_filter(ViewFilter::AllowedOnly, "Allowed");
                    }
                    KeyCode::Char('4') => {
                        app.set_filter(ViewFilter::BlockedOnly, "Blocked");
                    }
                    KeyCode::Char('f') => {
                        app.toggle_firewall_policy();
                    }
                    KeyCode::Char('a') => {
                        if let Some((path, _, _)) = selected_app_info {
                            app.allow_selected_all(&path);
                        }
                    }
                    KeyCode::Char('l') => {
                        if let Some((path, _, _)) = selected_app_info {
                            app.allow_selected_lan_only(&path);
                        }
                    }
                    KeyCode::Char('i') => {
                        if let Some((path, _, _)) = selected_app_info {
                            app.allow_selected_internet_only(&path);
                        }
                    }
                    KeyCode::Char('p') => {
                        if let Some((path, port, proto)) = selected_app_info {
                            app.allow_selected_current_port(&path, port, &proto);
                        }
                    }
                    KeyCode::Char('d') => {
                        if let Some((path, _, _)) = selected_app_info {
                            app.block_selected(&path);
                        }
                    }
                    KeyCode::Char('x') | KeyCode::Delete => {
                        if let Some((path, _, _)) = selected_app_info {
                            app.reset_selected_rule(&path);
                        }
                    }
                    KeyCode::Char(' ') => {
                        app.toggle_stream_pause();
                    }
                    KeyCode::F(12) | KeyCode::Char('L') => {
                        app.toggle_lockdown();
                    }
                    KeyCode::Char('s') => {
                        app.toggle_sort_menu();
                    }
                    KeyCode::Char('r') => {
                        app.firewall_active = crate::core::firewall::WindowsFirewallManager::is_outbound_policy_blocking();
                        let active_its_fw_rules =
                            crate::core::firewall::WindowsFirewallManager::load_active_its_fw_rules(
                            );
                        app.verified_fw_rules = active_its_fw_rules;
                        let dir = match app.active_direction {
                            crate::tui::app::FirewallDirection::Outbound => {
                                crate::core::rules::RuleDirection::Outbound
                            }
                            crate::tui::app::FirewallDirection::Inbound => {
                                crate::core::rules::RuleDirection::Inbound
                            }
                        };
                        let os_rules =
                            crate::core::firewall::WindowsFirewallManager::load_rules_from_os(dir);
                        let count = os_rules.len();
                        app.sync_from_os_rules(os_rules);
                        for drop_ev in wfp_monitor.poll_dropped_events() {
                            app.record_incoming_event(drop_ev);
                        }
                        app.latch_sort_snapshot();
                        app.sync_selection();
                        app.set_status(format!(
                            "Synced with Windows Firewall ({} active rules)",
                            count
                        ));
                    }
                    KeyCode::Enter | KeyCode::Char('e') => {
                        if let Some((path, _, _)) = selected_app_info {
                            app.open_rule_editor_for_app(&path);
                        } else {
                            app.open_rule_editor();
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let total = visible_apps.len();
                        app.next_item(total);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let total = visible_apps.len();
                        app.prev_item(total);
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_cli_flag_output_version_and_help() {
        let ver_short = format_cli_flag_output("-V").expect("should return version");
        let ver_long = format_cli_flag_output("--version").expect("should return version");
        assert_eq!(ver_short, ver_long);
        assert!(ver_short.starts_with("it's.fw "));
        assert!(!APP_VERSION.is_empty());

        let help_short = format_cli_flag_output("-h").expect("should return help");
        let help_long = format_cli_flag_output("--help").expect("should return help");
        assert_eq!(help_short, help_long);
        assert!(help_short.contains("USAGE:"));
        assert!(help_short.contains("--version"));

        assert!(format_cli_flag_output("--unknown").is_none());
    }
}
