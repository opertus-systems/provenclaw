use crate::app::App;
use crate::components::{panel, text_panel};
use crate::state::{FocusPane, View};
use crate::theme;
use provenclaw_core::RiskLevel;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph};

pub fn render(app: &App, frame: &mut Frame<'_>) {
    let frame_area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame_area);

    let header = Paragraph::new(app.header_text())
        .style(header_style(app))
        .block(panel("Security Posture"));
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(24),
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(chunks[1]);

    render_nav(app, frame, body[0]);
    render_center(app, frame, body[1]);
    render_inspector(app, frame, body[2]);

    let status = Paragraph::new(app.state.status.clone())
        .style(theme::muted())
        .block(panel("Status"));
    frame.render_widget(status, chunks[2]);

    if app.state.show_help {
        let help = "Ctrl+K palette | / search | g d/g r/g a/g t quick goto | v deep verify | e export | q close/quit";
        let area = ratatui::layout::Rect {
            x: frame_area.x + frame_area.width / 8,
            y: frame_area.y + frame_area.height / 8,
            width: frame_area.width * 3 / 4,
            height: frame_area.height / 4,
        };
        frame.render_widget(text_panel("Help", help.to_string()), area);
    }

    if app.state.show_palette {
        let area = ratatui::layout::Rect {
            x: frame_area.x + frame_area.width / 5,
            y: frame_area.y + frame_area.height / 6,
            width: frame_area.width * 3 / 5,
            height: frame_area.height / 2,
        };
        let items: Vec<ListItem<'_>> = app
            .palette_items()
            .iter()
            .enumerate()
            .map(|(idx, (name, _))| {
                if idx == app.state.palette_index {
                    ListItem::new(Line::from(vec![Span::styled(
                        *name,
                        Style::default()
                            .fg(ratatui::style::Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )]))
                } else {
                    ListItem::new(*name)
                }
            })
            .collect();
        frame.render_widget(List::new(items).block(panel("Command Palette")), area);
    }
}

fn header_style(app: &App) -> Style {
    match app.risk_level() {
        Some(RiskLevel::Low) => theme::accent(),
        Some(RiskLevel::Medium) => theme::warning(),
        Some(RiskLevel::High) | Some(RiskLevel::Degraded) => theme::danger(),
        None => theme::muted(),
    }
}

fn render_nav(app: &App, frame: &mut Frame<'_>, area: ratatui::layout::Rect) {
    let items: Vec<ListItem<'_>> = View::all()
        .iter()
        .enumerate()
        .map(|(idx, view)| {
            let marker = if idx == app.state.nav_index { ">" } else { " " };
            let focused = app.state.focus == FocusPane::Nav && idx == app.state.nav_index;
            let line = format!("{marker} {}", view.title());
            if focused {
                ListItem::new(Line::styled(
                    line,
                    Style::default()
                        .fg(ratatui::style::Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                ListItem::new(line)
            }
        })
        .collect();

    frame.render_widget(List::new(items).block(panel("Navigation")), area);
}

fn render_center(app: &App, frame: &mut Frame<'_>, area: ratatui::layout::Rect) {
    frame.render_widget(text_panel(app.state.view.title(), app.center_text()), area);
}

fn render_inspector(app: &App, frame: &mut Frame<'_>, area: ratatui::layout::Rect) {
    frame.render_widget(text_panel("Inspector", app.inspector_text()), area);
}
