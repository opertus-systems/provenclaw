use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

pub fn panel(title: &str) -> Block<'_> {
    Block::default().title(title).borders(Borders::ALL)
}

pub fn text_panel(title: &str, body: String) -> Paragraph<'_> {
    Paragraph::new(body)
        .block(panel(title))
        .wrap(Wrap { trim: false })
}

pub fn modal(title: &str, body: String, area: Rect) -> (Rect, Paragraph<'_>) {
    let modal_area = Rect {
        x: area.x + area.width / 6,
        y: area.y + area.height / 6,
        width: area.width * 2 / 3,
        height: area.height * 2 / 3,
    };
    let paragraph = Paragraph::new(vec![
        Line::styled(title, Style::default().add_modifier(Modifier::BOLD)),
        Line::raw(""),
        Line::raw(body),
    ])
    .block(panel(""))
    .wrap(Wrap { trim: false });
    (modal_area, paragraph)
}
