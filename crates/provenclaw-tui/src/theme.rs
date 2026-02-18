use ratatui::style::{Color, Style};

pub fn frame() -> Style {
    Style::default().fg(Color::White)
}

pub fn accent() -> Style {
    Style::default().fg(Color::Cyan)
}

pub fn warning() -> Style {
    Style::default().fg(Color::Yellow)
}

pub fn danger() -> Style {
    Style::default().fg(Color::Red)
}

pub fn muted() -> Style {
    Style::default().fg(Color::DarkGray)
}
