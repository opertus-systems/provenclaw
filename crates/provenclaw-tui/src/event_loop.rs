use crate::TuiOptions;
use crate::actions::UiAction;
use crate::app::App;
use crate::state::View;
use crate::views;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{self, Stdout};
use std::time::Duration;

pub fn run(options: TuiOptions) -> Result<(), crate::TuiError> {
    let mut app = App::new(options.read_only)?;

    if let Some(snapshot) = options.snapshot {
        std::fs::write(snapshot, app.snapshot_text())?;
        return Ok(());
    }

    let mut terminal = init_terminal()?;
    let mut result = Ok(());

    while !app.should_quit {
        terminal.draw(|frame| views::render(&app, frame))?;

        if event::poll(Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                let action = map_key(key, &mut app);
                if let Err(err) = app.handle(action) {
                    app.state.status = format!("error: {err}");
                }
            }
        }
    }

    if let Err(err) = restore_terminal(&mut terminal) {
        result = Err(crate::TuiError::Io(err));
    }

    result
}

fn init_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

fn map_key(key: KeyEvent, app: &mut App) -> UiAction {
    if app.state.pending_g {
        app.state.pending_g = false;
        return match key.code {
            KeyCode::Char('d') => UiAction::QuickGoto(View::Dashboard),
            KeyCode::Char('r') => UiAction::QuickGoto(View::Receipts),
            KeyCode::Char('a') => UiAction::QuickGoto(View::AuditStream),
            KeyCode::Char('t') => UiAction::QuickGoto(View::Trust),
            _ => UiAction::None,
        };
    }

    if app.state.search_mode {
        return match key.code {
            KeyCode::Esc => UiAction::SearchCancel,
            KeyCode::Enter => UiAction::SearchSubmit,
            KeyCode::Backspace => UiAction::SearchBackspace,
            KeyCode::Char(ch) => UiAction::SearchInput(ch),
            _ => UiAction::None,
        };
    }

    match (key.modifiers, key.code) {
        (KeyModifiers::CONTROL, KeyCode::Char('k')) => UiAction::TogglePalette,
        (_, KeyCode::Char('?')) => UiAction::ToggleHelp,
        (_, KeyCode::Char('/')) => UiAction::StartSearch,
        (_, KeyCode::Char('q')) => UiAction::Quit,
        (_, KeyCode::Char('j')) | (_, KeyCode::Down) => UiAction::MoveDown,
        (_, KeyCode::Char('k')) | (_, KeyCode::Up) => UiAction::MoveUp,
        (_, KeyCode::Left) => UiAction::MoveLeft,
        (_, KeyCode::Right) => UiAction::MoveRight,
        (_, KeyCode::Tab) => UiAction::Tab,
        (KeyModifiers::SHIFT, KeyCode::BackTab) => UiAction::ShiftTab,
        (_, KeyCode::Enter) => UiAction::Enter,
        (_, KeyCode::Char('g')) => {
            app.state.pending_g = true;
            UiAction::None
        }
        (_, KeyCode::Char('v')) => UiAction::DeepVerify,
        (_, KeyCode::Char('e')) => UiAction::Export,
        (_, KeyCode::Char('R')) | (_, KeyCode::Char('r')) => UiAction::Refresh,
        _ => UiAction::None,
    }
}
