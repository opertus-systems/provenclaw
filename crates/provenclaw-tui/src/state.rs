#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Run,
    Tools,
    Policy,
    Receipts,
    AuditStream,
    Trust,
    Diagnostics,
    Settings,
}

impl View {
    pub fn title(self) -> &'static str {
        match self {
            View::Dashboard => "Dashboard",
            View::Run => "Run",
            View::Tools => "Tools",
            View::Policy => "Policy",
            View::Receipts => "Receipts",
            View::AuditStream => "Audit Stream",
            View::Trust => "Trust",
            View::Diagnostics => "Diagnostics",
            View::Settings => "Settings",
        }
    }

    pub fn all() -> &'static [View] {
        &[
            View::Dashboard,
            View::Run,
            View::Tools,
            View::Policy,
            View::Receipts,
            View::AuditStream,
            View::Trust,
            View::Diagnostics,
            View::Settings,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Nav,
    Center,
    Inspector,
}

impl FocusPane {
    pub fn next(self) -> Self {
        match self {
            Self::Nav => Self::Center,
            Self::Center => Self::Inspector,
            Self::Inspector => Self::Nav,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Nav => Self::Inspector,
            Self::Center => Self::Nav,
            Self::Inspector => Self::Center,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub view: View,
    pub focus: FocusPane,
    pub nav_index: usize,
    pub center_index: usize,
    pub show_help: bool,
    pub show_palette: bool,
    pub palette_index: usize,
    pub search_mode: bool,
    pub search_query: String,
    pub pending_g: bool,
    pub status: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            view: View::Dashboard,
            focus: FocusPane::Nav,
            nav_index: 0,
            center_index: 0,
            show_help: false,
            show_palette: false,
            palette_index: 0,
            search_mode: false,
            search_query: String::new(),
            pending_g: false,
            status: "Ctrl+K: palette | ?: help | q: quit".to_string(),
        }
    }
}
