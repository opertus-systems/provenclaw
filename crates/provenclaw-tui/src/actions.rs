use crate::state::View;

#[derive(Debug, Clone)]
pub enum UiAction {
    MoveUp,
    MoveDown,
    MoveLeft,
    MoveRight,
    Tab,
    ShiftTab,
    Enter,
    ToggleHelp,
    TogglePalette,
    StartSearch,
    SearchInput(char),
    SearchBackspace,
    SearchSubmit,
    SearchCancel,
    QuickGoto(View),
    DeepVerify,
    Export,
    Refresh,
    Quit,
    None,
}
