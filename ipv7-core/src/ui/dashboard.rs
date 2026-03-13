//! ui/dashboard.rs
//! Interfaz de Línea de Comandos (TUI) para Gobernanza del Nodo IPv7.

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use std::{io, time::Duration};
use tokio::sync::mpsc;

/// Mensajes de eventos desde el hilo de red al hilo del TUI
pub enum TuiEvent {
    LogMsg(String),
    NetworkStatus(String),
    DhtUpdate(Vec<(String, String)>),
    UserChatInput(String),
}

pub struct DashboardState {
    pub logs: Vec<String>,
    pub node_id: String,
    pub status: String,
    pub dht_peers: Vec<(String, String)>,
    pub current_tab: usize,
    pub announcements: Vec<(String, String)>,
    pub chat_input: String,
    pub chat_messages: Vec<String>,
}

impl DashboardState {
    pub fn new(node_id: String, dht_peers: Vec<(String, String)>) -> Self {
        Self {
            logs: Vec::new(),
            node_id,
            status: "INICIALIZANDO".to_string(),
            dht_peers,
            current_tab: 0,
            announcements: Vec::new(),
            chat_input: String::new(),
            chat_messages: Vec::new(),
        }
    }
}

pub async fn run_dashboard(
    mut rx: mpsc::Receiver<TuiEvent>,
    tx_to_net: mpsc::Sender<TuiEvent>,
    initial_state: DashboardState,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = initial_state;

    loop {
        terminal.draw(|f| draw_ui(f, &state))?;

        // 1. Procesar eventos de red (Reactividad)
        while let Ok(event) = rx.try_recv() {
            match event {
                TuiEvent::LogMsg(msg) => {
                    state.logs.push(msg);
                    if state.logs.len() > 50 {
                        state.logs.remove(0);
                    }
                }
                TuiEvent::NetworkStatus(stat) => {
                    state.status = stat;
                }
                TuiEvent::DhtUpdate(peers) => {
                    state.dht_peers = peers;
                }
                _ => {}
            }
        }

        // 2. Interactuar con eventos de teclado (Entrada de Chat)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // Si estamos en la pestaña 3 (Comunidad), permitimos escribir
                if state.current_tab == 2 {
                    match key.code {
                        KeyCode::Char(c) => {
                            state.chat_input.push(c);
                        }
                        KeyCode::Backspace => {
                            state.chat_input.pop();
                        }
                        KeyCode::Enter => {
                            if !state.chat_input.is_empty() {
                                let msg = state.chat_input.clone();
                                state.chat_messages.push(format!("[Tú] {}", msg));
                                state.chat_input.clear();
                                let _ = tx_to_net.send(TuiEvent::UserChatInput(msg)).await;
                            }
                        }
                        KeyCode::Esc => state.current_tab = 0,
                        _ => {}
                    }
                }

                // Control de navegación general (a menos que estemos escribiendo)
                if state.current_tab != 2 || matches!(key.code, KeyCode::F(1) | KeyCode::F(2) | KeyCode::F(3)) {
                     match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('1') | KeyCode::F(1) => state.current_tab = 0,
                        KeyCode::Char('2') | KeyCode::F(2) => state.current_tab = 1,
                        KeyCode::Char('3') | KeyCode::F(3) => state.current_tab = 2,
                        _ => {}
                    }
                }
                
                // Salida de emergencia si no se puede escribir
                if key.code == KeyCode::Char('q') && state.chat_input.is_empty() {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw_ui(f: &mut ratatui::Frame, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
        .split(f.area());

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[1]);

    // Lado Izquierdo: LOGS o DHT o COMUNIDAD (Tab actual)
    if state.current_tab == 0 {
        let formatted_logs = state.logs.join("\n");
        let logs_widget = Paragraph::new(formatted_logs).block(
            Block::default()
                .title(" [ (1) Telemetría | (2) Kademlia DHT | (3) Comunidad ] ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(logs_widget, chunks[0]);
    } else if state.current_tab == 1 {
        let mut formatted_peers =
            String::from("ID SOBERANO (Base58)                      => ENDPOINT\n");
        formatted_peers
            .push_str("----------------------------------------------------------------------\n");
        for (id, addr) in &state.dht_peers {
            formatted_peers.push_str(&format!("{:<46} => {}\n", id, addr));
        }
        let dht_widget = Paragraph::new(formatted_peers).block(
            Block::default()
                .title(" [ (1) Telemetría | (2) Explorador Kademlia DHT | (3) Comunidad ] ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        );
        f.render_widget(dht_widget, chunks[0]);
    } else {
        let mut text = String::from("ANUNCIOS Y CHAT COMUNITARIO\n");
        text.push_str("══════════════════════════════════════════════════════\n\n");
        
        // Mostrar anuncios primero
        for (title, body) in &state.announcements {
            text.push_str(&format!("[!] {}: {}\n", title, body));
        }
        if !state.announcements.is_empty() { text.push_str("\n---\n\n"); }

        // Historial de Chat
        if state.chat_messages.is_empty() {
            text.push_str("¡Escribe un mensaje al desarrollador abajo para dar feedback!\n\n");
        } else {
            for msg in state.chat_messages.iter().rev().take(10).rev() {
                text.push_str(&format!("{}\n", msg));
            }
            text.push_str("\n");
        }

        // Caja de entrada
        text.push_str(&format!("> {}", state.chat_input));
        text.push_str("█"); // Cursor simulado

        let comm_widget = Paragraph::new(text).block(
            Block::default()
                .title(" [ (1) Telemetría | (2) Kademlia | (★ 3) Feedback & Community Chat ] ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightBlue)),
        );
        f.render_widget(comm_widget, chunks[0]);
    }

    // Superior Derecho: ESTADO DEL NODO
    let info = format!(
        "ID Soberano:\n{}\n\nEstado:\n{}",
        state.node_id, state.status
    );
    let info_widget = Paragraph::new(info).block(
        Block::default()
            .title(" [ Identidad Local ] ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );
    f.render_widget(info_widget, right_chunks[0]);

    // Inferior Derecho: MÉTRICAS
    let metrics = format!(
        "Conexiones Activas: 1\nAtaques Mitigados: 0\nNodos en Kademlia DHT: {}",
        state.dht_peers.len()
    );
    let metrics_widget = Paragraph::new(metrics).block(
        Block::default()
            .title(" [ Métricas y DHT ] ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(metrics_widget, right_chunks[1]);
}
