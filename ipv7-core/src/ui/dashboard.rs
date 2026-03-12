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
}

pub struct DashboardState {
    pub logs: Vec<String>,
    pub node_id: String,
    pub status: String,
    pub dht_peers: Vec<(String, String)>,
    pub current_tab: usize,
    pub announcements: Vec<(String, String)>,  // (title, body)
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
        }
    }
}

pub async fn run_dashboard(mut rx: mpsc::Receiver<TuiEvent>, initial_state: DashboardState) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = initial_state;

    loop {
        terminal.draw(|f| draw_ui(f, &state))?;

        // 1. Process network events from main loop
        if let Ok(event) = rx.try_recv() {
            match event {
                TuiEvent::LogMsg(msg) => {
                    state.logs.push(msg);
                    if state.logs.len() > 50 {
                        state.logs.remove(0); // Keep buffer bound
                    }
                }
                TuiEvent::NetworkStatus(stat) => {
                    state.status = stat;
                }
            }
        }

        // 2. Interact with keyboard events (async check)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('1') => state.current_tab = 0,
                    KeyCode::Char('2') => state.current_tab = 1,
                    KeyCode::Char('3') => state.current_tab = 2,
                    _ => {}
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
        let mut formatted_peers = String::from("ID SOBERANO (Base58)                      => ENDPOINT\n");
        formatted_peers.push_str("----------------------------------------------------------------------\n");
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
        let mut text = String::from("ANUNCIOS DEL DESARROLLADOR\n");
        text.push_str("══════════════════════════════════════════════════════\n\n");
        if state.announcements.is_empty() {
            text.push_str("Bienvenido a la red IPv7.\n\n");
            text.push_str("No hay anuncios del desarrollador por ahora.\n\n");
            text.push_str("Para enviar feedback:\n");
            text.push_str("  ipv7-core --say feature \'Quiero X funcionalidad\'\n");
            text.push_str("  ipv7-core --say bug \'El nodo no inicia en Linux\'\n");
            text.push_str("  ipv7-core --say hello \'Hola desde Argentina!\'\n");
        } else {
            for (title, body) in &state.announcements {
                text.push_str(&format!("[ {} ]\n{}\n\n", title, body));
            }
        }
        let comm_widget = Paragraph::new(text).block(
            Block::default()
                .title(" [ (1) Telemetría | (2) Kademlia | (★ 3) Comunidad & Anuncios ] ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightBlue)),
        );
        f.render_widget(comm_widget, chunks[0]);
    }

    // Superior Derecho: ESTADO DEL NODO
    let info = format!("ID Soberano:\n{}\n\nEstado:\n{}", state.node_id, state.status);
    let info_widget = Paragraph::new(info).block(
        Block::default()
            .title(" [ Identidad Local ] ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );
    f.render_widget(info_widget, right_chunks[0]);

    // Inferior Derecho: MÉTRICAS
    let metrics = format!("Conexiones Activas: 1\nAtaques Mitigados: 0\nNodos en Kademlia DHT: {}", state.dht_peers.len());
    let metrics_widget = Paragraph::new(metrics).block(
        Block::default()
            .title(" [ Métricas y DHT ] ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(metrics_widget, right_chunks[1]);
}
