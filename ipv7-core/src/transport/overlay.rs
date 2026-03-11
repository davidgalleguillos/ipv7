//! overlay.rs
//! Capa de Abstracción UDP 
//! Aquí se inicializan los Sockets P2P de Tokio permitiendo envíos sin cuellos de botella 
//! mediante cascada pseudoaleatoria y puertos descentralizados.

use tokio::net::UdpSocket;
use std::sync::Arc;
use crate::config::master::{MIN_PORT_RANGE, MAX_SUBPORT_ATTEMPTS};

pub struct OverlayRelay {
    /// El canal asíncrono físico local "bindeado" (enganchado).
    pub socket: Arc<UdpSocket>,
    /// El puerto subport final en el que este nodo decidió estacionarse
    pub bound_port: u32,
}

impl OverlayRelay {
    /// Inicia el Demonio Escucha (Listener) de IPv7.
    /// Realiza una "Cascada" de saltos usando MAX_SUBPORT_ATTEMPTS descritos en master.rs
    /// Trata de bindear desde 65553, si falla, avanza matemáticamente.
    pub async fn start_listener(listen_ip: &str) -> std::io::Result<Self> {
        let mut attempt = 0;
        let mut current_port = MIN_PORT_RANGE;

        loop {
            let bind_addr = format!("{}:{}", listen_ip, current_port);
            
            match UdpSocket::bind(&bind_addr).await {
                Ok(sock) => {
                    tracing::info!("[+] Overlay UDP Exitoso. Estacionado en Cascada (Nivel {}), Subpuerto: {}", attempt, current_port);
                    return Ok(OverlayRelay {
                        socket: Arc::new(sock),
                        bound_port: current_port,
                    });
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_SUBPORT_ATTEMPTS as u32 {
                        tracing::error!("[!] Fallo catastrófico de Cascada IPv7: No se pudo enlazar ningún socket. {}", e);
                        return Err(e);
                    }
                    // Matemática de rotación de subpuerto
                    tracing::warn!("[-] Subpuerto en uso o bloqueado ({}). Cascada actuando -> Rotando al nivel {}...", current_port, attempt);
                    current_port += 1; // Salto simple (podría ser un salto pseudoaleatorio basado en X25519)
                }
            }
        }
    }

    /// Método asíncrono simple que envía un datagrama empacado crudo hacia una ruta IPv4 tradicional
    /// Esto simula a qué nivel opera nuestra encapsulación.
    pub async fn send_raw_packet(&self, payload: &[u8], target_addr_ipv4: &str) -> std::io::Result<usize> {
        self.socket.send_to(payload, target_addr_ipv4).await
    }
}
