//! overlay.rs
//! Capa de Abstracción UDP
//! Aquí se inicializan los Sockets P2P de Tokio permitiendo envíos sin cuellos de botella
//! mediante cascada pseudoaleatoria y puertos descentralizados.
//! Incluye guardia singleton para evitar múltiples listeners competidores en el mismo proceso.

use crate::config::master::{MAX_SUBPORT_ATTEMPTS, MIN_PORT_RANGE};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Guardia global: garantiza que sólo se crea un listener UDP por proceso.
static LISTENER_ACTIVE: AtomicBool = AtomicBool::new(false);

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
    /// Devuelve error si ya existe un listener activo en este proceso (singleton).
    pub async fn start_listener(listen_ip: &str) -> std::io::Result<Self> {
        // Singleton: impedir listeners duplicados dentro del mismo proceso.
        if LISTENER_ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Ya existe un listener UDP activo en este proceso IPv7.",
            ));
        }

        let mut attempt = 0;
        let mut current_port = MIN_PORT_RANGE;

        loop {
            let bind_addr = format!("{}:{}", listen_ip, current_port);

            match UdpSocket::bind(&bind_addr).await {
                Ok(sock) => {
                    tracing::info!(
                        "[+] Overlay UDP Exitoso. Estacionado en Cascada (Nivel {}), Subpuerto: {}",
                        attempt,
                        current_port
                    );
                    return Ok(OverlayRelay {
                        socket: Arc::new(sock),
                        bound_port: current_port,
                    });
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_SUBPORT_ATTEMPTS as u32 {
                        // Liberar la guardia si la cascada falla completamente.
                        LISTENER_ACTIVE.store(false, Ordering::Release);
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
    pub async fn send_raw_packet(
        &self,
        payload: &[u8],
        target_addr_ipv4: &str,
    ) -> std::io::Result<usize> {
        self.socket.send_to(payload, target_addr_ipv4).await
    }
}

impl Drop for OverlayRelay {
    /// Al destruir el relay liberamos la guardia singleton para permitir reinicio limpio.
    fn drop(&mut self) {
        LISTENER_ACTIVE.store(false, Ordering::Release);
    }
}
