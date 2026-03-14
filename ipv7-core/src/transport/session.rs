//! session.rs
//! Auténtico Gestor de Sesiones Criptográficas Asíncronas (Fase 12).
//! Reemplaza el secreto maestro predefinido (hardcodeado) almacenando dinámicamente
//! los secretos compartidos X25519 resultantes de los Handshakes orgánicos.
//! Incluye TTL por sesión para evitar acumulación de secretos obsoletos (memory leak).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Tiempo máximo que se conserva un secreto de sesión sin actividad (24 horas).
const SESSION_TTL_SECS: u64 = 86_400;

#[derive(Clone)]
pub struct SessionManager {
    /// Mapeo de Identidad IPv7 Destino (Target ID) a (Secreto Simétrico, timestamp).
    secrets: Arc<RwLock<HashMap<[u8; 32], ([u8; 32], u64)>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registra el Secreto Compartido después de un exitoso intercambio Diffie-Hellman.
    /// Sobreescribe cualquier sesión anterior con el mismo peer, actualizando el TTL.
    pub async fn add_secret(&self, peer_id: [u8; 32], shared_secret: [u8; 32]) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut map = self.secrets.write().await;
        map.insert(peer_id, (shared_secret, now));
    }

    /// Obtiene el Secreto Compartido para cifrar/descifrar el puente con ese peer.
    /// Actualiza el timestamp de last-use para extender el TTL de la sesión activa.
    pub async fn get_secret(&self, peer_id: &[u8; 32]) -> Option<[u8; 32]> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut map = self.secrets.write().await;
        if let Some(entry) = map.get_mut(peer_id) {
            if now.saturating_sub(entry.1) < SESSION_TTL_SECS {
                entry.1 = now; // Renovar TTL en cada uso
                return Some(entry.0);
            }
            // Sesión expirada: eliminar y devolver None
            map.remove(peer_id);
        }
        None
    }

    /// Elimina las sesiones cuyo TTL ha expirado para evitar fugas de memoria.
    pub async fn maintenance(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut map = self.secrets.write().await;
        map.retain(|_, (_, last_use)| now.saturating_sub(*last_use) < SESSION_TTL_SECS);
    }
}
