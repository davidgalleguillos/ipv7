//! session.rs
//! Auténtico Gestor de Sesiones Criptográficas Asíncronas (Fase 12).
//! Reemplaza el secreto maestro predefinido (hardcodeado) almacenando dinámicamente
//! los secretos compartidos X25519 resultantes de los Handshakes orgánicos.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct SessionManager {
    /// Mapeo de Identidad IPv7 Destino (Target ID) a Secreto Símétrico ChaCha20
    secrets: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registra el Secreto Compartido después de un exitoso intercambio Diffie-Hellman
    pub async fn add_secret(&self, peer_id: [u8; 32], shared_secret: [u8; 32]) {
        let mut map = self.secrets.write().await;
        map.insert(peer_id, shared_secret);
    }

    /// Obtiene el Secreto Compartido para cifrar/descifrar el puente con ese peer
    pub async fn get_secret(&self, peer_id: &[u8; 32]) -> Option<[u8; 32]> {
        let map = self.secrets.read().await;
        map.get(peer_id).cloned()
    }
}
