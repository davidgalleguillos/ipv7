//! replay.rs
//! Motor de Protección contra Ataques de Replay para IPv7.
//! Utiliza una ventana de tiempo (Anti-Aging) y un cache de Nonces.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PACKET_AGE_SECS: u64 = 60; // Ventana de 1 minuto

#[derive(Clone)]
pub struct ReplayFilter {
    /// Cache de nonces vistos por peer para deteccion inmediata.
    /// Se limpia periódicamente o por límite.
    nonces: Arc<RwLock<HashMap<[u8; 32], HashSet<[u8; 32]>>>>,
    /// Último número de secuencia por peer.
    sequences: Arc<RwLock<HashMap<[u8; 32], u64>>>,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
            sequences: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Valida si un paquete es fresco y no ha sido duplicado.
    pub async fn verify_freshness(
        &self, 
        peer_id: &[u8; 32], 
        timestamp: u64, 
        nonce: &[u8; 32],
        seq: u64
    ) -> Result<(), &'static str> {
        // 1. Validar ventana de tiempo (Anti-Aging)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now.saturating_sub(timestamp) > MAX_PACKET_AGE_SECS {
            return Err("Paquete demasiado antiguo (Expira ventana Anti-Aging)");
        }

        if timestamp > now + 5 {
            return Err("Paquete del futuro (Posible manipulación de reloj)");
        }

        // 2. Validar Nonce (Detección de duplicado exacto)
        let mut n_table = self.nonces.write().await;
        let peer_nonces = n_table.entry(*peer_id).or_insert_with(HashSet::new);
        
        if peer_nonces.contains(nonce) {
            return Err("Replay Detectado: Nonce ya utilizado por este peer");
        }
        
        if peer_nonces.len() > 1000 {
            peer_nonces.clear(); // Limpieza simple para evitar memory bloat (mejorar en v2.1)
        }
        peer_nonces.insert(*nonce);

        // 3. Validar Secuencia Monotónica
        let mut s_table = self.sequences.write().await;
        let last_seq = s_table.get(peer_id).copied().unwrap_or(0);
        
        if seq <= last_seq && seq != 0 {
            return Err("Inconsistencia de Secuencia: Posible ataque de retroceso");
        }
        s_table.insert(*peer_id, seq);

        Ok(())
    }
}
