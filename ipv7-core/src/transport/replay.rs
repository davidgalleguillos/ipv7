//! replay.rs
//! Motor de Protección contra Ataques de Replay para IPv7.
//! Utiliza una ventana de tiempo (Anti-Aging) y un cache de Nonces acotado.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PACKET_AGE_SECS: u64 = 60; // Ventana de 1 minuto
const MAX_NONCES_PER_PEER: usize = 1000;

#[derive(Clone)]
pub struct ReplayFilter {
    /// Cache de nonces vistos por peer para deteccion inmediata.
    /// Almacena (nonce, timestamp) para permitir limpieza por tiempo.
    nonces: Arc<RwLock<HashMap<[u8; 32], (HashSet<[u8; 32]>, VecDeque<([u8; 32], u64)>)>>>,
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Validar ventana de tiempo (Anti-Aging)
        if now.saturating_sub(timestamp) > MAX_PACKET_AGE_SECS {
            return Err("Paquete demasiado antiguo (Expira ventana Anti-Aging)");
        }

        if timestamp > now + 5 {
            return Err("Paquete del futuro (Posible manipulación de reloj)");
        }

        // 2. Validar Nonce (Detección de duplicado exacto)
        let mut n_table = self.nonces.write().await;
        let (set, queue) = n_table.entry(*peer_id).or_insert_with(|| (HashSet::new(), VecDeque::new()));
        
        // Limpieza de nonces antiguos en el bucket de este peer
        while let Some((_, ts)) = queue.front() {
            if now.saturating_sub(*ts) > MAX_PACKET_AGE_SECS {
                if let Some((old_nonce, _)) = queue.pop_front() {
                    set.remove(&old_nonce);
                }
            } else {
                break;
            }
        }

        if set.contains(nonce) {
            return Err("Replay Detectado: Nonce ya utilizado por este peer");
        }
        
        // Acotar tamaño máximo por peer
        if set.len() >= MAX_NONCES_PER_PEER {
            if let Some((old_nonce, _)) = queue.pop_front() {
                set.remove(&old_nonce);
            }
        }

        set.insert(*nonce);
        queue.push_back((*nonce, timestamp));

        // 3. Validar Secuencia Monotónica
        let mut s_table = self.sequences.write().await;
        let last_seq = s_table.get(peer_id).copied().unwrap_or(0);
        
        // La secuencia 0 se ignora para compatibilidad con flujos sin estado
        if seq <= last_seq && seq != 0 {
            return Err("Inconsistencia de Secuencia: Posible ataque de retroceso");
        }
        s_table.insert(*peer_id, seq);

        Ok(())
    }

    /// Limpieza global de peers inactivos para evitar fugas de memoria
    pub async fn maintenance(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut n_table = self.nonces.write().await;
        
        // Eliminar peers que no han enviado nada en la ventana de tiempo
        n_table.retain(|_, (_, queue)| {
            if let Some((_, last_ts)) = queue.back() {
                now.saturating_sub(*last_ts) < MAX_PACKET_AGE_SECS * 2
            } else {
                false
            }
        });
    }
}
