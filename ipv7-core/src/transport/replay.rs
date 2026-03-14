//! replay.rs
//! Motor de Protección contra Ataques de Replay para IPv7 v1.3.0.
//! Utiliza una ventana de tiempo (Anti-Aging), un cache LRU de Nonces
//! acotado por peer, y validación de secuencia monotónica.

use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Ventana de tiempo máxima para aceptar paquetes (60 segundos).
const MAX_PACKET_AGE_SECS: u64 = 60;
/// Número máximo de nonces a recordar por peer (limita memoria).
const MAX_NONCES_PER_PEER: usize = 512;
/// Número máximo de peers tracked en el cache de nonces.
const MAX_TRACKED_PEERS: usize = 4096;

#[derive(Clone)]
pub struct ReplayFilter {
    /// Cache acotado LRU de nonces vistos por peer.
    /// Outer: peer_id → LruCache<nonce, ()>.
    nonces: Arc<RwLock<LruCache<[u8; 32], LruCache<[u8; 32], ()>>>>,
    /// Último número de secuencia por peer.
    sequences: Arc<RwLock<HashMap<[u8; 32], u64>>>,
}

impl ReplayFilter {
    pub fn new() -> Self {
        let max_peers = NonZeroUsize::new(MAX_TRACKED_PEERS).expect("MAX_TRACKED_PEERS > 0");
        Self {
            nonces: Arc::new(RwLock::new(LruCache::new(max_peers))),
            sequences: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Valida si un paquete es fresco y no ha sido duplicado.
    pub async fn verify_freshness(
        &self,
        peer_id: &[u8; 32],
        timestamp: u64,
        nonce: &[u8; 32],
        seq: u64,
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

        // 2. Validar Nonce (Detección de duplicado exacto) con cache LRU acotado
        let mut n_table = self.nonces.write().await;
        let max_nonces =
            NonZeroUsize::new(MAX_NONCES_PER_PEER).expect("MAX_NONCES_PER_PEER > 0");
        let peer_nonces = n_table
            .get_or_insert_mut(*peer_id, || LruCache::new(max_nonces));

        if peer_nonces.contains(nonce) {
            return Err("Replay Detectado: Nonce ya utilizado por este peer");
        }
        peer_nonces.put(*nonce, ());

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

// ─────────────────────────────────────────────────────────────
// Tests unitarios
// ─────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn nonce(byte: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = byte;
        n
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn test_fresh_packet_accepted() {
        let rf = ReplayFilter::new();
        let result = rf
            .verify_freshness(&peer(1), now(), &nonce(1), 1)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_replay_nonce_rejected() {
        let rf = ReplayFilter::new();
        let p = peer(2);
        let n = nonce(42);
        let ts = now();
        rf.verify_freshness(&p, ts, &n, 1).await.unwrap();
        let err = rf.verify_freshness(&p, ts, &n, 2).await;
        assert!(err.is_err(), "El nonce duplicado debe ser rechazado");
    }

    #[tokio::test]
    async fn test_old_packet_rejected() {
        let rf = ReplayFilter::new();
        let old_ts = now() - MAX_PACKET_AGE_SECS - 10;
        let err = rf
            .verify_freshness(&peer(3), old_ts, &nonce(3), 1)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_future_packet_rejected() {
        let rf = ReplayFilter::new();
        let future_ts = now() + 100;
        let err = rf
            .verify_freshness(&peer(4), future_ts, &nonce(4), 1)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_sequence_rollback_rejected() {
        let rf = ReplayFilter::new();
        let p = peer(5);
        let ts = now();
        rf.verify_freshness(&p, ts, &nonce(10), 10).await.unwrap();
        let err = rf.verify_freshness(&p, ts, &nonce(11), 5).await;
        assert!(err.is_err(), "Retroceso de secuencia debe rechazarse");
    }

    #[tokio::test]
    async fn test_sequence_zero_always_accepted() {
        let rf = ReplayFilter::new();
        let p = peer(6);
        let ts = now();
        // seq=0 es siempre aceptado (paquetes sin secuencia como pings)
        assert!(rf.verify_freshness(&p, ts, &nonce(20), 0).await.is_ok());
        assert!(rf.verify_freshness(&p, ts, &nonce(21), 0).await.is_ok());
    }

    #[tokio::test]
    async fn test_lru_nonce_cache_bounded() {
        let rf = ReplayFilter::new();
        let p = peer(7);
        let ts = now();

        // Insertar MAX_NONCES_PER_PEER + 1 nonces distintos en el mismo peer
        for i in 0u32..=(MAX_NONCES_PER_PEER as u32) {
            let mut n = [0u8; 32];
            n[0] = (i & 0xFF) as u8;
            n[1] = ((i >> 8) & 0xFF) as u8;
            // El número de secuencia siempre aumenta
            let _ = rf.verify_freshness(&p, ts, &n, i as u64 + 1).await;
        }
        // El cache no debe crecer más allá del límite (no hay panic/OOM)
        // Verificamos que un nonce nuevo (fuera del cache LRU) es aceptado
        let mut fresh_nonce = [0xFF_u8; 32];
        fresh_nonce[0] = 0xFE;
        let seq = MAX_NONCES_PER_PEER as u64 + 100;
        assert!(rf.verify_freshness(&p, ts, &fresh_nonce, seq).await.is_ok());
    }

    #[tokio::test]
    async fn test_different_peers_independent() {
        let rf = ReplayFilter::new();
        let ts = now();
        let n = nonce(99);
        // El mismo nonce de dos peers distintos es independiente
        assert!(rf.verify_freshness(&peer(8), ts, &n, 1).await.is_ok());
        assert!(rf.verify_freshness(&peer(9), ts, &n, 1).await.is_ok());
    }
}
