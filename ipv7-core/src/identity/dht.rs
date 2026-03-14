//! dht.rs
//! Implementación Kademlia K-Bucket DHT para IPv7 v1.3.0.
//! Mapea Identidades IPv7 (Llaves Públicas ED25519) a sus endpoints físicos (IP:Puerto).
//! Usa métricas XOR con tabla de 256 buckets, tamaño k=20 con semántica LRU,
//! metadatos de peer (last_seen, failed_pings) y limpieza por TTL.

use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Tamaño máximo de cada bucket (k de Kademlia).
pub const K_BUCKET_SIZE: usize = 20;
/// Número de buckets = bits en la clave (256 para ED25519).
const NUM_BUCKETS: usize = 256;
/// TTL de peer inactivo en segundos (10 minutos).
const PEER_TTL_SECS: u64 = 600;

/// Estructura de Mensajes Orgánicos del protocolo de enrutamiento DHT.
/// Sirven para NAT Punching (Ping/Pong) y para descubrimiento de topología (FindNode).
#[derive(Serialize, Deserialize, Debug)]
pub enum DhtPayload {
    Ping,
    Pong,
    FindNode { target: [u8; 32] },
    NodeList { peers: Vec<([u8; 32], String)> },
}

/// Metadatos de un peer conocido en la tabla de routing.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Llave pública del peer (su identidad IPv7).
    pub pubkey: [u8; 32],
    /// Endpoint físico IP:Puerto.
    pub address: String,
    /// Timestamp Unix (segundos) del último paquete recibido de este peer.
    pub last_seen: u64,
    /// Número de pings consecutivos sin respuesta (para evicción).
    pub failed_pings: u32,
    /// Reputación opcional [0, 100].
    pub reputation: Option<u8>,
}

impl PeerInfo {
    fn new(pubkey: [u8; 32], address: String) -> Self {
        Self {
            pubkey,
            address,
            last_seen: now_secs(),
            failed_pings: 0,
            reputation: None,
        }
    }

    fn is_stale(&self) -> bool {
        now_secs().saturating_sub(self.last_seen) > PEER_TTL_SECS
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Calcula la distancia matemática XOR entre dos identidades IPv7.
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

/// Calcula el índice del bucket según la posición del bit más significativo del XOR.
/// Retorna un valor en [0, 255]. IDs idénticos retornan 0 (imposible en uso normal).
pub fn bucket_index(local: &[u8; 32], remote: &[u8; 32]) -> usize {
    for i in 0..32 {
        let xor_byte = local[i] ^ remote[i];
        if xor_byte != 0 {
            // Bit más significativo en el byte i
            let bit_pos = 7 - xor_byte.leading_zeros() as usize;
            return i * 8 + bit_pos;
        }
    }
    0 // IDs idénticos — ignoramos en register_node
}

/// Tabla de K-Buckets Kademlia para enrutamiento escalable.
///
/// - 256 buckets, uno por posición de bit en el espacio de claves de 256 bits.
/// - Cada bucket almacena hasta K_BUCKET_SIZE (20) peers con semántica LRU.
/// - Limpieza automática de peers caducados (TTL = 10 min).
#[derive(Clone)]
pub struct DhtRegistry {
    pub local_id: [u8; 32],
    /// Tabla de buckets protegida por RwLock para acceso concurrente.
    buckets: Arc<RwLock<Vec<LruCache<[u8; 32], PeerInfo>>>>,
}

impl DhtRegistry {
    /// Inicializa la tabla DHT basada en el ID local Soberano.
    pub fn new(local_id: [u8; 32]) -> Self {
        let k = NonZeroUsize::new(K_BUCKET_SIZE).expect("K_BUCKET_SIZE > 0");
        let buckets = (0..NUM_BUCKETS).map(|_| LruCache::new(k)).collect();
        Self {
            local_id,
            buckets: Arc::new(RwLock::new(buckets)),
        }
    }

    /// Registra de forma asíncrona un nodo en el bucket correspondiente.
    /// Si el nodo ya existe, actualiza su endpoint y `last_seen`.
    /// Si el bucket está lleno, evicta el peer LRU (más antiguo no actualizado).
    pub async fn register_node(&self, pubkey: [u8; 32], physical_address: String) {
        if pubkey == self.local_id {
            return; // No nos registramos a nosotros mismos
        }
        let idx = bucket_index(&self.local_id, &pubkey);
        let mut buckets = self.buckets.write().await;
        let bucket = &mut buckets[idx];

        if let Some(existing) = bucket.get_mut(&pubkey) {
            // Peer ya conocido: actualizar endpoint y timestamp
            existing.address = physical_address;
            existing.last_seen = now_secs();
            existing.failed_pings = 0;
        } else {
            // Peer nuevo: insertar (LruCache evicta el más antiguo si está lleno)
            bucket.put(pubkey, PeerInfo::new(pubkey, physical_address));
        }
    }

    /// Búsqueda exacta de un nodo en la tabla local.
    /// Retorna None si no está presente (en Kademlia se dispararía un FIND_NODE).
    pub async fn lookup(&self, pubkey: &[u8; 32]) -> Option<String> {
        let idx = bucket_index(&self.local_id, pubkey);
        let buckets = self.buckets.read().await;
        buckets[idx].peek(pubkey).map(|p| p.address.clone())
    }

    /// Obtiene los `count` nodos más cercanos al `target` por distancia XOR.
    /// Recorre todos los buckets y ordena por distancia.
    pub async fn get_closest_peers(
        &self,
        target: &[u8; 32],
        count: usize,
    ) -> Vec<([u8; 32], String)> {
        let buckets = self.buckets.read().await;
        let mut all: Vec<([u8; 32], String, [u8; 32])> = buckets
            .iter()
            .flat_map(|b| {
                b.iter()
                    .filter(|(_, p)| !p.is_stale())
                    .map(|(k, p)| (*k, p.address.clone(), xor_distance(k, target)))
            })
            .collect();

        all.sort_by(|a, b| a.2.cmp(&b.2));
        all.into_iter()
            .take(count)
            .map(|(id, addr, _)| (id, addr))
            .collect()
    }

    /// Cuántos peers no-caducados conoce este nodo.
    pub async fn peer_count(&self) -> usize {
        let buckets = self.buckets.read().await;
        buckets
            .iter()
            .flat_map(|b| b.iter())
            .filter(|(_, p)| !p.is_stale())
            .count()
    }

    /// Devuelve un volcado de la tabla para visualización en el TUI.
    /// Formato: (Base58_ID, endpoint).
    pub async fn snapshot_peers(&self) -> Vec<(String, String)> {
        let buckets = self.buckets.read().await;
        buckets
            .iter()
            .flat_map(|b| b.iter())
            .filter(|(_, p)| !p.is_stale())
            .map(|(k, p)| (bs58::encode(k).into_string(), p.address.clone()))
            .collect()
    }

    /// Elimina peers caducados de todos los buckets (llamar periódicamente).
    pub async fn evict_stale_peers(&self) {
        let mut buckets = self.buckets.write().await;
        for bucket in buckets.iter_mut() {
            let stale_keys: Vec<[u8; 32]> = bucket
                .iter()
                .filter(|(_, p)| p.is_stale())
                .map(|(k, _)| *k)
                .collect();
            for k in stale_keys {
                bucket.pop(&k);
            }
        }
    }

    /// Incrementa el contador de pings fallidos de un peer.
    /// Si supera el umbral (3), lo elimina del bucket.
    pub async fn record_failed_ping(&self, pubkey: &[u8; 32]) {
        let idx = bucket_index(&self.local_id, pubkey);
        let mut buckets = self.buckets.write().await;
        let bucket = &mut buckets[idx];
        if let Some(peer) = bucket.get_mut(pubkey) {
            peer.failed_pings += 1;
            if peer.failed_pings >= 3 {
                bucket.pop(pubkey);
            }
        }
    }

    /// Devuelve un mapa plano pubkey→address para compatibilidad con código existente.
    pub async fn flat_snapshot(&self) -> HashMap<[u8; 32], String> {
        let buckets = self.buckets.read().await;
        buckets
            .iter()
            .flat_map(|b| b.iter())
            .map(|(k, p)| (*k, p.address.clone()))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────
// Tests unitarios
// ─────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    // ── bucket_index ──────────────────────────────────────────

    #[test]
    fn test_bucket_index_msb_byte0() {
        let local = make_id(0b0000_0001);
        let remote = make_id(0b1000_0001); // primer bit diferente → bit 7 del byte 0
        assert_eq!(bucket_index(&local, &remote), 7);
    }

    #[test]
    fn test_bucket_index_lsb_byte0() {
        let local = make_id(0b0000_0000);
        let remote = make_id(0b0000_0001); // bit 0 del byte 0
        assert_eq!(bucket_index(&local, &remote), 0);
    }

    #[test]
    fn test_bucket_index_byte1() {
        let local = [0u8; 32];
        let mut remote = [0u8; 32];
        remote[1] = 0b1000_0000; // bit 7 del byte 1 → índice 15
        assert_eq!(bucket_index(&local, &remote), 15);
    }

    #[test]
    fn test_bucket_index_identical() {
        let id = make_id(0xAB);
        assert_eq!(bucket_index(&id, &id), 0);
    }

    // ── inserción / evicción ──────────────────────────────────

    #[tokio::test]
    async fn test_register_and_lookup() {
        let local = make_id(0x00);
        let dht = DhtRegistry::new(local);
        let peer_id = make_id(0x80); // bucket 7
        dht.register_node(peer_id, "1.2.3.4:9000".to_string()).await;
        assert_eq!(dht.lookup(&peer_id).await, Some("1.2.3.4:9000".to_string()));
    }

    #[tokio::test]
    async fn test_update_existing_peer() {
        let local = make_id(0x00);
        let dht = DhtRegistry::new(local);
        let peer_id = make_id(0x80);
        dht.register_node(peer_id, "1.2.3.4:9000".to_string()).await;
        dht.register_node(peer_id, "5.6.7.8:9001".to_string()).await;
        assert_eq!(dht.lookup(&peer_id).await, Some("5.6.7.8:9001".to_string()));
    }

    #[tokio::test]
    async fn test_lru_eviction_at_k_limit() {
        let local = [0u8; 32];
        let dht = DhtRegistry::new(local);

        // Insertar K_BUCKET_SIZE + 1 peers que caigan en el mismo bucket (byte 0 = 0x80..0x9F)
        // Todos tienen byte 0 con bit 7 = 1 → bucket index 7
        for i in 0..=(K_BUCKET_SIZE as u8) {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[1] = i; // diferenciador
            dht.register_node(id, format!("1.2.3.{}:9000", i)).await;
        }

        // peer_count debe ser ≤ K_BUCKET_SIZE (LRU evicta el más antiguo)
        let count = dht.peer_count().await;
        assert!(count <= K_BUCKET_SIZE, "Count {} > k={}", count, K_BUCKET_SIZE);
    }

    #[tokio::test]
    async fn test_do_not_register_self() {
        let local = make_id(0x01);
        let dht = DhtRegistry::new(local);
        dht.register_node(local, "127.0.0.1:9000".to_string()).await;
        assert_eq!(dht.peer_count().await, 0);
    }

    // ── get_closest_peers ─────────────────────────────────────

    #[tokio::test]
    async fn test_closest_peers_sorted_by_xor() {
        let local = [0u8; 32];
        let dht = DhtRegistry::new(local);

        // Insertar tres peers con distancias conocidas al target [0xFF, 0, ...]
        let mut target = [0u8; 32];
        target[0] = 0xFF;

        // peer A: id [0xFE, ...] → XOR con target = [0x01, ...] (muy cercano)
        let mut a = [0u8; 32];
        a[0] = 0xFE;
        dht.register_node(a, "10.0.0.1:9000".to_string()).await;

        // peer B: id [0x80, ...] → XOR con target = [0x7F, ...] (medio)
        let mut b = [0u8; 32];
        b[0] = 0x80;
        dht.register_node(b, "10.0.0.2:9000".to_string()).await;

        // peer C: id [0x01, ...] → XOR con target = [0xFE, ...] (lejano)
        let mut c = [0u8; 32];
        c[0] = 0x01;
        dht.register_node(c, "10.0.0.3:9000".to_string()).await;

        let closest = dht.get_closest_peers(&target, 3).await;
        assert_eq!(closest.len(), 3);
        assert_eq!(closest[0].0, a); // A es el más cercano
        assert_eq!(closest[2].0, c); // C es el más lejano
    }

    #[tokio::test]
    async fn test_closest_peers_limited_by_count() {
        let local = [0u8; 32];
        let dht = DhtRegistry::new(local);
        for i in 1u8..=10 {
            let mut id = [0u8; 32];
            id[0] = i;
            dht.register_node(id, format!("10.0.0.{}:9000", i)).await;
        }
        let result = dht.get_closest_peers(&local, 5).await;
        assert_eq!(result.len(), 5);
    }

    // ── failed_ping / evicción activa ─────────────────────────

    #[tokio::test]
    async fn test_failed_ping_eviction() {
        let local = make_id(0x00);
        let dht = DhtRegistry::new(local);
        let peer_id = make_id(0x80);
        dht.register_node(peer_id, "1.2.3.4:9000".to_string()).await;

        dht.record_failed_ping(&peer_id).await;
        dht.record_failed_ping(&peer_id).await;
        assert!(dht.lookup(&peer_id).await.is_some()); // Aún presente con 2 fallos

        dht.record_failed_ping(&peer_id).await; // 3er fallo → evicción
        assert!(dht.lookup(&peer_id).await.is_none());
    }

    // ── snapshot_peers ────────────────────────────────────────

    #[tokio::test]
    async fn test_snapshot_peers_returns_base58() {
        let local = [0u8; 32];
        let dht = DhtRegistry::new(local);
        let mut peer_id = [0u8; 32];
        peer_id[0] = 0x42;
        dht.register_node(peer_id, "9.9.9.9:9000".to_string()).await;

        let snap = dht.snapshot_peers().await;
        assert_eq!(snap.len(), 1);
        let (b58_id, addr) = &snap[0];
        assert_eq!(b58_id, &bs58::encode(&peer_id).into_string());
        assert_eq!(addr, "9.9.9.9:9000");
    }

    // ── xor_distance ──────────────────────────────────────────

    #[test]
    fn test_xor_distance_reflexive() {
        let id = make_id(0xAB);
        assert_eq!(xor_distance(&id, &id), [0u8; 32]);
    }

    #[test]
    fn test_xor_distance_symmetric() {
        let a = make_id(0x0F);
        let b = make_id(0xF0);
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }
}
