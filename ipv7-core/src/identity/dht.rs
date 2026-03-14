//! dht.rs
//! Implementación Industrial de Kademlia DHT para IPv7 con K-Buckets.
//! Mapea Identidades IPv7 (Llaves Públicas ED25519) a sus endpoints físicos (IP:Puerto).
//! Utiliza métricas XOR y buckets LRU para escalabilidad masiva y resiliencia.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// K-Value estándar de Kademlia para redundancia (20 es el valor sugerido en el paper original).
pub const K_VALUE: usize = 20;
/// Número máximo de buckets para IDs de 256 bits.
pub const MAX_BUCKETS: usize = 256;
/// Tiempo de vida de un nodo antes de ser considerado muerto (1 hora).
pub const NODE_TTL_SECS: u64 = 3600;

/// Estructura de Mensajes Orgánicos del protocolo de enrutamiento DHT.
/// Sirven para NAT Punching (Ping/Pong) y para descubrimiento de topología (FindNode).
#[derive(Serialize, Deserialize, Debug)]
pub enum DhtPayload {
    Ping,
    Pong,
    FindNode { target: [u8; 32] },
    NodeList { peers: Vec<([u8; 32], String)> },
}

/// Registro detallado de un par en la red.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub id: [u8; 32],
    pub addr: String,
    pub last_seen: u64,
    pub rtt_est: u32,
    pub failures: u8,
    pub reputation: i32,
}

impl PeerRecord {
    pub fn new(id: [u8; 32], addr: String) -> Self {
        Self {
            id,
            addr,
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            rtt_est: 0,
            failures: 0,
            reputation: 0,
        }
    }

    pub fn update_seen(&mut self) {
        self.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.failures = 0;
    }
}

/// Un K-Bucket que almacena hasta K registros de pares con política LRU.
#[derive(Default, Clone, Debug)]
pub struct KBucket {
    pub entries: VecDeque<PeerRecord>,
}

impl KBucket {
    pub fn insert(&mut self, record: PeerRecord) -> Option<PeerRecord> {
        // Si ya existe, lo movemos al final (LRU: más reciente al final)
        if let Some(pos) = self.entries.iter().position(|r| r.id == record.id) {
            let mut existing = self.entries.remove(pos).unwrap();
            existing.addr = record.addr;
            existing.update_seen();
            self.entries.push_back(existing);
            return None;
        }

        // Si el bucket está lleno, devolvemos el LRU (front) para que el llamador lo verifique (ping)
        if self.entries.len() >= K_VALUE {
            return Some(self.entries.front().cloned().unwrap());
        }

        // Si hay espacio, simplemente insertamos al final
        self.entries.push_back(record);
        None
    }

    pub fn remove(&mut self, id: &[u8; 32]) {
        if let Some(pos) = self.entries.iter().position(|r| r.id == *id) {
            self.entries.remove(pos);
        }
    }
}

/// Calcula la distancia matemática XOR entre dos identidades IPv7
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

/// Calcula el índice del bucket basado en el bit más significativo diferente (XOR).
pub fn bucket_index(local_id: &[u8; 32], peer_id: &[u8; 32]) -> usize {
    let dist = xor_distance(local_id, peer_id);
    for (i, byte) in dist.iter().enumerate() {
        if *byte != 0 {
            let leading_zeros = byte.leading_zeros();
            // i=0 is most significant byte (bits 248-255)
            // i=31 is least significant byte (bits 0-7)
            return (31 - i) * 8 + (8 - leading_zeros as usize) - 1;
        }
    }
    0
}

#[derive(Clone)]
pub struct DhtRegistry {
    pub local_id: [u8; 32],
    /// K-Buckets: Tablas de ruteo escalables O(log N)
    pub buckets: Arc<RwLock<Vec<KBucket>>>,
}

impl DhtRegistry {
    /// Inicializa un enrutador DHT basado en el ID local Soberano.
    pub fn new(local_id: [u8; 32]) -> Self {
        let mut buckets = Vec::with_capacity(MAX_BUCKETS);
        for _ in 0..MAX_BUCKETS {
            buckets.push(KBucket::default());
        }
        Self {
            local_id,
            buckets: Arc::new(RwLock::new(buckets)),
        }
    }

    /// Registra de forma asíncrona un nodo visualizado en la red (Kademlia Insert)
    pub async fn register_node(&self, pubkey: [u8; 32], physical_address: String) {
        if pubkey == self.local_id {
            return;
        }

        let idx = bucket_index(&self.local_id, &pubkey);
        let mut buckets = self.buckets.write().await;
        
        let record = PeerRecord::new(pubkey, physical_address);
        if let Some(_lru_candidate) = buckets[idx].insert(record) {
            // TODO: En v2.2 disparar un PING al lru_candidate.
            // Si el PING falla, remover lru_candidate e insertar el nuevo record.
            // Por ahora, simplemente mantenemos los existentes si el bucket está lleno.
        }
    }

    /// Búsqueda de un nodo en la tabla de ruteo local.
    pub async fn lookup(&self, pubkey: &[u8; 32]) -> Option<String> {
        let idx = bucket_index(&self.local_id, pubkey);
        let buckets = self.buckets.read().await;
        buckets[idx].entries.iter()
            .find(|r| r.id == *pubkey)
            .map(|r| r.addr.clone())
    }

    /// Obtiene los K nodos más cercanos conocidos por XOR (Routing Real)
    pub async fn get_closest_peers(&self, target: &[u8; 32]) -> Vec<([u8; 32], String)> {
        let target_idx = bucket_index(&self.local_id, target);
        let buckets = self.buckets.read().await;
        
        let mut closest = Vec::new();
        
        // Empezar por el bucket del target y expandir hacia afuera
        let mut offset = 0;
        while closest.len() < K_VALUE && offset < MAX_BUCKETS {
            // Revisar bucket a la derecha
            if target_idx + offset < MAX_BUCKETS {
                for entry in &buckets[target_idx + offset].entries {
                    if closest.len() < K_VALUE {
                        closest.push((entry.id, entry.addr.clone()));
                    }
                }
            }
            
            // Revisar bucket a la izquierda
            if offset > 0 && target_idx >= offset {
                for entry in &buckets[target_idx - offset].entries {
                    if closest.len() < K_VALUE {
                        closest.push((entry.id, entry.addr.clone()));
                    }
                }
            }
            offset += 1;
        }
        
        closest
    }

    /// Cuántos pares conoce este nodo en total
    pub async fn peer_count(&self) -> usize {
        let buckets = self.buckets.read().await;
        buckets.iter().map(|b| b.entries.len()).sum()
    }

    /// Devuelve un volcado de la tabla para visualización administrativa en el TUI.
    pub async fn snapshot_peers(&self) -> Vec<(String, String)> {
        let buckets = self.buckets.read().await;
        let mut snapshot = Vec::new();
        for b in buckets.iter() {
            for entry in &b.entries {
                snapshot.push((bs58::encode(entry.id).into_string(), entry.addr.clone()));
            }
        }
        snapshot
    }

    /// Limpieza periódica: elimina nodos que han expirado
    pub async fn maintenance(&self) {
        let mut buckets = self.buckets.write().await;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        for b in buckets.iter_mut() {
            b.entries.retain(|r| now - r.last_seen < NODE_TTL_SECS);
        }
    }
}
