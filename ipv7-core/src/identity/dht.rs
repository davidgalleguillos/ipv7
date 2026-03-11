//! dht.rs
//! Implementación Fundacional de Kademlia DHT para IPv7.
//! Mapea Identidades IPv7 (Llaves Públicas ED25519) a sus endpoints físicos (IP:Puerto).
//! Utiliza métricas XOR concurrentes para el enrutamiento descentralizado.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Calcula la distancia matemática XOR entre dos identidades IPv7
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

#[derive(Clone)]
pub struct DhtRegistry {
    pub local_id: [u8; 32],
    /// K-Buckets simplificados: Mapeo de Identidad a Endpoint validado
    pub nodes: Arc<RwLock<HashMap<[u8; 32], String>>>,
}

impl DhtRegistry {
    /// Inicializa un enrutador DHT basado en el ID local Soberano.
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            local_id,
            nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registra de forma asíncrona un nodo visualizado en la red
    pub async fn register_node(&self, pubkey: [u8; 32], physical_address: String) {
        let mut table = self.nodes.write().await;
        table.insert(pubkey, physical_address);
    }

    /// Búsqueda de un nodo en la tabla de ruteo local.
    /// Si no existe, devuelve None (Aquí Kademlia dispararía un FIND_NODE).
    pub async fn lookup(&self, pubkey: &[u8; 32]) -> Option<String> {
        let table = self.nodes.read().await;
        table.get(pubkey).cloned()
    }
    
    /// Devuelve un volcado de la tabla para visualización administrativa en el TUI.
    pub async fn snapshot_peers(&self) -> Vec<(String, String)> {
        let table = self.nodes.read().await;
        table.iter().map(|(k, v)| (bs58::encode(k).into_string(), v.clone())).collect()
    }
}
