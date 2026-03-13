//! discovery.rs
//! Sistema de Bootstrap Multicapa IPv7 (Fase 14).
//!
//! CAPA 1: UDP Broadcast en LAN local (mDNS-like) → descubrimiento doméstico instantáneo
//! CAPA 2: Firebase Realtime Database → rendezvous global sin servidor central
//! CAPA 3: 7 Guardian Nodes hardcodeados → fallback de última instancia

use crate::config::bootstrap::{
    DISCOVERY_TIMEOUT_MS, FIREBASE_NODE_TTL_SECS, FIREBASE_URL, GUARDIAN_NODES, IPV7_DEFAULT_PORT,
};
use crate::config::master::DEFAULT_MESSAGE_TTL;
use crate::identity::dht::{DhtPayload, DhtRegistry};
use crate::identity::keys::NodeIdentity;
use crate::transport::packet::Ipv7Packet;

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

/// Nodo anunciado en Firebase (estructura JSON del tablón global)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirebaseNode {
    pub addr: String,
    pub id: String, // Base58 de la llave pública
    pub ts: u64,    // Unix timestamp del último anuncio
}

/// Resultado del proceso de bootstrap multicapa
pub struct BootstrapResult {
    pub lan_peers_found: usize,
    pub firebase_peers_found: usize,
    pub guardian_peers_contacted: usize,
    pub is_first_lan_node: bool,
}

/// ============================================================
/// CAPA 1: Broadcast UDP en la LAN local
/// ============================================================
pub async fn discover_lan_peers(my_node: &NodeIdentity, dht: &DhtRegistry) -> usize {
    tracing::info!("[Descubrimiento] Capa 1: Escaneando red doméstica (LAN Broadcast)...");

    // Abrir socket en modo broadcast
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[LAN] No se pudo abrir socket broadcast: {}", e);
            return 0;
        }
    };
    let _ = socket.set_broadcast(true);

    // Serializar Ping
    let ping = DhtPayload::Ping;
    let ping_bytes = match bincode::serialize(&ping) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    // Construir paquete IPv7 mínimo para el broadcast
    let mut broadcast_packet = Ipv7Packet {
        version: 7,
        source_id: *my_node.address.as_bytes(),
        destination_id: [0xFFu8; 32], // Broadcast ID
        signature: vec![0u8; 64],
        ttl: DEFAULT_MESSAGE_TTL,
        nonce: vec![0],
        encrypted_payload: ping_bytes,
    };

    // Firma Real Crítica (Resuelve alerta de Firma Inválida)
    let mut sm = Vec::new();
    sm.extend_from_slice(&broadcast_packet.source_id);
    sm.extend_from_slice(&broadcast_packet.destination_id);
    sm.extend_from_slice(&broadcast_packet.ttl.to_le_bytes());
    sm.extend_from_slice(&broadcast_packet.encrypted_payload);
    broadcast_packet.signature = my_node.sign(&sm).to_bytes().to_vec();

    let broadcast_addr = format!("255.255.255.255:{}", IPV7_DEFAULT_PORT);
    if let Ok(raw) = broadcast_packet.to_bytes() {
        let _ = socket.send_to(&raw, &broadcast_addr).await;
        tracing::info!("[LAN] Broadcast enviado → {}", broadcast_addr);
    }

    // Escuchar respuestas durante DISCOVERY_TIMEOUT_MS
    let mut peers_found = 0;
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Duration::from_millis(DISCOVERY_TIMEOUT_MS);

    while let Ok(Ok((amt, src))) = tokio::time::timeout(deadline, socket.recv_from(&mut buf)).await
    {
        if let Ok(pkt) = Ipv7Packet::from_bytes(&buf[..amt]) {
            dht.register_node(pkt.source_id, src.to_string()).await;
            peers_found += 1;
            tracing::info!("[LAN] ✓ Par doméstico detectado: {}", src);
        }
    }

    peers_found
}

/// ============================================================
/// CAPA 2: Firebase Realtime Database (Tablón Global P2P)
/// ============================================================
pub async fn firebase_bootstrap(my_id_b58: &str, my_addr: &str, dht: &DhtRegistry) -> usize {
    tracing::info!("[Descubrimiento] Capa 2: Anunciándose en Firebase Rendezvous global...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Anunciar nuestra existencia al tablón
    let my_entry = FirebaseNode {
        addr: my_addr.to_string(),
        id: my_id_b58.to_string(),
        ts: now_ts,
    };

    let post_url = format!("{}/nodes/{}.json", FIREBASE_URL, my_id_b58);
    match client.put(&post_url).json(&my_entry).send().await {
        Ok(_) => tracing::info!("[Firebase] ✓ Presencia anunciada en el tablón global."),
        Err(e) => tracing::warn!("[Firebase] No se pudo anunciar (sin internet?): {}", e),
    }

    // Obtener lista de nodos conocidos
    let get_url = format!("{}/nodes.json", FIREBASE_URL);
    let mut peers_found = 0;

    match client.get(&get_url).send().await {
        Ok(resp) => {
            if let Ok(nodes) = resp
                .json::<std::collections::HashMap<String, FirebaseNode>>()
                .await
            {
                for (_, node) in nodes.iter() {
                    // Ignorar nodos viejos
                    if now_ts.saturating_sub(node.ts) > FIREBASE_NODE_TTL_SECS {
                        continue;
                    }
                    // Ignorar a nosotros mismos
                    if node.id == my_id_b58 {
                        continue;
                    }
                    // Decodificar ID y registrar en DHT
                    if let Ok(decoded) = bs58::decode(&node.id).into_vec() {
                        if decoded.len() >= 32 {
                            let mut id = [0u8; 32];
                            id.copy_from_slice(&decoded[0..32]);
                            dht.register_node(id, node.addr.clone()).await;
                            peers_found += 1;
                            tracing::info!("[Firebase] ✓ Nodo global encontrado: {}", node.addr);
                        }
                    }
                }
            }
        }
        Err(e) => tracing::warn!("[Firebase] No se pudo consultar el tablón: {}", e),
    }

    peers_found
}

/// ============================================================
/// CAPA 3: Guardian Nodes (Fallback hardcodeado)
/// ============================================================
pub async fn contact_guardian_nodes(dht: &DhtRegistry) -> usize {
    if GUARDIAN_NODES.is_empty() {
        tracing::info!("[Guardianes] Red en período fundacional. Sin guardianes electos aún.");
        return 0;
    }

    tracing::info!(
        "[Descubrimiento] Capa 3: Contactando {} Nodos Guardianes...",
        GUARDIAN_NODES.len()
    );
    let mut contacted = 0;

    for (addr, id_b58) in GUARDIAN_NODES {
        if let Ok(decoded) = bs58::decode(id_b58).into_vec() {
            if decoded.len() >= 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&decoded[0..32]);
                dht.register_node(id, addr.to_string()).await;
                contacted += 1;
                tracing::info!("[Guardianes] Registrado: {}", addr);
            }
        }
    }
    contacted
}

/// ============================================================
/// ORQUESTADOR PRINCIPAL: Ejecuta las 3 capas en secuencia
/// ============================================================
/// ORQUESTADOR PRINCIPAL: Ejecuta las 3 capas en secuencia
/// ============================================================
pub async fn run_bootstrap(
    my_node: &NodeIdentity,
    my_id_b58: &str,
    my_addr: &str,
    dht: &DhtRegistry,
) -> BootstrapResult {
    tracing::info!("╔════════════════════════════════════════╗");
    tracing::info!("║  IPv7 Bootstrap Multicapa — Fase 14   ║");
    tracing::info!("╚════════════════════════════════════════╝");

    // Capa 1: LAN
    let lan_peers = discover_lan_peers(my_node, dht).await;
    let is_first = lan_peers == 0;

    if is_first {
        tracing::info!("🎉 ¡ERES EL PRIMER NODO IPv7 EN TU RED DOMÉSTICA!");
        tracing::info!("   Tu red nunca más caerá y se replicará automáticamente");
        tracing::info!("   en todos los dispositivos de tu red local.");
    } else {
        tracing::info!("✓ Unido a {} nodo(s) en tu red doméstica.", lan_peers);
    }

    // Capa 2: Firebase
    let firebase_peers = firebase_bootstrap(my_id_b58, my_addr, dht).await;

    // Capa 3: Guardianes (solo si no encontramos nada aún)
    let total_known = dht.peer_count().await;
    let guardian_peers = if total_known == 0 {
        contact_guardian_nodes(dht).await
    } else {
        0
    };

    let result = BootstrapResult {
        lan_peers_found: lan_peers,
        firebase_peers_found: firebase_peers,
        guardian_peers_contacted: guardian_peers,
        is_first_lan_node: is_first,
    };

    tracing::info!("─────────────────────────────────────────");
    tracing::info!("  Red Local:   {} nodo(s)", result.lan_peers_found);
    tracing::info!(
        "  Global:      {} nodo(s) vía Firebase",
        result.firebase_peers_found
    );
    tracing::info!(
        "  Guardianes:  {} nodo(s) de respaldo",
        result.guardian_peers_contacted
    );
    tracing::info!("─────────────────────────────────────────");

    result
}
