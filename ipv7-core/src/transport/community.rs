//! community.rs
//! Canal de Comunicación Bidireccional con el Desarrollador (Fase 15).
//!
//! Firebase paths:
//!   /announcements/{id}  → Desarrollador → Todos los nodos (broadcast)
//!   /community/{id}      → Nodo usuario → Desarrollador (feedback, bugs, hola)

use crate::config::bootstrap::FIREBASE_URL;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Anuncio publicado por el Desarrollador (solo él puede escribir con Admin SDK)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DevAnnouncement {
    pub title: String,
    pub body: String,
    pub url: Option<String>, // Link externo (GitHub release, docs, etc.)
    pub ts: u64,
}

/// Mensaje enviado por un nodo hacia el desarrollador
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommunityMessage {
    pub node_id: String,  // Base58 del nodo remitente
    pub category: String, // "bug" | "feature" | "hello" | "contrib"
    pub msg: String,
    pub ts: u64,
    pub version: String, // Versión del binario
}

const BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Obtiene los anuncios del desarrollador desde Firebase
pub async fn fetch_announcements() -> Vec<DevAnnouncement> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let url = format!("{}/announcements.json", FIREBASE_URL);

    match client.get(&url).send().await {
        Ok(resp) => {
            match resp
                .json::<std::collections::HashMap<String, DevAnnouncement>>()
                .await
            {
                Ok(map) => {
                    let mut list: Vec<DevAnnouncement> = map.into_values().collect();
                    // Ordenar por timestamp descendente (más recientes primero)
                    list.sort_by(|a, b| b.ts.cmp(&a.ts));
                    list.truncate(10); // Máximo 10 anuncios
                    list
                }
                Err(_) => vec![],
            }
        }
        Err(e) => {
            tracing::warn!("[Comunidad] No se pudieron obtener anuncios: {}", e);
            vec![]
        }
    }
}

/// Envía feedback / mensaje al desarrollador desde el nodo
pub async fn send_community_message(node_id_b58: &str, category: &str, message: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Clave única: node_id + timestamp para evitar colisiones
    let key = format!("{}-{}", &node_id_b58[..8], ts);
    let url = format!("{}/community/{}.json", FIREBASE_URL, key);

    let entry = CommunityMessage {
        node_id: node_id_b58.to_string(),
        category: category.to_string(),
        msg: message.to_string(),
        ts,
        version: BINARY_VERSION.to_string(),
    };

    match client.put(&url).json(&entry).send().await {
        Ok(r) if r.status().is_success() => {
            tracing::info!("[Comunidad] ✓ Mensaje enviado al desarrollador.");
            true
        }
        Ok(r) => {
            tracing::warn!("[Comunidad] Respuesta inesperada Firebase: {}", r.status());
            false
        }
        Err(e) => {
            tracing::warn!("[Comunidad] Error enviando mensaje: {}", e);
            false
        }
    }
}
