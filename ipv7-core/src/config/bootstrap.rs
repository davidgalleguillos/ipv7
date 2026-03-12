//! bootstrap.rs
//! Configuracion de Nodos Bootstrap de Alta Reputacion (Fase 14).
//! 3 Capas: LAN mDNS → Firebase Rendezvous → 7 Guardian Nodes

/// URL del servidor Firebase Realtime Database (tablón de anuncios P2P)
pub const FIREBASE_URL: &str = "https://ipv7-b5466-default-rtdb.firebaseio.com";

/// Los 7 Nodos Guardianes de máxima reputación de la red IPv7.
/// Hardcodeados como fallback final si Firebase no responde.
/// Se renuevan firmados en cada versión mayor anual.
pub const GUARDIAN_NODES: &[(&str, &str)] = &[
    // (IP:Puerto, ID Base58 del nodo)
    // --- Poblados al levantar nodos permanentes ---
    // Actualmente vacíos hasta que los guardianes sean elegidos con reputación verificada.
    // Se añadirán en el release v2.0 tras el período de comunidad inicial.
];

/// Puerto UDP estándar de la red IPv7
pub const IPV7_DEFAULT_PORT: u16 = 60553;

/// Tiempo máximo de espera en discovery (ms)
pub const DISCOVERY_TIMEOUT_MS: u64 = 800;

/// Nodos Firebase se consideran "vencidos" después de este tiempo (segundos)
pub const FIREBASE_NODE_TTL_SECS: u64 = 86400; // 24 horas
