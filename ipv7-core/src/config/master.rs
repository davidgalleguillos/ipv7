//! master.rs
//! Archivo Maestro de Optimización de IPv7
//! Contiene los límites técnicos estrictos (máximos y mínimos), umbrales matemáticos
//! y constantes globales calibradas.

// ============================================================================
// LÍMITES TÉCNICOS Y ENRUTAMIENTO
// ============================================================================

/// El puerto base estructural desde el que inicia la matriz dimensional de IPv7.
/// Elegido para estar en el rango efímero dinámico pero por debajo del límite de OS (65535).
pub const MIN_PORT_RANGE: u32 = 60553;

/// Máximo número de intentos (saltos) en la cascada de subpuertos antes 
/// de declarar un nodo host como inalcanzable.
pub const MAX_SUBPORT_ATTEMPTS: u8 = 5;

/// Tamaño de bloque UDP por defecto (en bytes) antes de fragmentar.
/// Optimizado para Ethernet estándar evitando MTU fragmentation en IPv4 subyacente.
pub const DEFAULT_PACKET_SIZE: usize = 1280;

// ============================================================================
// CONTRATOS DE TRANSMISIÓN Y VIDA ÚTIL (LIFECYCLE)
// ============================================================================

/// Tiempo de Vida (TTL) por defecto para paquetes estándar (en segundos).
pub const DEFAULT_MESSAGE_TTL: u64 = 86400; // 24 horas

// ============================================================================
// SISTEMA DE REPUTACIÓN Y GOBERNANZA
// ============================================================================

/// Porcentaje máximo de paquetes perdidos tolerado antes de penalizar reputación.
pub const MAX_TOLERATED_DROP_RATE: f32 = 0.50; // 50%

/// Reputación inicial asignada a un nodo desconocido.
pub const BASE_REPUTATION: u64 = 50;

/// Costo en puntos de reputación por enviar paquetes formados crípticamente de forma inválida (spam/ataque).
pub const PENALTY_INVALID_SIG: u64 = 10;
