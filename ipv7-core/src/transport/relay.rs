//! relay.rs
//! Protocolos de enrutamiento proxy / "Escudo de Cascada" (Onion Routing)
//! Utilizado para instruir a un nodo que retransmita un paquete interno de forma segura y ofuscada.

use serde::{Deserialize, Serialize};

/// Instrucción explícita de enrutador.
/// Cuando un paquete contiene este payload, el nodo receptor no es el usuario final,
/// sino una parada intermedia (Relé) en la Darknet IPv7.
#[derive(Serialize, Deserialize, Debug)]
pub struct RelayInstruction {
    /// La Identidad Pública (X25519/ED25519) hacia donde se debe saltar ahora.
    pub target_id: [u8; 32],

    /// El paquete IPv7 original y completamente cifrado/firmado del Remitente inicial
    /// empacado como binario en bruto (Cebolla interna).
    pub nested_packet: Vec<u8>,
}
