//! packet.rs
//! Estructura del marco (Frame) de un Paquete IPv7 en Bruto.
//! El núcleo serializable que viajará inyectado a través del Túnel UDP.

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

// Estructura principal atómica que viajará comprimida por bincode sobre UDP.
// Ningún campo viaja en "texto claro" entendible para un humano/router.
#[derive(Serialize, Deserialize, Debug)]
pub struct Ipv7Packet {
    /// Versión del protocolo (v2 para protección contra Replay).
    pub version: u8,

    /// Llave pública plana del Nodo Emisor (32 bytes).
    pub source_id: [u8; 32],

    /// Llave pública plana del Nodo Destino (32 bytes).
    pub destination_id: [u8; 32],

    /// Firma matemática que garantiza la inmutabilidad y autenticidad
    /// de TODOS los campos. (64 bytes).
    pub signature: Vec<u8>,

    /// Metadatos (LifeCycle/TTL).
    pub ttl: u64,

    /// Marca de tiempo para evitar Replay (Unix Secs).
    pub timestamp: u64,

    /// Número de secuencia incremental por flujo.
    pub sequence_number: u64,

    /// Sal criptográfica (Nonce) real (32 bytes).
    pub nonce: [u8; 32],

    /// El payload cifrado con XChaCha20Poly1305.
    pub encrypted_payload: Vec<u8>,
}

impl Ipv7Packet {
    /// Empaqueta la estructura base a bytes crudos (Serialización nivel C en nanosegundos).
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Toma los bytes recibidos de la placa de red y los levanta como Paquete estructural.
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    /// Obtiene los bytes que deben ser firmados/verificados.
    pub fn get_signing_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&self.version.to_le_bytes());
        message.extend_from_slice(&self.source_id);
        message.extend_from_slice(&self.destination_id);
        message.extend_from_slice(&self.ttl.to_le_bytes());
        message.extend_from_slice(&self.timestamp.to_le_bytes());
        message.extend_from_slice(&self.sequence_number.to_le_bytes());
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&self.encrypted_payload);
        message
    }

    /// Autenticar Matemáticamente el Origen.
    /// Valida que la firma corresponde realmente al `source_id` usando la librería ed25519.
    pub fn verify_origin_signature(&self) -> bool {
        use ed25519_dalek::{Verifier, VerifyingKey};

        let Ok(signer_pub_pub) = VerifyingKey::from_bytes(&self.source_id) else {
            return false;
        };
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);

        // FIRMA INDUSTRIAL v2.0: Incluye todos los metadatos para evitar manipulación.
        let message_to_verify = self.get_signing_message();

        signer_pub_pub
            .verify(&message_to_verify, &signature)
            .is_ok()
    }
}
