//! handshake.rs
//! Protocolo de Enlace (Handshake) IPv7 usando Diffie-Hellman en Curva Elíptica (X25519).
//! Genera secretos compartidos para el túnel simétrico XChaCha20Poly1305.

use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;

/// El contenido payload del intento de conexión inicial
#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakePayload {
    /// La llave pública efímera X25519 generada para esta sesión
    pub ephemeral_public_key: [u8; 32],
}

/// La respuesta afirmativa enviada desde el Listener hacia el Sender 
/// completando orgánicamente la derivación del secreto X25519.
#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeResponse {
    pub ephemeral_public_key: [u8; 32],
}

/// Manejador de la sesión de handshake activo.
/// Guarda el secreto efímero hasta que se completa el handshake Diffie-Hellman.
pub struct HandshakeSession {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl HandshakeSession {
    /// Inicia una nueva sesión, generando una clave pública/privada efímera (usar y tirar).
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        
        Self { secret, public_key }
    }

    /// Genera la estructura de carga útil (payload) para enviarla por un paquete IPv7.
    pub fn create_payload(&self) -> HandshakePayload {
        HandshakePayload {
            ephemeral_public_key: *self.public_key.as_bytes(),
        }
    }

    /// Completa el Diffie-Hellman. Retorna la derivación de 32 bytes que
    /// usará el SymmetricTunnel para cifrar el resto de la sesión.
    /// Consume la sesión (self) garantizando que la llave privada efímera
    /// es destruida de la memoria mediante drop y forward secrecy.
    pub fn derive_shared_secret(self, peer_public_bytes: [u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(peer_public_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_public);
        
        *shared_secret.as_bytes()
    }
}
