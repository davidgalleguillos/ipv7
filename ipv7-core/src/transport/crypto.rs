//! crypto.rs
//! Cifrado Extremo a Extremo de la Capa de Transporte de IPv7.
//! Todo flujo es ineludiblemente cifrado con XChaCha20Poly1305.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::RngCore;

pub struct SymmetricTunnel {
    pub cipher: XChaCha20Poly1305,
}

impl SymmetricTunnel {
    /// Inicializa un nuevo túnel simétrico derivado a partir de una llave secreta compartida
    /// (obtenida por intercambio X25519 en el handshake entre nodos).
    pub fn new(shared_secret: [u8; 32]) -> Self {
        let key = Key::from(shared_secret);
        SymmetricTunnel {
            cipher: XChaCha20Poly1305::new(&key),
        }
    }

    /// Cifra implacablemente los datos con XChaCha20-Poly1305.
    /// Devuelve un Nonce real de 32 bytes (estándar IPv7 v2.0) y el texto cifrado.
    pub fn encrypt_payload(
        &self,
        plain_payload: &[u8],
    ) -> Result<([u8; 32], Vec<u8>), &'static str> {
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        match self.cipher.encrypt(&nonce, plain_payload) {
            Ok(ciphertext) => {
                let mut transport_nonce = [0u8; 32];
                transport_nonce[..24].copy_from_slice(&nonce_bytes);
                Ok((transport_nonce, ciphertext))
            }
            Err(_) => Err("Fallo Crítico al Cifrar Payload IPv7"),
        }
    }

    /// Desencripta un paquete llegado desde el transporte industrial v2.0
    pub fn decrypt_payload(
        &self,
        nonce_bytes: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        // XChaCha20 usa 24 bytes del nonce de transporte de 32 bytes
        let nonce = XNonce::from_slice(&nonce_bytes[..24]);
        match self.cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err("Ataque o Corrupción Estructural en Cifrado"),
        }
    }
}
