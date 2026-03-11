//! crypto.rs
//! Cifrado Extremo a Extremo de la Capa de Transporte de IPv7.
//! Todo flujo es ineludiblemente cifrado con XChaCha20Poly1305.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce, Key
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

    /// Cifra implacablemente los datos hacia la infraestructura superpuesta.
    /// Devuelve un Nonce aleatorio y el texto cifrado, o Error.
    pub fn encrypt_payload(&self, plain_payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        match self.cipher.encrypt(&nonce, plain_payload) {
            Ok(ciphertext) => Ok((nonce_bytes.to_vec(), ciphertext)),
            Err(_) => Err("Fallo Crítico al Cifrar Payload IPv7"),
        }
    }

    /// Desencripta un paquete llegado en bruto desde las profundidades del UDP
    pub fn decrypt_payload(&self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if nonce_bytes.len() != 24 {
            return Err("Longitud de Nonce Inválida");
        }
        let nonce = XNonce::from_slice(nonce_bytes);
        match self.cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err("Ataque o Corrupción Estructural en Cifrado"),
        }
    }
}
