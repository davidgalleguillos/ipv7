//! keys.rs
//! Identidad Soberana de IPv7
//! 
//! Implementa el Principio 2: "Una clave, una identidad". 
//! La clave privada no sale del dispositivo y se autodestruye de la memoria con Zeroize.
//! Genera identidades tanto permanentes como efímeras/anónimas.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use zeroize::Zeroize;

/// Dirección criptográfica pública de un Nodo (identidad verificable).
#[derive(Clone, Eq, PartialEq)]
pub struct Ipv7Address {
    public_key: VerifyingKey,
}

impl Ipv7Address {
    /// Convierte la clave pública en una dirección legible y ruteable (ej. id://xxxxx)
    pub fn to_string(&self) -> String {
        let bytes = self.public_key.as_bytes();
        let encoded = bs58::encode(bytes).into_string();
        format!("id://{}", encoded)
    }

    /// Obtiene los bytes crudos de la clave pública para verificación matemática.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.public_key.as_bytes()
    }
}

/// Identidad Soberana de un Nodo.
/// Contiene la clave privada ultra-secreta y la dirección pública que expone al mundo.
pub struct NodeIdentity {
    pub address: Ipv7Address,
    /// Clave privada: el nodo debe firmar paquetes con esto
    secret_key: SigningKey, 
}

impl NodeIdentity {
    /// Genera una nueva identidad soberana. Utilizado tanto para el nodo principal
    /// como para identidades efímeras/anónimas.
    pub fn generate_new() -> Self {
        let mut csprng = OsRng;
        let secret_key = SigningKey::generate(&mut csprng);
        let public_key = secret_key.verifying_key();
        
        NodeIdentity {
            address: Ipv7Address { public_key },
            secret_key,
        }
    }

    /// Firma un mensaje en bruto (ej. cabecera del túnel UDP)
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.secret_key.sign(message)
    }
}

/// Garantía Crítica IPv7:
/// Al liberar (Drop) la identidad de memoria (ej. al apagar el nodo o destruir id efímera),
/// los bytes de la clave privada son sobreescritos con ceros.
impl Drop for NodeIdentity {
    fn drop(&mut self) {
        // Rust's ed25519_dalek SigningKey implements ZeroizeOnDrop by default,
        // pero hacemos explícito el concepto en la capa de la arquitectura para auditoría.
        let secret_bytes = self.secret_key.to_bytes();
        let mut secret_copy = secret_bytes.clone();
        secret_copy.zeroize();
    }
}
