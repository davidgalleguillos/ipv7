🔬 EVALUACIÓN TÉCNICA EXHAUSTIVA DE IPv7 v1.3.0
Resumen Ejecutivo
IPv7 es un protocolo P2P revolucionario en Rust que implementa identidad soberana con ED25519, cifrado X25519+ChaCha20, y enrutamiento Onion. Sin embargo, la versión actual contiene vulnerabilidades críticas de seguridad, ineficiencias arquitectónicas drásticas, y limitaciones severas de escalabilidad que impedirían soportar millones de nodos concurrentes. A continuación, un análisis granular en cuatro ejes.

1️⃣ SEGURIDAD DE IDENTIDADES ED25519 Y FIRMAS DE PAQUETES
✅ Aspectos Positivos
Rust
// ✓ Generación criptográficamente segura (OsRng)
pub fn generate_new() -> Self {
    let mut csprng = OsRng;
    let secret_key = SigningKey::generate(&mut csprng);
    let public_key = secret_key.verifying_key();
    NodeIdentity { address: Ipv7Address { public_key }, secret_key }
}

// ✓ Destrucción segura de memoria (Zeroize)
impl Drop for NodeIdentity {
    fn drop(&mut self) {
        let secret_bytes = self.secret_key.to_bytes();
        let mut secret_copy = secret_bytes;
        secret_copy.zeroize();  // Sobrescribe bytes de clave privada
    }
}

// ✓ Codificación Base58 para direcciones legibles
write!(f, "id://{}", bs58::encode(bytes).into_string())
⚠️ VULNERABILIDADES CRÍTICAS IDENTIFICADAS
1.1 - Replay Attack en Firma de Paquetes 🔴 CRÍTICO
Rust
// VULNERABLE: El message_to_verify NO incluye un nonce o secuencia
pub fn verify_origin_signature(&self) -> bool {
    let mut message_to_verify = Vec::new();
    message_to_verify.extend_from_slice(&self.source_id);
    message_to_verify.extend_from_slice(&self.destination_id);
    message_to_verify.extend_from_slice(&self.ttl.to_le_bytes());
    // ❌ NO HAY: timestamp, sequence_number, o nonce en la firma
    message_to_verify.extend_from_slice(&self.encrypted_payload);
    
    signer_pub_pub.verify(&message_to_verify, &signature).is_ok()
}
Ataque de Replay:

Un atacante captura un paquete IPv7 válido (P1 → P2) con contenido X
Retransmite el mismo paquete múltiples veces
Todas las validaciones pasarán porque la firma es idéntica
Impacto: DoS masivo, duplicación de mensajes, corrupción de estado
Remedio Inmediato:

Rust
#[derive(Serialize, Deserialize)]
pub struct Ipv7PacketWithNonce {
    pub source_id: [u8; 32],
    pub destination_id: [u8; 32],
    pub ttl: u64,
    pub nonce: [u8; 32],          // ← NUEVO: Random nonce por paquete
    pub timestamp: u64,            // ← NUEVO: Previene old replay
    pub sequence_number: u64,      // ← NUEVO: Per-peer sequence tracking
    pub encrypted_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

// Estructura para rastrear secuencias por peer
struct ReplayProtection {
    peer_last_sequence: Arc<RwLock<HashMap<[u8; 32], u64>>>,
    peer_nonce_cache: Arc<RwLock<HashMap<[u8; 32], HashSet<[u8; 32]>>>>,
}

impl ReplayProtection {
    pub async fn verify_fresh(&self, peer_id: &[u8; 32], nonce: &[u8; 32], seq: u64) -> bool {
        let mut seqs = self.peer_last_sequence.write().await;
        let mut nonces = self.peer_nonce_cache.write().await;
        
        // Verificar que el nonce nunca fue visto antes
        if let Some(seen_nonces) = nonces.get_mut(peer_id) {
            if seen_nonces.contains(nonce) {
                return false;  // Replay detectado
            }
            seen_nonces.insert(*nonce);
        } else {
            let mut new_set = HashSet::new();
            new_set.insert(*nonce);
            nonces.insert(*peer_id, new_set);
        }
        
        // Verificar secuencia monotónica (permite saltos, no retrocesos)
        let last_seq = seqs.get(peer_id).copied().unwrap_or(0);
        if seq <= last_seq {
            return false;
        }
        seqs.insert(*peer_id, seq);
        true
    }
}
1.2 - Falta de Tiempo Sincronizado en Firma 🔴 CRÍTICO
Rust
// El timestamp no es parte de la firma verificada
// Un atacante puede enviar paquetes "antiguos" indefinidamente
pub fn verify_origin_signature(&self) -> bool {
    // ... sin validar age(timestamp)
}
Remedio:

Rust
pub fn verify_origin_signature_with_ttl(&self, max_age_secs: u64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Validar que el paquete no sea más antiguo que max_age_secs
    if current_time.saturating_sub(self.timestamp) > max_age_secs {
        return false;  // Paquete demasiado viejo
    }
    
    // ... verificar firma ...
}
1.3 - Ninguna Verificación de Formato de Clave Pública 🔴 CRÍTICO
Rust
pub fn verify_origin_signature(&self) -> bool {
    // ❌ PELIGRO: Ed25519 tiene puntos de orden pequeño
    // Una clave pública mal formada puede ser construida por atacante
    let Ok(signer_pub_pub) = VerifyingKey::from_bytes(&self.source_id) else {
        return false;
    };
    // Si entra aquí, asume que la clave es válida sin verificaciones adicionales
}
Ataque de Punto Pequeño-Orden:

Ed25519 tiene 8 puntos de orden pequeño
Atacante construye clave pública en subgrupo pequeño
Puede falsificar firmas usando relaciones matemáticas
Remedio:

Rust
pub fn verify_key_format(pubkey: &VerifyingKey) -> bool {
    // Ed25519-dalek ya resiste esto internamente con verificación de cofactor
    // PERO debemos validar explícitamente
    
    // 1. Verificar que la clave no es punto neutro
    let bytes = pubkey.as_bytes();
    if bytes == &[0u8; 32] || bytes == &[1u8; 32] {
        return false;
    }
    
    // 2. Verificar estructura de bits (Ed25519 específico)
    let last_byte = bytes[31];
    if last_byte & 0xF0 != 0 {  // Bits superiores deben ser 0
        return false;
    }
    
    true
}
1.4 - Falta de Firma del Nonce en Payload 🟠 ALTO
Rust
pub struct Ipv7Packet {
    pub nonce: Vec<u8>,              // ← Viaja sin protección
    pub encrypted_payload: Vec<u8>,  // ← Cifrado pero nonce NO firmado
}
Un atacante puede interceptar paquete, modificar nonce, y aunque el payload permanezca cifrado, la estructura es inconsistente.

Remedio:

Rust
pub struct Ipv7PacketSecure {
    pub version: u8,
    pub source_id: [u8; 32],
    pub destination_id: [u8; 32],
    pub ttl: u64,
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub sequence_number: u64,
    pub encrypted_payload: Vec<u8>,
    pub signature: Vec<u8>,  // Cubre TODOS los campos anteriores
}

// Firma debe incluir:
let mut sig_msg = Vec::new();
sig_msg.extend_from_slice(&packet.version.to_le_bytes());
sig_msg.extend_from_slice(&packet.source_id);
sig_msg.extend_from_slice(&packet.destination_id);
sig_msg.extend_from_slice(&packet.ttl.to_le_bytes());
sig_msg.extend_from_slice(&packet.nonce);           // ← Ahora firmado
sig_msg.extend_from_slice(&packet.timestamp.to_le_bytes());  // ← Ahora firmado
sig_msg.extend_from_slice(&packet.sequence_number.to_le_bytes());  // ← Ahora firmado
sig_msg.extend_from_slice(&packet.encrypted_payload);
// packet.signature = my_node.sign(&sig_msg).to_bytes().to_vec();
1.5 - Ausencia de Forward Secrecy en Handshake 🟠 ALTO
Rust
pub struct HandshakeSession {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl HandshakeSession {
    pub fn derive_shared_secret(self, peer_public_bytes: [u8; 32]) -> [u8; 32] {
        let peer_public = PublicKey::from(peer_public_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_public);
        *shared_secret.as_bytes()  // ← Se reutiliza por TODA la sesión
    }
}
Problema: El mismo shared_secret se usa para todos los paquetes de la sesión. Si se compromete, todos los paquetes pasados y futuros se descifran.

Remedio - KDF con Derivación por Paquete:

Rust
use hkdf::Hkdf;
use sha2::Sha256;

pub struct SessionCipher {
    master_secret: [u8; 32],
    packet_counter: Arc<AtomicU64>,  // Incremental per packet
}

impl SessionCipher {
    pub fn derive_packet_key(&self, packet_num: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.master_secret);
        
        let mut packet_context = Vec::new();
        packet_context.extend_from_slice(b"IPv7_PACKET_KEY");
        packet_context.extend_from_slice(&packet_num.to_le_bytes());
        
        let mut output = [0u8; 32];
        hk.expand(&packet_context, &mut output)
            .expect("32 bytes is valid length");
        output
    }
    
    pub async fn encrypt_payload_with_forward_secrecy(
        &self,
        plain_payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let packet_num = self.packet_counter.fetch_add(1, Ordering::SeqCst);
        let packet_key = self.derive_packet_key(packet_num);
        
        // Usar packet_key en lugar de shared_secret directamente
        let cipher = XChaCha20Poly1305::new(&Key::from(packet_key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        
        match cipher.encrypt(&nonce, plain_payload) {
            Ok(ciphertext) => Ok((nonce_bytes.to_vec(), ciphertext)),
            Err(_) => Err("Encryption failed"),
        }
    }
}
2️⃣ EFICIENCIA DE CASCADA UDP Y HANDSHAKE X25519
✅ Aspectos Positivos
✓ Tokio async/await elimina bloqueos de I/O
✓ Bincode serialización ultra-rápida (~10-100 ns por paquete)
✓ Ed25519-dalek + X25519-dalek son librerías optimizadas
✓ ChaCha20Poly1305 sin uso de AES-NI, multiplataforma rápido
⚠️ INEFICIENCIAS CRÍTICAS
2.1 - Creación de Socket UDP por Cascada 🔴 CRÍTICO
Rust
impl OverlayRelay {
    pub async fn start_listener(listen_ip: &str) -> std::io::Result<Self> {
        let mut attempt = 0;
        let mut current_port = MIN_PORT_RANGE;

        loop {
            let bind_addr = format!("{}:{}", listen_ip, current_port);

            match UdpSocket::bind(&bind_addr).await {  // ← Crea socket NUEVO por cada intento
                Ok(sock) => {
                    return Ok(OverlayRelay {
                        socket: Arc::new(sock),
                        bound_port: current_port,
                    });
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_SUBPORT_ATTEMPTS {
                        return Err(e);
                    }
                    current_port += 1;  // ← Secuencial, no pseudoaleatorio
                }
            }
        }
    }
}
Problemas:

Intentos secuenciales lentos: Si puerto 65553 está ocupado, intenta 65554, 65555... en bucle síncrono (aunque espera I/O)
No reutiliza puertos: Cada nodo abre UN SOCKET. En millones de nodos, SO exhausto
Rendimiento O(n): Peor caso 1000 intentos × ~1ms c/u = ~1s por nodo
2.2 - Handshake X25519 Síncrono (Bloquea por 3 segundos) 🔴 CRÍTICO
Rust
let auth_secret = if let Ok(Ok((amt, _))) = tokio::time::timeout(
    std::time::Duration::from_secs(3),  // ← 3 SEGUNDOS HARDCODEADO
    net_relay.socket.recv_from(&mut buf),
)
.await {
    // ... procesar respuesta
} else {
    tracing::error!("[X] Timeout extenuado.");
    return Ok(());
};
Impacto en Millones de Nodos:

1M nodos × 3s timeout = 3,000,000 segundos = 833 horas de latencia acumulada
Incluso si se hacen handshakes en paralelo, timeout es por conexión
Remedio - Adaptive Timeout:

Rust
pub struct AdaptiveHandshakeConfig {
    base_timeout_ms: u64,
    max_timeout_ms: u64,
    rtt_estimator: Arc<RwLock<HashMap<[u8; 32], u64>>>,  // latencia por peer
}

impl AdaptiveHandshakeConfig {
    pub async fn get_timeout_for_peer(&self, peer_id: &[u8; 32]) -> Duration {
        let estimator = self.rtt_estimator.read().await;
        let estimated_rtt = estimator.get(peer_id).copied().unwrap_or(50);  // 50ms default
        
        // Timeout = 3 × RTT (espacio para retransmisiones)
        let timeout_ms = (estimated_rtt * 3).clamp(self.base_timeout_ms, self.max_timeout_ms);
        Duration::from_millis(timeout_ms)
    }
    
    pub async fn record_rtt(&self, peer_id: [u8; 32], rtt_ms: u64) {
        let mut estimator = self.rtt_estimator.write().await;
        // Suavizar con promedio móvil exponencial (EWMA)
        let existing = estimator.get(&peer_id).copied().unwrap_or(50);
        let alpha = 0.2;  // Peso del nuevo valor
        let new_rtt = (alpha * rtt_ms as f32 + (1.0 - alpha) * existing as f32) as u64;
        estimator.insert(peer_id, new_rtt);
    }
}
2.3 - Serialización Sin Compresión de Payload 🟠 ALTO
Rust
pub struct Ipv7Packet {
    pub signature: Vec<u8>,            // 64 bytes + overhead
    pub nonce: Vec<u8>,                // 24 bytes + overhead  
    pub encrypted_payload: Vec<u8>,    // Variable + overhead
}
Cada Vec<u8> en bincode añade 4 bytes de length prefix. Con millones de paquetes/seg:

4 bytes × 1M paquetes/seg = 4MB/s overhead innecesario
Remedio - Fixed-Size Arrays:

Rust
#[derive(Serialize, Deserialize)]
pub struct Ipv7PacketOptimized {
    pub version: u8,
    pub source_id: [u8; 32],
    pub destination_id: [u8; 32],
    pub ttl: u64,
    pub timestamp: u64,
    pub sequence_number: u64,
    pub nonce: [u8; 24],              // ← Fixed array (sin length prefix)
    pub signature: [u8; 64],           // ← Fixed array
    pub encrypted_payload: [u8; 1280], // ← Fixed size (o varint para tamaño variable)
    pub payload_len: u16,              // ← Bytes reales usados en payload
}

// Total overhead: 32 + 32 + 32 + 8 + 8 + 8 + 24 + 64 + 2 = 210 bytes fijos
// vs actual IPv7Packet que puede ser >300 bytes con vecs
2.4 - Verificación de Firma ANTES de Desencriptar 🟠 ALTO
Rust
if packet.verify_origin_signature() {  // ← Ed25519 verify = ~300-500 microsegundos
    // AHORA procesamos payload
    if let Ok(dht_msg) = bincode::deserialize::<DhtPayload>(&packet.encrypted_payload) {
        // ...
    }
}
Problema: Verificar firma de payload cifrado es defensible (no reveals datos), pero ineficiente en escala. Si 1M paquetes/seg llegan y 99% son basura, gastas 1M × 300µs = 300 segundos = 5 minutos solo verificando firmas.

Remedio - Rate Limiting Inteligente:

Rust
pub struct PacketFilter {
    peer_packet_counts: Arc<RwLock<HashMap<[u8; 32], (u64, Instant)>>>,  // (count, window_start)
    max_packets_per_second: u64,
}

impl PacketFilter {
    pub async fn check_rate_limit(&self, source_id: &[u8; 32]) -> bool {
        let mut counts = self.peer_packet_counts.write().await;
        let now = Instant::now();
        
        let (count, window_start) = counts.get(source_id).copied().unwrap_or((0, now));
        
        if now.duration_since(window_start).as_secs() > 1 {
            // Nueva ventana de 1 segundo
            counts.insert(*source_id, (1, now));
            return true;  // Permitir
        }
        
        if count >= self.max_packets_per_second {
            return false;  // Rate limit exceeded
        }
        
        counts.insert(*source_id, (count + 1, window_start));
        true
    }
}

// En main loop:
if !packet_filter.check_rate_limit(&packet.source_id).await {
    tracing::warn!("[Rate Limit] Dropping packet from {:?}", packet.source_id);
    continue;  // Drop antes de verificar firma costosa
}

if packet.verify_origin_signature() {
    // ... continuar ...
}
3️⃣ ESCALABILIDAD DE DHT: HashMap vs K-Buckets
❌ ANÁLISIS CRÍTICO DE ARQUITECTURA ACTUAL
Rust
#[derive(Clone)]
pub struct DhtRegistry {
    pub local_id: [u8; 32],
    /// K-Buckets simplificados: Mapeo de Identidad a Endpoint validado
    pub nodes: Arc<RwLock<HashMap<[u8; 32], String>>>,
}
LO QUE EL CÓDIGO DICE: "K-Buckets simplificados"
LO QUE EL CÓDIGO HACE: Almacena TODOS los nodos en UN HASHMAP PLANO

🔴 PROBLEMAS FUNDAMENTALES
3.1 - O(n) Memory para Millones de Nodos
Code
Escenario: 10 millones de nodos en red IPv7

HashMap<[u8; 32], String>
├─ Key (32 bytes): [u8; 32]
├─ Value (String "192.168.1.1:60553"):
│  ├─ ptr (8 bytes)
│  ├─ len (8 bytes)
│  ├─ capacity (8 bytes)
│  └─ data (~20 bytes promedio para IP:puerto)
├─ HashMap overhead: ~56 bytes por entrada

Total por nodo: 32 + 44 + 56 = ~132 bytes mínimo

10M nodos × 132 bytes = 1.32 GB en UN NODO

Peor caso (nodo "central"): 10M × 132 = 1.32 GB + overhead de HashMap
En Kademlia tradicional (k=20 buckets × 20 peers):

Code
20 buckets × 20 peers × 132 bytes = ~52 KB por nodo
Diferencia: 1.32 GB vs 52 KB = 25,000× PEOR

3.2 - Lookup O(1) pero Mantenimiento O(n) 🔴
Rust
pub async fn register_node(&self, pubkey: [u8; 32], physical_address: String) {
    let mut table = self.nodes.write().await;
    table.insert(pubkey, physical_address);  // ← O(1) insert
    // ❌ Pero NO HAY: evicción, expiración, bucketing por XOR
}

pub async fn get_closest_peers(&self, _target: &[u8; 32]) -> Vec<([u8; 32], String)> {
    let table = self.nodes.read().await;
    table
        .iter()
        .map(|(id, addr)| (*id, addr.clone()))  // ← O(n) SCAN COMPLETO
        .take(10)
        .collect()
}
Problema:

get_closest_peers() escanea TODOS los nodos para encontrar los 10 más cercanos por XOR
En 10M nodos: 10M × ~500ns (comparación XOR) = 5 segundos por lookup
Peor caso en Kademlia: 20 buckets × 20 peers × 500ns = 200 microsegundos
Diferencia: 5 seg vs 200 µs = 25,000× PEOR
3.3 - Sin Gestión de Ciclo de Vida de Pares 🔴
Rust
pub async fn register_node(&self, pubkey: [u8; 32], physical_address: String) {
    let mut table = self.nodes.write().await;
    table.insert(pubkey, physical_address);
    // ✗ Sin TTL
    // ✗ Sin heartbeat
    // ✗ Sin detección de nodos muertos
    // ✗ Sin evicción cuando tabla llena
}
Impacto:

Con 1M nodos online/offline, tabla crece indefinidamente
Nodos apagados permanecen hasta reboot
Memoria se agota exponencialmente
✅ IMPLEMENTACIÓN CORRECTA: K-Buckets Kademlia Real
Rust
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const K_BUCKET_SIZE: usize = 20;
const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);  // 1 hora
const NODE_TTL: Duration = Duration::from_secs(86400);  // 24 horas sin PING

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: [u8; 32],
    pub address: SocketAddr,
    pub last_seen: Instant,
    pub failed_pings: u32,
    pub reputation: u64,
}

#[derive(Clone)]
pub struct KademliaRegistry {
    pub local_id: [u8; 32],
    /// Buckets organizados por distancia XOR (160 posibles, pero solo 256 bits = 256 buckets máx)
    buckets: Arc<RwLock<BTreeMap<usize, VecDeque<PeerInfo>>>>,
    
    /// Cache de pares rechazados recientemente (anti-sybil)
    blocked_peers: Arc<RwLock<HashMap<[u8; 32], Instant>>>,
    
    /// Estadísticas globales
    stats: Arc<RwLock<RegistryStats>>,
}

#[derive(Clone, Debug, Default)]
pub struct RegistryStats {
    pub total_peers: usize,
    pub total_lookups: u64,
    pub failed_lookups: u64,
    pub avg_lookup_time_us: u64,
}

impl KademliaRegistry {
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            local_id,
            buckets: Arc::new(RwLock::new(BTreeMap::new())),
            blocked_peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RegistryStats::default())),
        }
    }

    /// Calcula el índice del bucket según distancia XOR
    /// Usa posición del bit más significativo diferente
    fn get_bucket_index(a: &[u8; 32], b: &[u8; 32]) -> usize {
        for i in 0..32 {
            if a[i] != b[i] {
                // Encontrar primer bit diferente en byte i
                let xor_byte = a[i] ^ b[i];
                let highest_bit = 7 - xor_byte.leading_zeros() as usize;
                return i * 8 + highest_bit;
            }
        }
        0  // IDs son idénticos (imposible, pero fallback)
    }

    /// Registra un nuevo peer o actualiza existente
    pub async fn register_peer(&self, peer_info: PeerInfo) -> Result<(), String> {
        // Validar que no sea blacklisted
        let blocked = self.blocked_peers.read().await;
        if blocked.contains_key(&peer_info.id) {
            if let Some(blocked_until) = blocked.get(&peer_info.id) {
                if Instant::now() < *blocked_until {
                    return Err("Peer es blacklisted".to_string());
                }
            }
        }
        drop(blocked);

        let bucket_index = Self::get_bucket_index(&self.local_id, &peer_info.id);
        let mut buckets = self.buckets.write().await;

        let bucket = buckets.entry(bucket_index).or_insert_with(VecDeque::new);

        // Buscar si peer ya existe
        if let Some(pos) = bucket.iter().position(|p| p.id == peer_info.id) {
            // Mover a final (least recently seen primero, más recientemente al final)
            bucket.remove(pos);
            bucket.push_back(peer_info);
            return Ok(());
        }

        // Nuevo peer
        if bucket.len() < K_BUCKET_SIZE {
            bucket.push_back(peer_info);
            let mut stats = self.stats.write().await;
            stats.total_peers += 1;
            return Ok(());
        }

        // Bucket lleno: probar PING el nodo menos recientemente visto
        let lru_peer = bucket.front().cloned().expect("bucket not empty");
        
        // En producción, aquí disparamos un PING RPC asincrónico
        // y esperamos respuesta. Si falla, evictamos el LRU.
        // Por ahora, lo evictamos directamente:
        
        bucket.pop_front();
        bucket.push_back(peer_info);
        
        Ok(())
    }

    /// Busca los K peers más cercanos a un target
    /// Complejidad: O(K * log(256)) = O(20 * 8) = O(160) >> O(n)
    pub async fn find_closest_peers(&self, target_id: &[u8; 32], k: usize) -> Vec<PeerInfo> {
        let bucket_index = Self::get_bucket_index(&self.local_id, target_id);
        let buckets = self.buckets.read().await;

        let mut result = Vec::with_capacity(k);

        // Buscar en bucket del target y buckets adyacentes
        let search_range = 3;  // Búsqueda en ±3 buckets
        let start = bucket_index.saturating_sub(search_range);
        let end = (bucket_index + search_range + 1).min(256);

        for i in start..end {
            if let Some(bucket) = buckets.get(&i) {
                for peer in bucket.iter() {
                    if peer.failed_pings < 3 {  // Ignorar nodos que fallan
                        result.push(peer.clone());
                        if result.len() >= k {
                            return result;
                        }
                    }
                }
            }
        }

        result
    }

    /// Marca un peer como muerto (PING fallido)
    pub async fn mark_peer_dead(&self, peer_id: &[u8; 32]) {
        let bucket_index = Self::get_bucket_index(&self.local_id, peer_id);
        let mut buckets = self.buckets.write().await;

        if let Some(bucket) = buckets.get_mut(&bucket_index) {
            if let Some(peer) = bucket.iter_mut().find(|p| p.id == *peer_id) {
                peer.failed_pings += 1;
                if peer.failed_pings >= 3 {
                    bucket.retain(|p| p.id != *peer_id);
                    
                    let mut stats = self.stats.write().await;
                    stats.total_peers = stats.total_peers.saturating_sub(1);
                }
            }
        }
    }

    /// Limpieza periódica de peers expirados (ejecutar cada 1 hora)
    pub async fn cleanup_expired_peers(&self) {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        let mut removed_count = 0;
        for bucket in buckets.values_mut() {
            bucket.retain(|peer| {
                let is_expired = now.duration_since(peer.last_seen) > NODE_TTL;
                if is_expired {
                    removed_count += 1;
                }
                !is_expired
            });
        }

        let mut stats = self.stats.write().await;
        stats.total_peers = stats.total_peers.saturating_sub(removed_count);
    }

    /// Estadísticas de la tabla
    pub async fn get_stats(&self) -> RegistryStats {
        self.stats.read().await.clone()
    }

    pub async fn get_peer_count(&self) -> usize {
        let stats = self.stats.read().await;
        stats.total_peers
    }
}

// Tarea periódica de limpieza (en main.rs)
tokio::spawn(async {
    let dht_cleanup = dht.clone();
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        dht_cleanup.cleanup_expired_peers().await;
    }
});
📊 COMPARATIVA: HashMap Plano vs K-Buckets
Métrica	HashMap Plano	K-Buckets Kademlia
Memory (10M nodos)	1.32 GB	~52 MB (20 buckets × 20 × 132 bytes)
Lookup latencia	5 segundos (O(n))	200 microsegundos (O(1))
Insert latencia	100 nanosegundos	500 nanosegundos
Evicción antigua	Nunca	Automática (TTL)
Escalabilidad a 1M nodos	❌ Impracticable	✅ Excelente
Detección de muertos	Nunca	PING periódico
Anti-Sybil	None	Reputation + bucketing
4️⃣ RECOMENDACIONES DE CÓDIGO PARA SOPORTAR MILLONES DE NODOS
📋 Roadmap de Implementación Prioritizado
FASE 1: URGENTE (1-2 semanas)
1.1 - Replayprueba Firmas
Rust
// En src/transport/packet.rs

#[derive(Serialize, Deserialize, Debug)]
pub struct Ipv7PacketSecureV2 {
    pub version: u8,
    pub source_id: [u8; 32],
    pub destination_id: [u8; 32],
    pub ttl: u64,
    pub timestamp: u64,
    pub sequence_number: u64,
    pub nonce: [u8; 32],
    pub encrypted_payload: Vec<u8>,
    pub signature: [u8; 64],  // Firma cubre TODOS los campos
}

impl Ipv7PacketSecureV2 {
    pub fn verify_with_replay_protection(
        &self,
        replay_filter: &ReplayProtection,
    ) -> Result<(), String> {
        // 1. Verificar timestamp (no más de 30 segundos)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now.saturating_sub(self.timestamp) > 30 {
            return Err("Packet timestamp too old".to_string());
        }

        // 2. Verificar nonce nunca visto antes (bloquea replays)
        if !replay_filter.check_nonce(&self.source_id, &self.nonce) {
            return Err("Nonce replay detected".to_string());
        }

        // 3. Verificar secuencia monotónica por peer
        if !replay_filter.check_sequence(&self.source_id, self.sequence_number) {
            return Err("Sequence number rollback detected".to_string());
        }

        // 4. Verificar firma sobre TODOS los campos
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};
        
        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.source_id) else {
            return Err("Invalid source public key".to_string());
        };

        let mut message = Vec::new();
        message.extend_from_slice(&self.version.to_le_bytes());
        message.extend_from_slice(&self.source_id);
        message.extend_from_slice(&self.destination_id);
        message.extend_from_slice(&self.ttl.to_le_bytes());
        message.extend_from_slice(&self.timestamp.to_le_bytes());
        message.extend_from_slice(&self.sequence_number.to_le_bytes());
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&self.encrypted_payload);

        let sig = Signature::from_bytes(&self.signature);
        verifying_key.verify(&message, &sig)
            .map_err(|_| "Signature verification failed".to_string())?;

        Ok(())
    }
}
1.2 - Estructura de Replay Protection
Rust
// En src/identity/replay.rs (nuevo archivo)

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Instant, Duration};

pub struct ReplayProtection {
    /// Último nonce visto por peer (para deteccióne inmediata de replays)
    peer_nonce_cache: Arc<RwLock<HashMap<[u8; 32], HashSet<[u8; 32]>>>>,
    
    /// Últimas secuencias registradas por peer
    peer_sequence_tracker: Arc<RwLock<HashMap<[u8; 32], u64>>>,
    
    /// Timestamps muy viejos se auto-expiran (no guardarlos forever)
    cache_expiration: Duration,
}

impl ReplayProtection {
    pub fn new(cache_ttl_secs: u64) -> Self {
        Self {
            peer_nonce_cache: Arc::new(RwLock::new(HashMap::new())),
            peer_sequence_tracker: Arc::new(RwLock::new(HashMap::new())),
            cache_expiration: Duration::from_secs(cache_ttl_secs),
        }
    }

    pub async fn check_nonce(&self, peer_id: &[u8; 32], nonce: &[u8; 32]) -> bool {
        let mut cache = self.peer_nonce_cache.write().await;
        
        let peer_nonces = cache.entry(*peer_id).or_insert_with(HashSet::new);
        
        if peer_nonces.contains(nonce) {
            return false;  // Replay: nonce ya visto
        }
        
        peer_nonces.insert(*nonce);
        
        // Limitar tamaño del cache (máximo 10K nonces por peer)
        if peer_nonces.len() > 10_000 {
            peer_nonces.clear();
        }
        
        true
    }

    pub async fn check_sequence(&self, peer_id: &[u8; 32], seq_num: u64) -> bool {
        let mut tracker = self.peer_sequence_tracker.write().await;
        
        let last_seq = tracker.get(peer_id).copied().unwrap_or(0);
        
        if seq_num <= last_seq {
            return false;  // Sequence rollback or replay
        }
        
        tracker.insert(*peer_id, seq_num);
        true
    }
}
1.3 - Forward Secrecy en Sesiones
Rust
// Modificar src/transport/session.rs

use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct SessionManagerWithForwardSecrecy {
    /// Master secret por peer (derivado en handshake)
    master_secrets: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    
    /// Contadores de paquete por peer para derivación incremental
    packet_counters: Arc<RwLock<HashMap<[u8; 32], u64>>>,
}

impl SessionManagerWithForwardSecrecy {
    pub fn new() -> Self {
        Self {
            master_secrets: Arc::new(RwLock::new(HashMap::new())),
            packet_counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_secret(&self, peer_id: [u8; 32], master_secret: [u8; 32]) {
        let mut secrets = self.master_secrets.write().await;
        secrets.insert(peer_id, master_secret);
        
        let mut counters = self.packet_counters.write().await;
        counters.insert(peer_id, 0);
    }

    pub async fn derive_packet_key(&self, peer_id: &[u8; 32]) -> Result<([u8; 32], u64), String> {
        let secrets = self.master_secrets.read().await;
        let master_secret = secrets
            .get(peer_id)
            .copied()
            .ok_or_else(|| "No session with peer".to_string())?;
        drop(secrets);

        let mut counters = self.packet_counters.write().await;
        let packet_num = counters
            .entry(*peer_id)
            .and_modify(|c| *c += 1)
            .or_insert(0);
        let current_num = *packet_num;

        drop(counters);

        // Derivar clave única por paquete
        let hk = Hkdf::<Sha256>::new(None, &master_secret);
        let mut info = Vec::new();
        info.extend_from_slice(b"IPv7_PACKET_KEY");
        info.extend_from_slice(&current_num.to_le_bytes());

        let mut key = [0u8; 32];
        hk.expand(&info, &mut key)
            .map_err(|_| "HKDF expansion failed".to_string())?;

        Ok((key, current_num))
    }
}
FASE 2: CRÍTICA (2-4 semanas)
2.1 - Reemplazar HashMap con K-Buckets (código completo arriba)
Rust
// En Cargo.toml
[dependencies]
# ... existing ...
lru = "0.12"  # Para LRU cache en buckets
kademlia = "0.1"  # O implementar custom como arriba
2.2 - Packet Rate Limiting Granular
Rust
// En src/transport/rate_limiter.rs (nuevo)

use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Instant;

#[derive(Clone)]
pub struct RateLimiter {
    /// Per-IP rate limits
    ip_buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    
    /// Per-peer (by pubkey) rate limits
    peer_buckets: Arc<RwLock<HashMap<[u8; 32], TokenBucket>>>,
    
    /// Global rate limit
    global_bucket: Arc<RwLock<TokenBucket>>,
}

#[derive(Clone, Copy)]
pub struct TokenBucket {
    tokens: f32,
    last_refill: Instant,
    capacity: f32,
    refill_rate: f32,  // tokens per second
}

impl TokenBucket {
    pub fn new(capacity: f32, refill_rate: f32) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    pub fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f32();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    pub fn try_consume(&mut self, cost: f32) -> bool {
        self.refill();
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            ip_buckets: Arc::new(RwLock::new(HashMap::new())),
            peer_buckets: Arc::new(RwLock::new(HashMap::new())),
            global_bucket: Arc::new(RwLock::new(TokenBucket::new(100_000.0, 10_000.0))),
        }
    }

    /// Check if packet should be processed
    /// Returns true if within rate limits
    pub async fn check_limits(
        &self,
        source_ip: IpAddr,
        source_peer_id: &[u8; 32],
        packet_size_bytes: u32,
    ) -> bool {
        let cost = (packet_size_bytes as f32) / 1024.0;  // Convert bytes to KB

        // Check global limit
        let mut global = self.global_bucket.write().await;
        if !global.try_consume(cost) {
            return false;
        }
        drop(global);

        // Check per-IP limit (100 KB/s per IP)
        let mut ip_buckets = self.ip_buckets.write().await;
        let ip_bucket = ip_buckets
            .entry(source_ip)
            .or_insert_with(|| TokenBucket::new(100.0, 100.0));
        
        if !ip_bucket.try_consume(cost) {
            return false;
        }
        drop(ip_buckets);

        // Check per-peer limit (1 MB/s per peer)
        let mut peer_buckets = self.peer_buckets.write().await;
        let peer_bucket = peer_buckets
            .entry(*source_peer_id)
            .or_insert_with(|| TokenBucket::new(1000.0, 1000.0));
        
        peer_bucket.try_consume(cost)
    }
}
2.3 - Adaptive Timeout para Handshakes
Rust
// En src/transport/handshake.rs

#[derive(Clone)]
pub struct AdaptiveHandshakeManager {
    /// RTT estimator (EWMA)
    rtt_estimator: Arc<RwLock<HashMap<[u8; 32], u64>>>,
    
    /// Min/Max timeout bounds
    min_timeout_ms: u64,
    max_timeout_ms: u64,
}

impl AdaptiveHandshakeManager {
    pub fn new(min_timeout_ms: u64, max_timeout_ms: u64) -> Self {
        Self {
            rtt_estimator: Arc::new(RwLock::new(HashMap::new())),
            min_timeout_ms,
            max_timeout_ms,
        }
    }

    pub async fn get_timeout(&self, peer_id: &[u8; 32]) -> Duration {
        let estimator = self.rtt_estimator.read().await;
        let estimated_rtt = estimator.get(peer_id).copied().unwrap_or(50);
        
        // Timeout = 3 × RTT (permite retransmisiones)
        let timeout_ms = (estimated_rtt * 3)
            .clamp(self.min_timeout_ms, self.max_timeout_ms);
        
        Duration::from_millis(timeout_ms)
    }

    pub async fn record_rtt(&self, peer_id: [u8; 32], observed_rtt: u64) {
        let mut estimator = self.rtt_estimator.write().await;
        
        let existing = estimator.get(&peer_id).copied().unwrap_or(50);
        
        // EWMA: new_rtt = 0.2 × observed + 0.8 × existing
        let new_rtt = (0.2 * observed_rtt as f32 + 0.8 * existing as f32) as u64;
        
        estimator.insert(peer_id, new_rtt);
    }
}
FASE 3: OPTIMIZACIÓN (4-6 semanas)
3.1 - Fixed-Size Packet Structure
Rust
// En src/transport/packet.rs, reemplazar Ipv7Packet antiguo

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Ipv7PacketOptimizedV2 {
    pub version: u8,                     // 1 byte
    pub source_id: [u8; 32],             // 32 bytes
    pub destination_id: [u8; 32],        // 32 bytes
    pub ttl: u64,                        // 8 bytes
    pub timestamp: u64,                  // 8 bytes
    pub sequence_number: u64,            // 8 bytes
    pub nonce: [u8; 24],                 // 24 bytes (fixed, no length prefix)
    pub signature: [u8; 64],             // 64 bytes (fixed)
    pub payload_len: u16,                // 2 bytes (actual payload length)
    pub encrypted_payload: [u8; 1280],   // 1280 bytes (fixed max)
}

// Total: 1 + 32 + 32 + 8 + 8 + 8 + 24 + 64 + 2 + 1280 = 1459 bytes (vs variable 300-1500)

impl Ipv7PacketOptimizedV2 {
    pub fn to_bytes(&self) -> [u8; 1459] {
        // Usar MaybeUninit para memory-safe copy
        let mut buffer = [0u8; 1459];
        
        let mut offset = 0;
        buffer[offset] = self.version;
        offset += 1;
        
        buffer[offset..offset+32].copy_from_slice(&self.source_id);
        offset += 32;
        
        buffer[offset..offset+32].copy_from_slice(&self.destination_id);
        offset += 32;
        
        buffer[offset..offset+8].copy_from_slice(&self.ttl.to_le_bytes());
        offset += 8;
        
        buffer[offset..offset+8].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 8;
        
        buffer[offset..offset+8].copy_from_slice(&self.sequence_number.to_le_bytes());
        offset += 8;
        
        buffer[offset..offset+24].copy_from_slice(&self.nonce);
        offset += 24;
        
        buffer[offset..offset+64].copy_from_slice(&self.signature);
        offset += 64;
        
        buffer[offset..offset+2].copy_from_slice(&self.payload_len.to_le_bytes());
        offset += 2;
        
        buffer[offset..offset+1280].copy_from_slice(&self.encrypted_payload);
        
        buffer
    }

    pub fn from_bytes(buffer: &[u8; 1459]) -> Result<Self, &'static str> {
        if buffer.len() < 1459 {
            return Err("Buffer too small");
        }

        let mut offset = 0;
        let version = buffer[offset];
        offset += 1;

        let mut source_id = [0u8; 32];
        source_id.copy_from_slice(&buffer[offset..offset+32]);
        offset += 32;

        let mut destination_id = [0u8; 32];
        destination_id.copy_from_slice(&buffer[offset..offset+32]);
        offset += 32;

        let ttl = u64::from_le_bytes(buffer[offset..offset+8].try_into().unwrap());
        offset += 8;

        let timestamp = u64::from_le_bytes(buffer[offset..offset+8].try_into().unwrap());
        offset += 8;

        let sequence_number = u64::from_le_bytes(buffer[offset..offset+8].try_into().unwrap());
        offset += 8;

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&buffer[offset..offset+24]);
        offset += 24;

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buffer[offset..offset+64]);
        offset += 64;

        let payload_len = u16::from_le_bytes(buffer[offset..offset+2].try_into().unwrap());
        offset += 2;

        let mut encrypted_payload = [0u8; 1280];
        encrypted_payload.copy_from_slice(&buffer[offset..offset+1280]);

        Ok(Self {
            version,
            source_id,
            destination_id,
            ttl,
            timestamp,
            sequence_number,
            nonce,
            signature,
            payload_len,
            encrypted_payload,
        })
    }
}
3.2 - Connection Pool para UDP Sockets
Rust
// En src/transport/connection_pool.rs (nuevo)

use tokio::net::UdpSocket;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::net::SocketAddr;

pub struct UdpConnectionPool {
    /// Cache de sockets by remote address
    sockets: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    
    /// Socket compartido para escuchar
    listener_socket: Arc<UdpSocket>,
    
    /// Límite de conexiones
    max_connections: usize,
}

impl UdpConnectionPool {
    pub async fn new(listen_addr: &str, max_connections: usize) -> std::io::Result<Self> {
        let listener_socket = UdpSocket::bind(listen_addr).await?;
        
        Ok(Self {
            sockets: Arc::new(RwLock::new(HashMap::new())),
            listener_socket: Arc::new(listener_socket),
            max_connections,
        })
    }

    /// Envía a un destino, reutilizando socket si existe
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        // Usar socket compartido de escucha para envío (UDP puede reutilizar)
        self.listener_socket.send_to(data, addr).await
    }

    /// Recibe con timeout global
    pub async fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<(usize, SocketAddr)> {
        tokio::time::timeout(timeout, self.listener_socket.recv_from(buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "recv timeout"))?
    }
}
3.3 - Batch Processing de Paquetes
Rust
// En src/main.rs, reemplazar loop de procesamiento

use std::collections::VecDeque;

// En lugar de procesar 1 paquete a la vez:
let mut packet_batch = VecDeque::with_capacity(100);
let batch_timeout = Duration::from_millis(10);
let batch_deadline = Instant::now() + batch_timeout;

loop {
    let timeout_remaining = batch_deadline.saturating_duration_since(Instant::now());
    
    match tokio::time::timeout(
        timeout_remaining,
        relay.socket.recv_from(&mut buf),
    ).await {
        Ok(Ok((amt, src))) => {
            packet_batch.push_back((amt, src, buf.to_vec()));
            
            // Si batch lleno o deadline alcanzado, procesar
            if packet_batch.len() >= 100 || Instant::now() >= batch_deadline {
                process_batch(&packet_batch, &dht, &sessions, &tx).await;
                packet_batch.clear();
            }
        }
        Err(_) => {
            // Timeout: procesar lo que tenemos
            if !packet_batch.is_empty() {
                process_batch(&packet_batch, &dht, &sessions, &tx).await;
                packet_batch.clear();
            }
        }
        Ok(Err(e)) => {
            eprintln!("Socket error: {}", e);
        }
    }
}

async fn process_batch(
    batch: &VecDeque<(usize, SocketAddr, Vec<u8>)>,
    dht: &DhtRegistry,
    sessions: &SessionManager,
    tx: &mpsc::Sender<TuiEvent>,
) {
    // Procesar hasta 100 paquetes en paralelo
    let handles: Vec<_> = batch.iter().map(|(amt, src, data)| {
        let dht = dht.clone();
        let sessions = sessions.clone();
        let tx = tx.clone();
        let data = data.clone();
        let src = *src;
        
        tokio::spawn(async move {
            // Procesar paquete individual sin bloquear otros
            if let Ok(packet) = Ipv7Packet::from_bytes(&data[..amt]) {
                if packet.verify_origin_signature() {
                    dht.register_node(packet.source_id, src.to_string()).await;
                    // ... resto de lógica ...
                }
            }
        })
    }).collect();
    
    // Esperar a que completen, con timeout
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::join_all(handles),
    ).await;
}
📊 RESUMEN DE VULNERABILIDADES Y SOLUCIONES
ID	Vulnerabilidad	Severidad	Solución	Líneas de Código
1.1	Replay Attack en Firmas	🔴 CRÍTICO	Agregar nonce + timestamp verificado	150
1.2	Sin TTL en Timestamp	🔴 CRÍTICO	Validar age(timestamp) ≤ 30s	50
1.3	Clave pública no validada	🔴 CRÍTICO	Verificar formato Ed25519	40
1.4	Nonce no firmado	🟠 ALTO	Incluir nonce en firma	5
1.5	Sin Forward Secrecy	🟠 ALTO	HKDF per-packet key derivation	200
2.1	Socket cascade lenta	🔴 CRÍTICO	Reutilizar sockets UDP	100
2.2	Handshake 3s timeout	🔴 CRÍTICO	Adaptive timeout con EWMA RTT	120
2.3	Vec sin compresión	🟠 ALTO	Fixed-size arrays en struct	300
2.4	Verify firma antes limite	🟠 ALTO	Rate limiting + early drop	150
3.1	HashMap O(n) memory	🔴 CRÍTICO	K-Buckets Kademlia	500
3.2	Lookup O(n) lentitud	🔴 CRÍTICO	K-Buckets + XOR bucketing	(incluido 3.1)
3.3	Sin gestión de ciclo vida	🔴 CRÍTICO	TTL + PING periódico	300
🎯 CONCLUSIÓN FINAL
IPv7 v1.3.0 es concepto brillante pero implementación de producción prematura:

✅ Fortalezas:

Arquitectura P2P verdaderamente descentralizada
Stack criptográfico sólido (Ed25519, X25519, ChaCha20)
Código Rust rápido y memory-safe
❌ Limitaciones Críticas:

Vulnerable a replay attacks (sin remediar = compromiso total)
DHT HashMap no escala (máx ~1K nodos, no 1M)
Timeouts hardcodeados (3s = latencia prohibitiva)
Sin gestión de pares muertos