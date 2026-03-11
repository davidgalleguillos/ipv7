//! main.rs
//! Demonio IPv7 Fase 2 (Enrutamiento UDP P2P Real y Escudo de Cascada)
#![allow(dead_code)]

mod config;
mod identity;
mod transport;
mod telemetry;
mod ui;

use identity::keys::NodeIdentity;
use identity::dht::DhtRegistry;
use transport::overlay::OverlayRelay;
use transport::packet::Ipv7Packet;
use transport::relay::RelayInstruction;
use transport::handshake::HandshakeSession;
use transport::crypto::SymmetricTunnel;
use transport::virtual_adapter::start_virtual_adapter;
use ui::dashboard::{run_dashboard, DashboardState, TuiEvent};
use std::env;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    telemetry::init_telemetry();
    
    tracing::info!("===========================================================");
    tracing::info!("Iniciando Motor Cuántico IPv7 - Fase 4 (Telemetría & TUI)");
    tracing::info!("===========================================================");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        tracing::error!("USO: ipv7-core [--listen] | [--connect] | [--cascade] | [--vpn]");
        std::process::exit(1);
    }

    let my_node = NodeIdentity::generate_new();
    tracing::info!("[*] Identidad Local Soberana Generada.");
    tracing::info!("    -> Dirección: {}", my_node.address.to_string());
    
    // Configurar canal para enviar logs desde la asincronía al TUI
    let (tx, rx) = mpsc::channel::<TuiEvent>(100);

    // SIMULACIÓN DHT (Phase 3 & 6)
    // En el futuro, resolver "id://" a IP real usará Kademlia DHT.
    let mut dht = DhtRegistry::new(*my_node.address.as_bytes());
    let sim_dest_pubkey = [0x99; 32];
    let sim_relay_pubkey = [0x88; 32]; // Nodo Intermedio

    // Hardcodeo las rutas físicas para pruebas locales:
    // El listener 1 tomará 60553 (Destino). El listener 2 tomará 60554 (Relay).
    dht.register_node(sim_dest_pubkey, "127.0.0.1:60553".to_string()).await;
    dht.register_node(sim_relay_pubkey, "127.0.0.1:60554".to_string()).await;

    if args[1] == "--listen" {
        // MODO NODO PASIVO (Esperando conexión)
        let relay = OverlayRelay::start_listener("127.0.0.1").await?;
        tracing::info!("[📡] Escuchando activamente en el Subpuerto IPv7: {}", relay.bound_port);
        tracing::debug!("[📡] Dile a otro nodo que se conecte a ti usando tu IP de red de área local y puerto.");
        
        let tx_clone = tx.clone();
        let dht_clone = dht.clone();
        
        // Desplazar el bucle de red UDP a una tarea asíncrona de fondo
        tokio::spawn(async move {
            let mut buf = [0u8; config::master::DEFAULT_PACKET_SIZE];
            loop {
                if let Ok((amt, src)) = relay.socket.recv_from(&mut buf).await {
                    let msg = format!("[!] Paquete IPv7 crudo recibido desde {} ({} bytes)", src, amt);
                    tracing::info!("{}", msg);
                    let _ = tx_clone.send(TuiEvent::LogMsg(msg)).await;
                    
                    match Ipv7Packet::from_bytes(&buf[..amt]) {
                        Ok(packet) => {
                            let _ = tx_clone.send(TuiEvent::LogMsg("    [✓] Estructura IPv7 Válida.".to_string())).await;
                            
                            if packet.verify_origin_signature() {
                                let _ = tx_clone.send(TuiEvent::LogMsg("    [✓] Firma ED25519 de Origen AUTENTICADA.".to_string())).await;
                                
                                // Evaluar qué tipo de Payload es
                                if let Ok(hs_payload) = bincode::deserialize::<transport::handshake::HandshakePayload>(&packet.encrypted_payload) {
                                    let _ = tx_clone.send(TuiEvent::LogMsg(format!("    [✓] Handshake X25519 extraído. Efímera: {:?}", &hs_payload.ephemeral_public_key[0..4]))).await;
                                } else if let Ok(relay_payload) = bincode::deserialize::<RelayInstruction>(&packet.encrypted_payload) {
                                    let _ = tx_clone.send(TuiEvent::LogMsg("    [🛡️] Instrucción de RELÉ (Cebolla) detectada.".to_string())).await;
                                    let _ = tx_clone.send(TuiEvent::LogMsg(format!("    [*] Desenvolviendo y reinyectando a DHT Target ID..."))).await;
                                    
                                    // Búsqueda en el DHT del siguiente salto
                                    let target_addr = dht_clone.lookup(&relay_payload.target_id).await.unwrap_or_else(|| "127.0.0.1:60553".to_string());
                                    tracing::info!("[Cascada] Reenviando paquete pelado hacia: {}", target_addr);
                                    let _ = tx_clone.send(TuiEvent::LogMsg(format!("    [🚀] Rebotando hacia IP física: {}", target_addr))).await;
                                    
                                    // Firing the nested raw packet forward as proxy
                                    let _ = relay.send_raw_packet(&relay_payload.nested_packet, &target_addr).await;
                                } else {
                                    tracing::warn!("Payload no es Handshake ni RelayInstruction. Asumiendo Datos Cifrados Finales.");
                                    let shared_secret = [0x55; 32]; // Secreto pre-acordado simulado (Post-Handshake)
                                    let tunnel = SymmetricTunnel::new(shared_secret);
                                    match tunnel.decrypt_payload(&packet.nonce, &packet.encrypted_payload) {
                                        Ok(plaintext) => {
                                            let msg = String::from_utf8_lossy(&plaintext);
                                            let _ = tx_clone.send(TuiEvent::LogMsg(format!("    [📥] MENSAJE SEGURO DESCIFRADO: {}", msg))).await;
                                        },
                                        Err(e) => {
                                            let _ = tx_clone.send(TuiEvent::LogMsg(format!("    [X] ALERTA CRÍTICA: Error ChaCha20-Poly1305. {}", e))).await;
                                        }
                                    }
                                }
                            } else {
                                let _ = tx_clone.send(TuiEvent::LogMsg("    [X] ALERTA: Firma Inválida.".to_string())).await;
                            }
                        },
                        Err(_) => {
                            let _ = tx_clone.send(TuiEvent::LogMsg("    [X] Basura irreconocible en puerto IPv7.".to_string())).await;
                        }
                    }
                }
            }
        });

        // Hilo principal queda atrapado re-dibujando el TUI
        let state = DashboardState::new(my_node.address.to_string(), dht.snapshot_peers().await);
        run_dashboard(rx, state).await?;
        
    } else if args[1] == "--connect" {
        // MODO NODO ACTIVO (Enviando un Handshake Inicial)
        let target_pubkey = sim_dest_pubkey;
        
        tracing::info!("[*] Consultando DHT local para localizar nodo id://[DESTINO_SIMULADO]...");
        let target_address = match dht.lookup(&target_pubkey).await {
            Some(addr) => addr,
            None => {
                tracing::error!("[X] Error DHT: Nodo no registrado.");
                return Ok(());
            }
        };
        tracing::info!("    -> ¡Endpoint físico localizado! {}", target_address);
        
        let relay = OverlayRelay::start_listener("0.0.0.0").await?;
        
        // Fase 3: Iniciando Handshake
        tracing::info!("[*] Generando materiales para sesión de Handshake X25519...");
        let handshake_session = HandshakeSession::new();
        let payload_struct = handshake_session.create_payload();
        
        // Empaquetamos la llave pública efímera dentro del payload
        let payload_bin = bincode::serialize(&payload_struct).unwrap();

        let packet = Ipv7Packet {
            version: 7,
            source_id: *my_node.address.as_bytes(),
            destination_id: target_pubkey,
            signature: vec![0u8; 64],
            ttl: config::master::DEFAULT_MESSAGE_TTL,
            nonce: vec![0,1,2,3,4], // Simulación hasta Fase 4 (crypto tunnel)
            encrypted_payload: payload_bin,
        };

        let mut raw_sig_message = Vec::new();
        raw_sig_message.extend_from_slice(&packet.source_id);
        raw_sig_message.extend_from_slice(&packet.destination_id);
        raw_sig_message.extend_from_slice(&packet.ttl.to_le_bytes());
        raw_sig_message.extend_from_slice(&packet.encrypted_payload);

        let signature_bytes = my_node.sign(&raw_sig_message).to_bytes();
        
        let final_packet = Ipv7Packet {
            signature: signature_bytes.to_vec(),
            ..packet
        };

        let raw_bytes = final_packet.to_bytes().expect("Error empacando Bincode");
        
        tracing::debug!("[🚀] Empaquetado estructural ({} bytes en total).", raw_bytes.len());
        tracing::info!("[🚀] Disparando Handshake Request TCP-like sobre UDP hacia -> {}", target_address);
        
        relay.send_raw_packet(&raw_bytes, &target_address).await?;
        tracing::info!("[✓] Handshake proyectado al túnel.");
        
    } else if args[1] == "--cascade" {
        // MODO NODO ACTIVO ENRUTADO (Onion proxy vía Nodo 2)
        tracing::info!("\n[*] INICIANDO TRANSMISIÓN DE CASCADA (ONION ROUTING)");
        
        let target_pubkey = sim_dest_pubkey;
        let relay_pubkey = sim_relay_pubkey;
        
        // El relé es el único que necesitamos contactar físicamente ahora
        let relay_address = match dht.lookup(&relay_pubkey).await {
            Some(addr) => addr,
            None => return Ok(()),
        };
        tracing::info!("    -> ¡Endpoint físico del Relé localizado! {}", relay_address);
        
        // Cifrado Simétrico del payload interior (Fase 7)
        let shared_secret = [0x55; 32];
        let tunnel = SymmetricTunnel::new(shared_secret);
        let secret_msg = b"ALERTA: Este mensaje viaja blindado con ChaCha20-Poly1305 a traves de la cebolla IPv7.";
        let (nonce, encrypted_body) = tunnel.encrypt_payload(secret_msg).unwrap();

        // Paquete Cebolla INTERNO (El que verá el destino final)
        let inner_packet = Ipv7Packet {
            version: 7,
            source_id: *my_node.address.as_bytes(), // Firma final será de nosotros
            destination_id: target_pubkey,
            signature: vec![0u8; 64],
            ttl: config::master::DEFAULT_MESSAGE_TTL - 1,
            nonce: nonce,
            encrypted_payload: encrypted_body,
        };

        let mut inner_sig_msg = Vec::new();
        inner_sig_msg.extend_from_slice(&inner_packet.source_id);
        inner_sig_msg.extend_from_slice(&inner_packet.destination_id);
        inner_sig_msg.extend_from_slice(&inner_packet.ttl.to_le_bytes());
        inner_sig_msg.extend_from_slice(&inner_packet.encrypted_payload);
        
        let inner_signed = Ipv7Packet {
            signature: my_node.sign(&inner_sig_msg).to_bytes().to_vec(),
            ..inner_packet
        };
        
        let inner_bytes = inner_signed.to_bytes().unwrap();

        // Envolvemos eso en una "Instrucción de Relé"
        let relay_instruction = RelayInstruction {
            target_id: target_pubkey,
            nested_packet: inner_bytes,
        };
        let relay_payload_bin = bincode::serialize(&relay_instruction).unwrap();

        // Paquete Cebolla EXTERNO (Solo lo ve el Relé)
        let outer_packet = Ipv7Packet {
            version: 7,
            source_id: *my_node.address.as_bytes(),
            destination_id: relay_pubkey,
            signature: vec![0u8; 64],
            ttl: config::master::DEFAULT_MESSAGE_TTL,
            nonce: vec![0,1],
            encrypted_payload: relay_payload_bin,
        };

        let mut outer_sig_msg = Vec::new();
        outer_sig_msg.extend_from_slice(&outer_packet.source_id);
        outer_sig_msg.extend_from_slice(&outer_packet.destination_id);
        outer_sig_msg.extend_from_slice(&outer_packet.ttl.to_le_bytes());
        outer_sig_msg.extend_from_slice(&outer_packet.encrypted_payload);
        
        let outer_signed = Ipv7Packet {
            signature: my_node.sign(&outer_sig_msg).to_bytes().to_vec(),
            ..outer_packet
        };
        let final_raw_bytes = outer_signed.to_bytes().unwrap();

        let net_relay = OverlayRelay::start_listener("0.0.0.0").await?;
        tracing::info!("[🚀] Disparando Cebolla Exterior hacia el Relé IP -> {}", relay_address);
        net_relay.send_raw_packet(&final_raw_bytes, &relay_address).await?;
        tracing::info!("[✓] Cascada inicializada ciegamente.");
        
    } else if args[1] == "--vpn" {
        // MODO NODO VPN (Abre TAP OS)
        tracing::info!("\n[*] INICIANDO MONTAJE TUN/TAP (Phase 10)");
        match start_virtual_adapter().await {
            Ok(_device) => {
                tracing::info!("    [✓] ¡Enlace Kernel-IPv7 Preparado! Capturando tráfico IPv4 local y enrutando con criptografía fuerte.");
            },
            Err(e) => {
                 tracing::error!("    [X] Error crítico. Reintente como Administrador o instale tun/tap drivers: {}", e);
            }
        }
    } else {
         tracing::error!("Argumentos inválidos.");
    }

    Ok(())
}
