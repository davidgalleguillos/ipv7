//! main.rs
//! Demonio IPv7 Fase 2 (Enrutamiento UDP P2P Real y Escudo de Cascada)
#![allow(dead_code)]

mod config;
mod identity;
mod transport;
mod telemetry;
mod ui;

use identity::keys::NodeIdentity;
use identity::dht::{DhtRegistry, DhtPayload};
use transport::overlay::OverlayRelay;
use transport::packet::Ipv7Packet;
use transport::relay::RelayInstruction;
use transport::handshake::{HandshakeSession, HandshakeResponse};
use transport::crypto::SymmetricTunnel;
use transport::session::SessionManager;
use transport::virtual_adapter::start_virtual_adapter;
use transport::discovery::run_bootstrap;
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

    // Kademlia DHT Real Orgánico (Phase 13)
    let dht = DhtRegistry::new(*my_node.address.as_bytes());
    let sessions = SessionManager::new();

    if args[1] == "--listen" {
        // MODO NODO PASIVO (Esperando conexión)
        // Escuchar en TODAS las interfaces para recibir tanto LAN como WAN
        let relay = OverlayRelay::start_listener("0.0.0.0").await?;
        let local_addr = format!("0.0.0.0:{}", relay.bound_port);
        let my_id_b58 = my_node.address.to_string();
        tracing::info!("[📡] Escuchando activamente en el Subpuerto IPv7: {}", relay.bound_port);
        
        // ═══════════════════════════════════════════
        // FASE 14: Bootstrap Multicapa Automático
        // ═══════════════════════════════════════════
        run_bootstrap(
            my_node.address.as_bytes(),
            &my_id_b58,
            &local_addr,
            &dht,
        ).await;
        
        let tx_clone = tx.clone();
        let dht_clone = dht.clone();
        let sessions_clone = sessions.clone();
        let my_address_str = my_node.address.to_string();
        
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
                                
                                // AUTO-DESCUBRIMIENTO: Añadimos a quien sea que nos hable a nuestro Kademlia DHT (NAT Punching pasivo)
                                dht_clone.register_node(packet.source_id, src.to_string()).await;
                                
                                // Evaluar qué tipo de Payload es
                                if let Ok(dht_msg) = bincode::deserialize::<DhtPayload>(&packet.encrypted_payload) {
                                    match dht_msg {
                                        DhtPayload::Ping => {
                                            tracing::info!("    [+] PING recibido de {}. Respondiendo PONG.", src);
                                            let pong_bin = bincode::serialize(&DhtPayload::Pong).unwrap();
                                            let mut p_packet = Ipv7Packet {
                                                version:7, source_id: *my_node.address.as_bytes(), destination_id: packet.source_id,
                                                signature: vec![0u8; 64], ttl: config::master::DEFAULT_MESSAGE_TTL, nonce: vec![0], encrypted_payload: pong_bin,
                                            };
                                            let mut sm = Vec::new(); sm.extend_from_slice(&p_packet.source_id); sm.extend_from_slice(&p_packet.destination_id);
                                            sm.extend_from_slice(&p_packet.ttl.to_le_bytes()); sm.extend_from_slice(&p_packet.encrypted_payload);
                                            p_packet.signature = my_node.sign(&sm).to_bytes().to_vec();
                                            let _ = relay.send_raw_packet(&p_packet.to_bytes().unwrap(), &src.to_string()).await;
                                        },
                                        DhtPayload::Pong => {
                                            tracing::info!("    [+] PONG recibido. ¡Mapeo completado exitosamente!");
                                        },
                                        _ => {}
                                    }
                                } else if let Ok(hs_payload) = bincode::deserialize::<transport::handshake::HandshakePayload>(&packet.encrypted_payload) {
                                    let _ = tx_clone.send(TuiEvent::LogMsg(format!("    [✓] Handshake X25519 Request extraído. Efímera: {:?}", &hs_payload.ephemeral_public_key[0..4]))).await;
                                    
                                    // Responder Handshake Orgánico
                                    let local_session = HandshakeSession::new();
                                    let local_pubkey = *local_session.public_key.as_bytes();
                                    let shared_secret = local_session.derive_shared_secret(hs_payload.ephemeral_public_key);
                                    
                                    sessions_clone.add_secret(packet.source_id, shared_secret).await;
                                    let _ = tx_clone.send(TuiEvent::LogMsg("    [+] Sesión Asegurada. Secreto Orgánico ChaCha20 Almacenado.".to_string())).await;
                                    
                                    let resp_payload = HandshakeResponse { ephemeral_public_key: local_pubkey };
                                    let resp_bin = bincode::serialize(&resp_payload).unwrap();
                                    let mut resp_packet = Ipv7Packet {
                                        version: 7, source_id: *my_node.address.as_bytes(), destination_id: packet.source_id,
                                        signature: vec![0u8; 64], ttl: config::master::DEFAULT_MESSAGE_TTL, nonce: vec![0], encrypted_payload: resp_bin,
                                    };
                                    let mut sig_msg = Vec::new();
                                    sig_msg.extend_from_slice(&resp_packet.source_id); sig_msg.extend_from_slice(&resp_packet.destination_id);
                                    sig_msg.extend_from_slice(&resp_packet.ttl.to_le_bytes()); sig_msg.extend_from_slice(&resp_packet.encrypted_payload);
                                    resp_packet.signature = my_node.sign(&sig_msg).to_bytes().to_vec();
                                    
                                    if let Some(target_addr) = dht_clone.lookup(&packet.source_id).await {
                                        let _ = relay.send_raw_packet(&resp_packet.to_bytes().unwrap(), &target_addr).await;
                                    }
                                } else if let Ok(_hs_resp) = bincode::deserialize::<HandshakeResponse>(&packet.encrypted_payload) {
                                    let _ = tx_clone.send(TuiEvent::LogMsg("    [✓] Handshake RESPONSE Recibido. Túnel listo.".to_string())).await;
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
                                    if let Some(shared_secret) = sessions_clone.get_secret(&packet.source_id).await {
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
                                    } else {
                                        let _ = tx_clone.send(TuiEvent::LogMsg("    [X] ALERTA: Mensaje rechazado (No hay sesión Handshake guardada).".to_string())).await;
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
        let state = DashboardState::new(my_address_str, dht.snapshot_peers().await);
        run_dashboard(rx, state).await?;
        
    } else if args[1] == "--ping" {
        // MODO DESCUBRIMIENTO (Enviando PING para popular topología)
        if args.len() < 4 {
            tracing::error!("USO: ipv7-core --ping <IP:Puerto> <Base58_Target_ID>");
            return Ok(());
        }
        let target_address = &args[2];
        let decoded = bs58::decode(args[3].replace("id://", "")).into_vec().unwrap();
        let mut target_pubkey = [0u8; 32];
        target_pubkey.copy_from_slice(&decoded[0..32]);
        
        tracing::info!("[*] Ejecutando UDP NAT Punching hacia -> {}", target_address);
        let relay = OverlayRelay::start_listener("0.0.0.0").await?;
        
        let ping_bin = bincode::serialize(&DhtPayload::Ping).unwrap();
        let mut p_packet = Ipv7Packet {
            version: 7, source_id: *my_node.address.as_bytes(), destination_id: target_pubkey,
            signature: vec![0u8; 64], ttl: config::master::DEFAULT_MESSAGE_TTL, nonce: vec![0], encrypted_payload: ping_bin,
        };
        let mut sm = Vec::new(); sm.extend_from_slice(&p_packet.source_id); sm.extend_from_slice(&p_packet.destination_id);
        sm.extend_from_slice(&p_packet.ttl.to_le_bytes()); sm.extend_from_slice(&p_packet.encrypted_payload);
        p_packet.signature = my_node.sign(&sm).to_bytes().to_vec();
        
        relay.send_raw_packet(&p_packet.to_bytes().unwrap(), target_address).await?;
        tracing::info!("[✓] PING enviado. Tu nodo ahora está registrado en la tabla del oponente.");
        
        // Esperando PONG
        let mut buf = [0u8; config::master::DEFAULT_PACKET_SIZE];
        if let Ok(Ok((_amt, _))) = tokio::time::timeout(std::time::Duration::from_secs(3), relay.socket.recv_from(&mut buf)).await {
            tracing::info!("[✓] PONG recibido. Kademlia Orgánico Sincronizado recíprocamente.");
        } else {
            tracing::error!("[X] Timeout extenuado. El nodo está apagado o inalcanzable.");
        }
        
    } else if args[1] == "--connect" {
        if args.len() < 3 {
             tracing::error!("USO: ipv7-core --connect <Base58_Target_ID>"); return Ok(());
        }
        let decoded = bs58::decode(args[2].replace("id://", "")).into_vec().unwrap();
        let mut target_pubkey = [0u8; 32];
        target_pubkey.copy_from_slice(&decoded[0..32]);
        
        tracing::info!("[*] Consultando DHT local para localizar nodo id://{}...", args[2]);
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
        tracing::info!("[✓] Handshake proyectado al túnel. Esperando respuesta orgánica...");
        
        let mut buf = [0u8; config::master::DEFAULT_PACKET_SIZE];
        if let Ok(Ok((amt, _))) = tokio::time::timeout(std::time::Duration::from_secs(3), relay.socket.recv_from(&mut buf)).await {
            let pkt = Ipv7Packet::from_bytes(&buf[..amt]).unwrap();
            let hs_resp = bincode::deserialize::<HandshakeResponse>(&pkt.encrypted_payload).unwrap();
            let _shared_secret = handshake_session.derive_shared_secret(hs_resp.ephemeral_public_key);
            tracing::info!("[✓] Magia Diffie-Hellman completada. Secreto Orgánico ChaCha20 obtenido de la red exitosamente.");
        } else {
            tracing::error!("[X] Timeout. El nodo remoto no respondió el Handshake IPv7.");
        }
        
    } else if args[1] == "--cascade" {
        if args.len() < 4 {
             tracing::error!("USO: ipv7-core --cascade <Base58_Target_ID> <Base58_Relay_ID>"); return Ok(());
        }
        // MODO NODO ACTIVO ENRUTADO (Onion proxy vía Nodo Relé)
        tracing::info!("\n[*] INICIANDO TRANSMISIÓN DE CASCADA (ONION ROUTING)");
        
        let mut target_pubkey = [0u8; 32];
        let mut relay_pubkey = [0u8; 32];
        target_pubkey.copy_from_slice(&bs58::decode(args[2].replace("id://", "")).into_vec().unwrap()[0..32]);
        relay_pubkey.copy_from_slice(&bs58::decode(args[3].replace("id://", "")).into_vec().unwrap()[0..32]);
        
        // El relé es el único que necesitamos contactar físicamente ahora
        let relay_address = match dht.lookup(&relay_pubkey).await {
            Some(addr) => addr,
            None => return Ok(()),
        };
        tracing::info!("    -> ¡Endpoint físico del Relé localizado! {}", relay_address);
        let target_address = dht.lookup(&target_pubkey).await.unwrap_or_else(|| "127.0.0.1:60553".to_string());
        
        // --- Handshake Preliminar Directo (Para derivar orgánicamente el secreto sin Mocks) ---
        let net_relay = OverlayRelay::start_listener("0.0.0.0").await?;
        let handshake_session = HandshakeSession::new();
        let payload_bin = bincode::serialize(&handshake_session.create_payload()).unwrap();
        let mut hs_packet = Ipv7Packet {
            version: 7, source_id: *my_node.address.as_bytes(), destination_id: target_pubkey, signature: vec![0u8; 64],
            ttl: config::master::DEFAULT_MESSAGE_TTL, nonce: vec![0], encrypted_payload: payload_bin,
        };
        let mut sig_msg = Vec::new();
        sig_msg.extend_from_slice(&hs_packet.source_id); sig_msg.extend_from_slice(&hs_packet.destination_id);
        sig_msg.extend_from_slice(&hs_packet.ttl.to_le_bytes()); sig_msg.extend_from_slice(&hs_packet.encrypted_payload);
        hs_packet.signature = my_node.sign(&sig_msg).to_bytes().to_vec();
        
        net_relay.send_raw_packet(&hs_packet.to_bytes().unwrap(), &target_address).await?;
        
        let mut buf = [0u8; config::master::DEFAULT_PACKET_SIZE];
        let auth_secret = if let Ok(Ok((amt, _))) = tokio::time::timeout(std::time::Duration::from_secs(3), net_relay.socket.recv_from(&mut buf)).await {
            let pkt = Ipv7Packet::from_bytes(&buf[..amt]).unwrap();
            let hs_resp = bincode::deserialize::<HandshakeResponse>(&pkt.encrypted_payload).unwrap();
            let s = handshake_session.derive_shared_secret(hs_resp.ephemeral_public_key);
            tracing::info!("[✓] Pre-Acuerdo Orgánico exitoso (Target Derivó Mismo Secreto).");
            s
        } else {
            tracing::error!("    [X] Falló preparación orgánica prioritaria. Se suspende Cascada.");
            return Ok(());
        };

        // Cifrado Simétrico INEXPUGNABLE del payload interior (Fase 12)
        let tunnel = SymmetricTunnel::new(auth_secret);
        let secret_msg = b"ALERTA: Este mensaje viaja blindado con ChaCha20-Poly1305 real y asincrono a traves de la cebolla IPv7 sin Mocks.";
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
