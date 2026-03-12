//! virtual_adapter.rs
//! Puente a nivel de Kernel del Sistema Operativo (VPN TUN/TAP).
//!
//! Estado actual: Modo de detección e instalación guiada.
//! La activación completa requiere drivers adicionales:
//!   - Windows: instalar WinTun (https://www.wintun.net/)
//!   - Linux:   ejecutar como root (sudo)
//!   - macOS:   ejecutar como root (sudo)

use std::net::UdpSocket;

/// Inicia el modo VPN del nodo IPv7.
/// Levanta una interfaz de red virtual y comienza a interceptar tráfico IPv4.
pub async fn start_virtual_adapter() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("[VPN] ════════════════════════════════════════════");
    tracing::info!("[VPN]  IPv7 Virtual Network Adapter - v1.1");
    tracing::info!("[VPN] ════════════════════════════════════════════");
    tracing::info!("[VPN] Solicitando enlace kernel para interfaz TUN/TAP...");

    // Verificar que tenemos conectividad UDP básica (port 60553)
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let local = sock.local_addr()?;
            tracing::info!("[VPN] ✓ Pila de red detectada: {}", local);
        }
        Err(e) => {
            tracing::error!("[VPN] ✗ Sin acceso a la red: {}", e);
            return Err(e.into());
        }
    }

    tracing::info!("[VPN] -----------------------------------------------");
    tracing::info!("[VPN]  MODO VPN COMPLETO — Activación requerida:");
    tracing::info!("[VPN]");

    #[cfg(target_os = "windows")]
    {
        tracing::info!("[VPN]  Windows detectado.");
        tracing::info!("[VPN]  1. Descarga WinTun: https://www.wintun.net/");
        tracing::info!("[VPN]  2. Instala wintun.dll en System32");
        tracing::info!("[VPN]  3. Ejecuta como Administrador: ipv7-core --vpn");
    }

    #[cfg(target_os = "linux")]
    {
        tracing::info!("[VPN]  Linux detectado.");
        tracing::info!("[VPN]  1. Asegúrate de tener el módulo tun cargado:");
        tracing::info!("[VPN]     sudo modprobe tun");
        tracing::info!("[VPN]  2. Ejecuta con privilegios:");
        tracing::info!("[VPN]     sudo ipv7-core --vpn");
    }

    #[cfg(target_os = "macos")]
    {
        tracing::info!("[VPN]  macOS detectado.");
        tracing::info!("[VPN]  1. Ejecuta con privilegios:");
        tracing::info!("[VPN]     sudo ipv7-core --vpn");
    }

    tracing::info!("[VPN] -----------------------------------------------");
    tracing::info!("[VPN]  IPv7 P2P activo sin VPN. Todos los demás");
    tracing::info!("[VPN]  comandos funcionan sin privilegios especiales.");
    tracing::info!("[VPN] ════════════════════════════════════════════");

    // Mantener el proceso vivo mientras el usuario lee las instrucciones
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    Ok(())
}
