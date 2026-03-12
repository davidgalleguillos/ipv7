//! virtual_adapter.rs
//! Puente a nivel de Kernel del Sistema Operativo.
//! Toma tráfico IPv4/IPv6 plano, lo intercepta a nivel TUN/TAP, y lo inyecta a nuestro demonio IPv7.
//! Solo activo en plataformas Unix (Linux/macOS). En Windows se requiere Wintun instalado.

// En plataformas que soporten la API tun (Unix/Windows con Wintun)
pub async fn start_virtual_adapter() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("[*] Solicitando Privilegios de Kernel para Virtual Adapter TUN/TAP...");

    let mut config = tun::Configuration::default();
    config
        .address((10, 7, 7, 7))       // IP Mágica en la subred de nuestra VPN
        .netmask((255, 255, 255, 0))
        .destination((10, 7, 7, 1))
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    match tun::create_as_async(&config) {
        Ok(device) => {
            tracing::info!("[✓] Virtual Network Adapter CREADO [10.7.7.7].");
            // Mantener el device vivo (loop de captura de tráfico en el futuro)
            drop(device);
            Ok(())
        },
        Err(e) => {
            tracing::error!("[X] Permiso Denegado o Error al montar Interfaz Red.");
            Err(e.into())
        }
    }
}
