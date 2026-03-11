//! virtual_adapter.rs
//! Puente a nivel de Kernel del Sistema Operativo.
//! Toma tráfico IPv4/IPv6 plano, lo intercepta a nivel TUN/TAP, y lo inyecta a nuestro demonio IPv7.

pub async fn start_virtual_adapter() -> Result<tun::AsyncDevice, Box<dyn std::error::Error>> {
    tracing::info!("[*] Solicitando Privilegios de Kernel para Virtual Adapter TUN/TAP...");
    
    let mut config = tun::Configuration::default();
    config
        .address((10, 7, 7, 7)) // IP Mágica en la subred de nuestra VPN
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
            Ok(device)
        },
        Err(e) => {
            tracing::error!("[X] Permiso Denegado o Error al montar Interfaz Red (Wintun no encontrado o falto Privilegio).");
            Err(e.into())
        }
    }
}
