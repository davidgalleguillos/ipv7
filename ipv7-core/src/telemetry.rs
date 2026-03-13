//! telemetry.rs
//! Motor de Trazas (Logging) y Telemetría Estructurada para IPv7.
//! Reemplaza los logs estándar por eventos asíncronos procesables de alto rendimiento.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Inicializa el suscriptor de tracing global.
/// Por defecto se emiten logs a nivel INFO, a menos que la variable
/// de entorno RUST_LOG dicte lo contrario (e.g., RUST_LOG=debug).
pub fn init_telemetry() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let format = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(true)
        .with_line_number(true)
        .compact(); // Formato denso ideal para "kernel-level" logs en el TUI

    tracing_subscriber::registry()
        .with(filter)
        .with(format)
        .init();
}
