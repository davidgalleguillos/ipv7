# IPv7 Core (The Great Sandbox) 🌐🧅

Bienvenido a **IPv7**, el protocolo fundacional peer-to-peer de enrutamiento y cifrado profundo (Escudo de Cascada). IPv7 sustituye el paradigma cliente-servidor tradicional para crear conexiones VPN descentralizadas inescrutables, blindadas con matemática de Curva Elíptica (ED25519, X25519) y ChaCha20-Poly1305.

## 🚀 Instalación en Cualquier Computadora

Existen dos maneras de instalar el Demonio IPv7 en un equipo local u ordenador en la nube:

### Método 1: Binarios Pre-compilados (Recomendado)
Gracias a nuestro Sistema de Integración Continua (CI/CD), no necesitas saber programar para ejecutar IPv7.

1. Navega a la sección **[Releases](https://github.com/davidgalleguillos/ipv7/releases)** de este repositorio.
2. Descarga el ejecutable que corresponda a tu Sistema Operativo:
   - **Windows:** Descarga `ipv7-core-windows-amd64.exe`
   - **Linux:** Descarga `ipv7-core-linux-amd64`
   - **macOS:** Descarga `ipv7-core-macos-amd64`
3. Abre una terminal (o Símbolo del Sistema) en la carpeta donde lo descargaste y ejecútalo (ej: `./ipv7-core-windows-amd64.exe --listen`). 

*Nota: Para desplegar el Interceptor Virtual de Red local TUN/TAP (Phase 10), deberás correr el ejecutable con **Privilegios de Administrador** usando el flag `--vpn`.*

### Método 2: Compilación desde Fuente (Desarrolladores)
Si deseas compilar con tu propio compilador e inspeccionar la arquitectura en anillo (Ring-0) de la red:

1. Instala el entorno [Rust (rustup)](https://rustup.rs/).
2. Clona el repositorio:
   ```bash
   git clone https://github.com/davidgalleguillos/ipv7.git
   cd ipv7/ipv7-core
   ```
3. Compila el motor con Máxima Optimización P2P:
   ```bash
   cargo build --release
   ```
4. El binario ultra-rápido se encontrará en `target/release/ipv7-core`.

---

## 🛠️ Cómo Utilizar el Motor IPv7

El motor se opera 100% mediante Terminal con la Consola TUI Interactiva activada:

- **Modo Servidor / Escucha Pasiva:** `ipv7-core --listen`
  (Espera a conectarse a tu propia subred).
  
- **Modo Cliente VPN (Red Falsa Local):** `ipv7-core --vpn`
  (Instancia una interfaz en la IP Mágica `10.7.7.7` capturando tráfico físico).
  
- **Modo Inyector Proxy (Escudo de Cascada):** `ipv7-core --cascade`
  (Envuelve paquetes usando Onion-Routing para disfrazar tu identidad cruzando reles).

*Al estar dentro de la Consola TUI, presiona **`1`** para ver el estado del Enrutamiento o **`2`** para explorar a tus Vecinos P2P en el DHT.*
