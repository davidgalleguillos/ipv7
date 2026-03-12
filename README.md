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

## 🛠️ Cómo Utilizar el Motor IPv7 (Real, sin Mocks)

El motor se opera 100% mediante Terminal. Cada nodo tiene una **Identidad Soberana** generada automáticamente al iniciarse (ED25519 + Base58), visible en la consola del TUI.

### Flujo Completo de Conexión Orgánica (3 Terminales)

**Paso 1 — Levantar el Nodo Destino (Terminal 1):**
```bash
ipv7-core --listen
```
Guarda la dirección `id://Abc123...` que aparece. Es tu Identidad Soberana.

**Paso 2 — Inyectar tu IP en el DHT del otro nodo (UDP NAT Punching):**
```bash
ipv7-core --ping <IP:Puerto> id://Abc123...
```
Esto envía un `PING` autenticado hacia el IP real del nodo destino, que responde un `PONG` y ambos nodos quedan mutuamente registrados en sus Tablas Kademlia. No se necesita pre-configuración ni servidores centrales.

**Paso 3 — Conectar y hacer Handshake X25519:**
```bash
ipv7-core --connect id://Abc123...
```
Deriva orgánicamente un secreto compartido ChaCha20 via Diffie-Hellman. Ahora el canal está cifrado de extremo a extremo.

**Paso 4 (Opcional) — Enrutamiento Onion de Cascada:**
```bash
ipv7-core --cascade id://Destino... id://Relay...
```
Envuelve el mensaje en capas de cebolla y lo lanza via un nodo intermediario, disimulando el origen.

**Modo VPN — Interceptar tráfico IPv4 del OS:**
```bash
# Como Administrador:
ipv7-core --vpn
```
Instancia una interfaz virtual TUN/TAP en `10.7.7.7` para enrutar tráfico del sistema operativo.

*Al estar dentro de la Consola TUI: **`1`** = Telemetría | **`2`** = Explorador Kademlia DHT | **`q`** = Salir.*
