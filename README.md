<div align="center">

# IPv7 Core 🌐

**El Protocolo de Red Soberana de Nueva Generación**

*Descentralizado · Cifrado de Extremo a Extremo · Sin Servidores Centrales · Sin Metadatos*

[![Release](https://img.shields.io/github/v/release/davidgalleguillos/ipv7?style=for-the-badge&color=blueviolet)](https://github.com/davidgalleguillos/ipv7/releases)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/davidgalleguillos/ipv7/release.yml?style=for-the-badge&label=CI%2FCD)](https://github.com/davidgalleguillos/ipv7/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)

</div>

---

## ¿Qué es IPv7?

IPv7 es un protocolo de red peer-to-peer de nueva generación que reemplaza el paradigma cliente-servidor tradicional. Proporciona:

- 🔐 **Identidad Soberana** — Cada nodo genera su propio par de llaves ED25519. No hay registro, no hay cuenta, no hay contraseña.
- 🤝 **Cifrado Real X25519 + ChaCha20-Poly1305** — El intercambio de claves Diffie-Hellman ocurre de forma orgánica entre pares. Ningún secreto está hardcodeado.
- 🧅 **Enrutamiento Cebolla (Onion Routing)** — Los mensajes viajan cifrados a través de nodos intermediarios que desconocen el origen y destino real.
- 🌐 **DHT Kademlia Descentralizado** — Los nodos se descubren entre sí automáticamente. No existe un servidor central que pueda ser bloqueado o censurado.
- 📡 **Bootstrap Multicapa Automático** — Al iniciar, el nodo busca pares en LAN, luego en la red global (Firebase), luego en nodos guardianes. Sin configuración manual.
- 🛡️ **VPN a Nivel de Kernel** — Interfaz TUN/TAP real para enrutar tráfico IPv4 del sistema operativo.

---

## 🚀 Instalación Rápida

### Opción A: Binario Pre-compilado (Recomendado)

No necesitas saber programar. Descarga y ejecuta:

| Sistema Operativo | Archivo |
|---|---|
| 🪟 Windows | [`ipv7-core-windows-amd64.exe`](https://github.com/davidgalleguillos/ipv7/releases/latest) |
| 🐧 Linux | [`ipv7-core-linux-amd64`](https://github.com/davidgalleguillos/ipv7/releases/latest) |
| 🍎 macOS Intel | [`ipv7-core-macos-amd64`](https://github.com/davidgalleguillos/ipv7/releases/latest) |
| 🍎 macOS Silicon | [`ipv7-core-macos-arm64`](https://github.com/davidgalleguillos/ipv7/releases/latest) |

```bash
# Linux / macOS: dar permisos y ejecutar
chmod +x ipv7-core-linux-amd64
./ipv7-core-linux-amd64 --listen

# Windows (PowerShell):
.\ipv7-core-windows-amd64.exe --listen
```

### Opción B: Compilar desde Fuente

```bash
# Requiere Rust: https://rustup.rs/
git clone https://github.com/davidgalleguillos/ipv7.git
cd ipv7/ipv7-core
cargo build --release
./target/release/ipv7-core --listen
```

> [!TIP]
> **Windows Users:** En caso de error, el programa pausará automáticamente la consola para permitirte leer el diagnóstico antes de cerrarse.

---

## 🛠️ Comandos

El motor opera 100% desde terminal. Al arrancar, el nodo genera su **Identidad Soberana** (Base58) visible en pantalla.

### Flujo de conexión entre dos computadoras (paso a paso)

```bash
# ── COMPUTADORA A (Destino, ej: tu casa) ─────────────────────────────
./ipv7-core --listen
# → Muestra: "Dirección: id://AbcXyz123..."
# → El nodo anuncia su presencia automáticamente en Firebase y en la LAN.

# ── COMPUTADORA B (Cliente, ej: cafetería) ───────────────────────────
# Paso 1: Introducirte en su DHT (UDP NAT Punching)
./ipv7-core --ping 192.168.1.100:60553 id://AbcXyz123...

# Paso 2: Handshake X25519 — derivar secreto ChaCha20 orgánicamente
./ipv7-core --connect id://AbcXyz123...

# Paso 3 (opcional): Enrutamiento Cebolla a través de un nodo intermediario
./ipv7-core --cascade id://Destino... id://Relay...
```

### Todos los comandos

| Comando | Descripción |
|---|---|
| `--listen` | Activa el nodo pasivo. Inicia bootstrap multicapa automático. Abre el TUI. |
| `--ping <IP:Puerto> id://XYZ` | Envía PING autenticado para registrarse en el DHT del destino. |
| `--connect id://XYZ` | Inicia Handshake X25519 y establece canal cifrado. |
| `--cascade id://Destino id://Relay` | Onion routing a través de un nodo intermediario. |
| `--vpn` | Levanta interfaz TUN/TAP en `10.7.7.7` *(requiere Administrador)*. |
| `--say <categoría> "<mensaje>"` | Envía feedback al desarrollador. Categorías: `bug`, `feature`, `hello`, `contrib`. |

### Teclas dentro del TUI
| Tecla | Función |
|---|---|
| `1` | Telemetría y traza de paquetes en tiempo real |
| `2` | Explorador Kademlia DHT (pares conocidos) |
| `3` | ★ Canal de Comunidad y Anuncios del Desarrollador |
| `q` | Salir |

---

## 🏗️ Arquitectura Técnica

```
┌─────────────────────────────────────────────────────┐
│                    IPv7 Core v1.1                   │
├─────────────┬───────────────┬───────────────────────┤
│  Identidad  │   Transporte  │         UI            │
│             │               │                       │
│  ED25519    │  UDP Overlay  │  Ratatui TUI          │
│  X25519 DH  │  Kademlia DHT │  3 Tabs               │
│  ChaCha20   │  Onion Relay  │  Telemetría           │
│  Zeroize    │  TUN/TAP      │  DHT Explorer         │
│             │  SessionMgr   │  Comunidad            │
│             │  Bootstrap:   │                       │
│             │   LAN mDNS    │                       │
│             │   Firebase    │                       │
│             │   Guardianes  │                       │
└─────────────┴───────────────┴───────────────────────┘
```

### Stack Tecnológico
- **Lenguaje:** Rust (edición 2021)
- **Runtime Asíncrono:** Tokio
- **Criptografía:** `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`
- **CLI/TUI:** Ratatui + Crossterm
- **Red:** UDP nativo + Tokio async sockets
- **Bootstrap Global:** Firebase Realtime Database (REST)
- **Serialización:** Bincode (binario eficiente) + Serde JSON (Firebase)

---

## 📡 Sistema de Bootstrap Multicapa

Cuando el nodo arranca, realiza automáticamente en segundos:

```
Nodo Nuevo
    │
    ▼  Capa 1: UDP Broadcast 255.255.255.255
    ├── ¿Hay pares en mi red doméstica?
    │    SÍ → "Unido a N nodos locales"
    │    NO → "🎉 PRIMER NODO en tu red doméstica"
    │
    ▼  Capa 2: Firebase Realtime Database
    ├── Anuncia tu IP al tablón global
    └── Descarga pares activos (<24h) del tablón
    
    ▼  Capa 3: 7 Guardian Nodes (fallback)
    └── Contacta nodos de alta reputación si todo falla
```

---

## 💬 Canal de Comunidad

Envía feedback directamente al desarrollador desde tu nodo:

```bash
./ipv7-core --say bug "Error al iniciar en Ubuntu 22.04"
./ipv7-core --say feature "Me gustaría soporte para IPv6 nativo"
./ipv7-core --say hello "¡Hola desde México! Increíble proyecto."
./ipv7-core --say contrib "Tengo un VPS y quiero ser nodo guardián"
```

Los mensajes llegan directamente a Firebase. El desarrollador los lee y responde via anuncios en el **Tab 3** del TUI.

---

## 🐳 Docker / Kubernetes

```bash
# Construir imagen
docker build -t ipv7-core .

# Ejecutar nodo
docker run --cap-add=NET_ADMIN --device /dev/net/tun ipv7-core --listen
```

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crea tu rama: `git checkout -b feat/mi-funcionalidad`
3. Haz commit: `git commit -m 'feat: descripción'`
4. Push: `git push origin feat/mi-funcionalidad`
5. Abre un Pull Request

O simplemente usa `--say contrib "tengo idea X"` y lo hablamos directamente.

---

## 📜 Licencia

MIT © 2026 David Galleguillos — [github.com/davidgalleguillos](https://github.com/davidgalleguillos)

> *"La privacidad no es para esconder algo malo. Es para proteger algo bueno."*
