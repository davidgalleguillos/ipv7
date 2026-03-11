# Fase 11: Despliegue Masivo en Contenedores (Nodos Core de Alta Capacidad)
# Optimizado para orquestaciones como Kubernetes, Docker Swarm o despliegues Cloud Native.

# --- ETAPA 1: Construcción ---
FROM rust:1.80-slim-bookworm as builder

# Dependencias necesarias en Debian debido a las librerías criptográficas y subredes TUN
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/ipv7-core
# Copiamos el manifiesto primero para cachear deps
COPY ipv7-core/Cargo.toml .
# Creación de stub falso para compilar
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src/

# Copiamos el verdadero código fuente
COPY ipv7-core/src ./src
RUN touch src/main.rs
# Construimos el nodo IPv7 con todas las máximas optimizaciones LTO y directivas de Strip
RUN cargo build --release

# --- ETAPA 2: Runtime Minimalista ---
FROM debian:bookworm-slim

# Instalamos iproute2 para el adaptador /TUN y certificados root para interaccionar
RUN apt-get update && apt-get install -y ca-certificates iproute2 iptables && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/ipv7-core/target/release/ipv7-core /usr/local/bin/ipv7-core

# Declarar los puertos de overlay UDP donde la red p2p operará globalmente
EXPOSE 60553/udp 
EXPOSE 60554/udp

# Variables de entorno predeterminadas, útiles en K8s para la inyección estática
ENV RUST_LOG=info

# Ejecutar el demonio por defecto escuchando
ENTRYPOINT ["ipv7-core", "--listen"]
