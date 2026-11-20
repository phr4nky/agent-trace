# agent-trace-server with the web UI. Build from the repository root:
#   docker build -f crates/agent-trace-server/Dockerfile -t agent-trace-server .
# or use docker-compose.yml (PostgreSQL + server).

# 1. Web UI (Angular + SwipyUI)
FROM node:24-alpine AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npx ng build

# 2. Server (Rust)
FROM rust:1-slim-trixie AS server
WORKDIR /src
# Only the Rust sources: a change of the UI does not rebuild the server.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p agent-trace-server

# 3. Runtime: the binary, the UI, no build tools, no root
FROM debian:trixie-slim
RUN useradd --system --uid 10001 --home-dir /data --create-home agenttrace
COPY --from=server /src/target/release/agent-trace-server /usr/local/bin/agent-trace-server
COPY --from=ui /ui/dist/agent-trace-ui/browser /srv/ui
USER agenttrace
WORKDIR /data
EXPOSE 8080
# Reads have no login yet: publish the port on loopback only (see docker-compose.yml) or put
# the server behind your own access control.
ENTRYPOINT ["agent-trace-server"]
CMD ["serve", "--listen", "0.0.0.0:8080", "--ui-dir", "/srv/ui", "--allow-unauthenticated-reads"]
