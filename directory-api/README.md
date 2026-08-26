# RustDesk Directory API (RDS)

A self-hosted management layer for a private [RustDesk](https://github.com/rustdesk/rustdesk) deployment:
device enrollment, operator accounts with 2FA, audit logging, relay-access leasing, and an admin
web UI, sitting in front of your own hbbs/hbbr (rendezvous/relay) server.

This directory does not build or run hbbs/hbbr itself — build the `rustdesk-server` source one level
up (or run a published RustDesk server image) separately, and point `RUSTDESK_SERVER_ADDRESS` at it.

## Layout

- `app/` — FastAPI application (`main.py`, `admin_ui.py`, `security_extension.py`), built and run
  via `compose.yml`.
- `migrations/` — schema migrations, applied in order. There is no automated runner; apply each
  file manually with `psql` against the `database` container the first time you stand up the stack.
- `compose.yml` / `compose.override.yml` — the `database` (Postgres) and `api` services.
- `.env.example` — copy to `.env` and fill in real secrets before starting the stack
  (`docker compose up -d`).
- `deploy/caddy/Caddyfile` — reference reverse-proxy config for three vhosts: a public rendezvous
  domain, an ops/admin domain (TLS origin cert required), and a managed-client API domain. Adjust
  domains, the origin cert paths, and the `proxy_protocol allow` source IP for your own edge.
- `deploy/sbin/` — operational scripts (backups, backup verification, relay firewall guard, health
  collector, signed update-bundle publisher, owner emergency recovery). Intended to live at
  `/usr/local/sbin/` on the host.
- `deploy/systemd/` — unit/timer files wiring the above scripts into systemd. Intended to live at
  `/etc/systemd/system/`.

## First-time setup (sketch)

1. `cp .env.example .env` and fill in strong random secrets.
2. `docker compose up -d database`, then apply `migrations/*.sql` in order against it.
3. `docker compose up -d api`.
4. Put `deploy/caddy/Caddyfile` in place (edit the domains and TLS cert paths first), reverse-proxying
   to `127.0.0.1:21120`.
5. Install the scripts in `deploy/sbin/` and units in `deploy/systemd/` if you want the backup,
   relay-guard, and health-collector automation.
6. Generate your own hbbs/hbbr keypair and TLS certificates — none are included here.
