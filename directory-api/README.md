# RustDesk Directory API (RDS)

> Built to run alongside a self-hosted [RustDesk](https://github.com/rustdesk/rustdesk) deployment —
> not affiliated with or endorsed by RustDesk. None of this exists without the RustDesk project: the
> [client](https://github.com/rustdesk/rustdesk), the
> [server](https://github.com/rustdesk/rustdesk-server), and the wider self-host ecosystem
> (https://rustdesk.com/docs/en/self-host/). Full credit to the RustDesk team and contributors — this
> is original code written to add self-hosted Pro-tier-style management features (enrollment, 2FA,
> audit logging, relay-access leasing, admin UI) on top of the open-source server, not a modified
> copy of any RustDesk source.

A self-hosted management layer for a private RustDesk deployment: device enrollment, operator
accounts with 2FA, audit logging, relay-access leasing, and an admin web UI, sitting in front of
your own hbbs/hbbr (rendezvous/relay) server.

This directory does not build or run hbbs/hbbr itself — build the `rustdesk-server` source one level
up (or run a published RustDesk server image) separately. Nothing here is configured with the
hbbs/hbbr address: edit the `rustdesk_server` placeholder in `app/security_extension.py`. The health
collector expects containers named `rustdesk-hbbs`/`rustdesk-hbbr` on the same host, and the
Caddyfile expects their WebSocket listeners on `127.0.0.1:21118`/`21119`.

## RustDrop

Resumable, end-to-end encrypted file drops between managed Clients (`app/rustdrop.py`). This
service authorizes and brokers each drop — does the sender own it, is the recipient the addressee —
but never sees plaintext file contents (file names and sizes are visible to it); it relays
ciphertext to a separate, single-purpose blob store (see the
[rustdrop-storage](https://github.com/MAGA-Brad/rustdrop-storage) repo) that knows nothing about
device identity at all. Configured via `RUSTDROP_STORAGE_BASE_URL` and `RUSTDROP_STORAGE_SECRET` in
`.env`; both are required, so the stack won't start without a RustDrop storage backend. Place that
backend's CA certificate at `config/rustdrop-storage-ca.pem`. Still in active development.

## Screenshots

| | |
|---|---|
| ![Managed Client directory (RDC)](screenshots/RDC_Directory.png) | ![RustDrop — send to a managed Client](screenshots/RustDrop_Directory.png) |
| ![RustDesk and RustDrop side by side, light theme](screenshots/RDC_RustDrop_Light.png) | ![RustDrop — incoming and outgoing transfers](screenshots/RustDrop_Pending_Transfer.png) |
| ![Admin dashboard — Group Management overview](screenshots/RDS_Dashboard_Overview.png) | ![Admin dashboard — Client build/update status](screenshots/RDS_Client_Update_Status.png) |
| ![Admin dashboard — Server Health](screenshots/RDS_ServerHealth.png) | |

## Layout

- `app/` — FastAPI application (`main.py` plus `admin_ui.py`, `security_extension.py`,
  `mobile_api.py`, `managed_chat.py`, `device_logs.py`, `rustdrop.py`), built and run via
  `compose.yml`.
- `migrations/` — schema migrations, applied in order. There is no automated runner; apply each
  file manually with `psql` against the `database` container the first time you stand up the stack.
  **Known gap:** the schema for `security_settings`, `relay_access_leases` and
  `operator_access_resets` is not included yet, so 018 and 021 fail on a fresh database; and 023
  needs your first Owner account created by hand (with its id filled in) before it will apply.
- `compose.yml` / `compose.override.yml` — the `database` (Postgres) and `api` services.
- `.env.example` — copy to `.env` and fill in real secrets before starting the stack
  (`docker compose up -d`). The ops scripts assume the stack lives in `/opt/rustdesk-directory` with
  their secrets in `config/secrets.env`.
- `deploy/caddy/Caddyfile` — reference reverse-proxy config for four vhosts: a public rendezvous
  domain (also carrying the `/ws/id` and `/ws/relay` WebSocket routes), an ops/admin domain and a
  managed-client API domain (both using a TLS origin cert), and a direct, not-CDN-proxied RustDrop
  transfer domain. Adjust domains, the origin cert paths, and the `proxy_protocol allow` source IP
  for your own edge.
- `deploy/sbin/` — operational scripts (backups, backup verification, relay-guard mode CLI and
  firewall-sync daemon, health collector, signed update-bundle publisher, owner emergency recovery,
  an SSH-only host firewall, and a Caddy root-permission preflight). Intended to live at
  `/usr/local/sbin/` on the host.
- `deploy/systemd/` — unit/timer files wiring the backup, restore-verify, relay-guard sync,
  health-collector and host-firewall scripts into systemd; the rest are run by hand. Intended to
  live at `/etc/systemd/system/`.

## First-time setup (sketch)

1. `cp .env.example .env` and fill in strong random secrets.
2. `docker compose up -d database`, then apply `migrations/*.sql` in order against it.
3. Set `FORWARDED_ALLOW_IPS` in `compose.yml` to your Docker network's gateway address (otherwise
   every client appears to come from the gateway), then `docker compose up -d api`.
4. Put `deploy/caddy/Caddyfile` in place (edit the domains and TLS cert paths first), reverse-proxying
   to `127.0.0.1:21120`.
5. Install the scripts in `deploy/sbin/` and units in `deploy/systemd/` if you want the backup,
   relay-guard, and health-collector automation. Edit the SSH source range in
   `rustdesk-host-firewall` before enabling it, or you will lock yourself out.
6. Generate your own hbbs/hbbr keypair and TLS certificates — none are included here.
