# RustDesk Directory API (RDS)

> Built to run alongside a self-hosted [RustDesk](https://github.com/rustdesk/rustdesk) deployment —
> not affiliated with or endorsed by RustDesk. None of this exists without the RustDesk project: the
> [client](https://github.com/rustdesk/rustdesk), the
> [server](https://github.com/rustdesk/rustdesk-server), and the wider self-host ecosystem
> (https://rustdesk.com/docs/en/self-host/). Full credit to the RustDesk team and contributors — this
> is original code written to add self-hosted Pro-tier-style management features (enrollment, 2FA,
> audit logging, relay-access leasing, device certificates and passports, admin UI) on top of the
> open-source server, not a modified copy of any RustDesk source.

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
  `mobile_api.py`, `managed_chat.py`, `device_logs.py`, `rustdrop.py`, `sealed.py` for the sealed
  transport, `edge_certs.py` for edge client certificates, `device_sync.py` for change-driven
  sync, and `ca_link.py`, the job link the passport CA VM pulls from), built and run via
  `compose.yml`.
- `ca/` — the device-passport CA, which runs on its own VM, not in this stack: `ca/passport` is the
  passport format crate (shared with the relay's passport check) and `ca/signer` the signer
  (`ca-signer run|gen-root|root-pubkey|import <file>|verify-log|version [--config path]`, config
  in `/etc/ca-signer/config.json` by default). Build with `cargo build --release` in
  `ca/signer`; a static musl build runs on a minimal VM.
- `migrations/` — schema migrations, applied in file-name order (`017a_…` sits between 017 and
  018). There is no automated runner; apply each file with `psql` against the `database` container
  the first time you stand up the stack (see First-time setup). They apply cleanly to an empty
  database; no account has to exist first.
- `compose.yml` / `compose.override.yml` — the `database` (Postgres), `api` and `ca-link`
  services. `ca-link` listens on port 9443 of `CA_LINK_BIND` (an internal interface only the CA VM
  can reach) and accepts only client certificates signed by the link CA in `config/ca-link/`.
- `.env.example` — copy to `.env` and fill in real secrets before starting the stack
  (`docker compose up -d`). The ops scripts assume the stack lives in `/opt/rustdesk-directory` with
  their secrets in `config/secrets.env`.
- `deploy/caddy/Caddyfile` — reference reverse-proxy config for five vhosts: a public rendezvous
  domain (also carrying the `/ws/id` and `/ws/relay` WebSocket routes), an ops/admin domain and a
  managed-client API domain (both using a TLS origin cert), a direct, not-CDN-proxied RustDrop
  transfer domain, and a CDN-only WebSocket fallback domain for clients built with
  `RUSTDESK_MANAGED_WS_FALLBACK_HOST` (origin-pull client certificate required; the client address
  comes from the CDN's header). Adjust domains, the origin cert paths, and the
  `proxy_protocol allow` source IP for your own edge.
- `deploy/sbin/` — operational scripts (backups, backup verification, relay-guard mode CLI and
  firewall-sync daemon, health collector, signed update-bundle publisher, first-Owner bootstrap,
  owner emergency recovery, an SSH-only host firewall, a Caddy root-permission preflight, and a
  per-minute sync that gives relays built from rustdesk-managed-relay their approved IDs, the
  identity-key fingerprints for the passport check and the Remote Connections settings, and
  returns hbbs's encryption and passport counts).
  Intended to live at `/usr/local/sbin/` on the host.
- `deploy/systemd/` — unit/timer files wiring the backup, restore-verify, relay-guard sync,
  approved-ID/settings sync, health-collector and host-firewall scripts into systemd; the rest are
  run by hand. Intended to live at `/etc/systemd/system/`.

## First-time setup (sketch)

1. `cp .env.example .env` and fill in strong random secrets. The ops scripts read their own copy
   from `config/secrets.env`; put the same `TOTP_ENCRYPTION_SECRET=` line there.
2. `docker compose up -d database`, then apply every migration in order, stopping at the first
   error:
   ```sh
   for f in $(LC_ALL=C ls migrations/*.sql); do
     echo "$f"
     docker exec -i rustdesk-directory-db psql -X -q -v ON_ERROR_STOP=1 \
       -U rustdesk_directory -d rustdesk_directory < "$f" || break
   done
   ```
3. Create the first (Creator-)Owner account, as root on the host:
   `bash deploy/sbin/rustdesk-owner-bootstrap`. It asks for a username, display name and password,
   enrolls an authenticator (TOTP) and inserts the one Owner the database allows to be created
   directly; it refuses to run once any Owner exists, and prints the new account's id. Invite
   everyone else from the dashboard afterwards.

   Then make that account the protected primary Owner. The code recognises it by two hard-coded
   values, and **both** must match it:
   - **Username** (default `brad`). Only this value decides who gets the Mail and Config tabs
     (SMTP, security, power and RustDrop settings) and device-log requests, both in the dashboard
     and in the API, and which account the dashboard shows as protected. Either name your first
     Owner `brad`, or change every copy: `PROTECTED_BRAD_USERNAME` in `app/main.py`, `isBrad()`
     and `isProtectedBradAccount()` in `app/admin_ui.py`, and the four `'brad'` literals in
     migration 023.
   - **Account id** (`PROTECTED_BRAD_ACCOUNT_ID` in `app/main.py`, shipped as the all-zero
     placeholder). This is **required**: alert emails go only to the email address of the account
     with this id, so with the placeholder no alert mail is ever sent. (Lifecycle/role protection
     in the API and in 023's trigger matches either the username or the id.) Get the id from the
     bootstrap output or with
     `docker exec rustdesk-directory-db psql -U rustdesk_directory -d rustdesk_directory -Atc "SELECT creator_owner_id FROM directory_instance"`.
     Set it in `app/main.py`, replace the four all-zero UUIDs in migration 023 with it, and
     re-apply 023, which is safe to re-run:
     `docker exec -i rustdesk-directory-db psql -X -q -v ON_ERROR_STOP=1 -U rustdesk_directory -d rustdesk_directory < migrations/023_operator_account_lifecycle_delete.sql`

   `app/` is built into the api image, so make these edits before step 4, or rebuild afterwards
   with `docker compose up -d --build api`. Once you are signed in, open **My Account** and set
   that account's email address so alert mail has a recipient. Alert mail also needs
   `SMTP_ENCRYPTION_SECRET` in `.env` and an enabled SMTP server on the Mail tab.
4. Set `FORWARDED_ALLOW_IPS` in `compose.yml` to your Docker network's gateway address (otherwise
   every client appears to come from the gateway), then `docker compose up -d api`.
5. Put `deploy/caddy/Caddyfile` in place (edit the domains and TLS cert paths first), reverse-proxying
   to `127.0.0.1:21120`.
6. Install the scripts in `deploy/sbin/` and units in `deploy/systemd/` if you want the backup,
   relay-guard, and health-collector automation. Edit the SSH source range in
   `rustdesk-host-firewall` before enabling it, or you will lock yourself out.
7. Generate your own hbbs/hbbr keypair and TLS certificates — none are included here.
8. Peer authentication (device certificates), optional but recommended:
   - **Create the CA key.** Generate one as described in `.env.example` and set
     `PEER_CA_PRIVATE_KEY`. Apply it with `docker compose up -d api` (a plain restart doesn't
     re-read `.env`), then read the CA public key from `GET /v1/peer-auth/ca`.
   - **Build the client against it.** Set `RUSTDESK_MANAGED_PEER_CA_PUBKEY` to that public key in
     the build environment. Approved Clients then fetch and renew their own certificates.
   - **Roll out in log mode.** Leave the mode at **log** (the default) on the Config page →
     Remote Connections. Watch the readiness count there, and switch to **enforce** once every
     active Client runs a build that presents certificates.
   - **Guard the key.** It lives only in `.env`. The bundled backup script archives
     `config/secrets.env`, not `.env`, so back the key up separately. Rotating it means rebuilding
     the client with the new public key, and in enforce mode logins fail until every Client runs
     the rebuilt client.
9. Sealed transport, optional but recommended: generate an X25519 key pair, set the private half as
   `SEALED_X25519_PRIVATE_KEY` in `.env`, and build the client with `RUSTDESK_MANAGED_SEAL_PUBKEY`
   set to the public half. When rotating, move the old private key to
   `SEALED_X25519_PREVIOUS_PRIVATE_KEY` so Clients built before the rotation keep working. Like the
   CA key, back it up separately. Clients from build 31 never fall back to unsealed calls, so a
   broken sealing setup cuts them off from RDS (update checks included) until the key they were
   built with is configured again.
10. Edge client certificates, optional: set `CF_EDGE_CERT_TOKEN` (a Cloudflare API token that can
    manage client certificates) and `CF_ZONE_ID`. Enforce the certificate at the edge only once
    every Client has one.
11. Rendezvous encryption and WebRTC need the relay build from
    [rustdesk-managed-relay](https://github.com/MAGA-Brad/rustdesk-managed-relay). Install the
    approved-ID/settings sync units, then choose the modes on the Config page → Remote
    Connections. Set encryption to **optional** before rolling out managed clients built from this
    tree (they can't connect while it's off; RDS won't let you switch it off while any approved
    Client reports build 30 or newer), and
    switch to **required** only once the counts there show no unencrypted connections. Leave WebRTC at **test devices only** until every Client
    is built with your own STUN server (`RUSTDESK_MANAGED_ICE_SERVERS`).
12. Device passports, optional:
    - **Stand up the CA VM.** Build `ca/signer`, create its root key with `ca-signer gen-root` and
      keep it as an encrypted systemd credential, issue the signer a client certificate from your
      link CA, and point its config at `https://<CA_LINK_BIND>:9443`. Start the `ca-link`
      service here with the link CA and server certificate in `config/ca-link/`.
    - **Build against it.** `ca-signer root-pubkey` reads the root seed on stdin and prints the
      root public key: build clients with `RUSTDESK_MANAGED_PASSPORT_ROOTS` set to it and start
      hbbs with `PASSPORT_ROOTS` set to it (in hbbs's own environment, not from RDS).
    - **Roll out.** Set issuing to **log** on the Config page, then press **Queue passports for
      approved devices without one** in the CA panel (Clients approved earlier aren't on the CA's
      file until then). Windows Clients from build 34 and RDC for Android move to their own identity
      key and fetch passports. Then set hbbs's passport check to **log**, watch its counts, try **test** with a
      few test devices, and switch to **enforce** once every active Client runs build 34 or newer
      (RDS refuses it before that).
