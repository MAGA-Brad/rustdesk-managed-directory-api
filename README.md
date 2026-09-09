> Yes, I used Claude to act as SSoE for me. It caught quite a few things that I just missed.
>
> **Credits & attribution**
> - This repository is a fork of
>   [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) (AGPL-3.0), the official
>   self-hosted RustDesk rendezvous/relay server. Everything below this notice is unmodified upstream
>   source — full credit to the RustDesk team and its contributors.
> - In production this is actually run via the community-maintained security-hardened build published
>   at [rustdesk-org/rustdesk-server](https://github.com/rustdesk-org/rustdesk-server) rather than a
>   self-built image; credit to that project and its maintainer(s) as well.
> - This fork adds [`directory-api/`](directory-api/) — a self-hosted device directory, operator
>   enrollment/2FA, audit logging, relay-access leasing, and admin management API that sits in front
>   of the server above. See [`directory-api/README.md`](directory-api/README.md) for setup/layout
>   details.

## What `directory-api/` adds ("RDS")

RDS is the management layer this fork adds in front of a stock hbbs/hbbr — it doesn't touch the
relay/rendezvous protocol at all, it just makes running a *fleet* of RustDesk clients practical
instead of a pile of individually-configured machines. It pairs with
[rustdesk-managed-client](https://github.com/MAGA-Brad/rustdesk-managed-client) ("RDC"), a fork of
the RustDesk client built to talk to it.

### Fleet enrollment and lifecycle
- **Self-service, password-gated enrollment** — a device authenticates with a shared enrollment
  secret and registers itself; nothing reaches the relay until an operator approves it.
- **Full device lifecycle**: pending → approved, with denied/blocked/revoked as explicit terminal
  states, each change attributed to an operator and logged.
- **Owner-authorized re-enrollment recovery** — a device that loses or regenerates its local
  credential isn't orphaned; an owner-role operator can authorize it to re-enroll under its
  original identity, with the prior credential invalidated the instant the new one lands.
- **Friendly-name reservation** — human-readable device names are reserved while a device is
  pending/approved/blocked and automatically released when denied/revoked, so names don't get
  permanently squatted by dead entries.

### Operator accounts, not shared passwords
- Operator accounts with roles — sensitive actions (like authorizing a re-enrollment) require the
  **owner** role specifically, not just "logged in."
- **Mandatory 2FA** on the admin/management surface.
- **Full audit logging**: every enrollment event, status change, and admin action is recorded with
  the acting operator and source IP — a real audit trail, not just current-state.

### Relay access is leased, not just allowed
- Devices get **short-lived, per-device relay-access leases** rather than a static IP allowlist — a
  **Relay Guard** daemon syncs a dynamic firewall allowlist off active leases, so relay ports are
  only ever open to devices with a currently-valid, currently-approved lease.

### Signed updates for the managed client
- RDS is also the **signing authority** for RDC's auto-update feature — release manifests are
  Ed25519-signed here before publishing, so the client only ever trusts an update it can verify
  came from this server's private key, not just "whatever file is at this URL."

### Ops automation included
- `deploy/sbin/` + `deploy/systemd/` ship real operational scripts, not just app code: automated
  backups with verification, the relay-firewall-guard sync daemon, a health collector, the signed
  update-bundle publisher, and an owner emergency-recovery script — plus a reference Caddy config
  splitting the public rendezvous domain, the admin/ops domain, and the managed-client API domain
  into three separately-scoped vhosts.

### Server health monitoring, not just uptime
- A live **Server Health** dashboard panel covering core services (API/DB/relay), host vitals
  (CPU load, memory, root filesystem, uptime, pending OS updates), storage (ZFS pool health,
  per-drive SSD wear %, SMART pass/fail, RAID controller and physical-drive status), and hardware
  sensors (CPU temperature, fan and power-supply redundancy, BMC event log, UPS/NUT status) — down
  to being able to watch two independent UPS units separately and choose which one actually drives
  a shutdown decision versus which is just monitored for visibility.
- A **debounced alert pipeline**: every condition above only notifies on a genuine state change,
  not on every poll — so a flapping sensor doesn't turn into an alert flood, but a real failure
  (a downed power supply, a full BMC event log, a drive dropping out of SMART-pass) reaches an
  operator immediately by email and mobile push, with a matching "back to normal" notice when it
  clears.

### A companion mobile app, deliberately narrow in scope
- **RDC Mobile Manager** lets an operator view managed devices, approve/block/revoke them, and
  receive push notifications for new pending devices and health alerts — from a phone, with 2FA
  login carried over from the web session model. It's intentionally scoped to device
  management only: no operator-account administration (invites, resets, role changes) is reachable
  from the app, since those are account-recovery-capable actions that shouldn't be exposed from a
  device that could be lost or compromised.

### Remote debug-log requests and build tracking
- An operator can request a managed device's local debug log on demand — a single device or the
  whole fleet at once — without needing a remote session into the machine first.
- Client Management tracks each device's self-reported build number against the latest signed
  release, so an out-of-date client is visible directly in the dashboard rather than discovered
  the hard way.

### Managed 1:1 chat
- A lightweight text channel between an operator and a specific managed device, built on the same
  directory/session model as everything else here — useful for a quick "starting your remote
  session now" without needing a separate side channel.

See [`directory-api/README.md`](directory-api/README.md) for the actual layout and first-time
setup steps.

## Screenshots

| | |
|---|---|
| ![Client Management — fleet overview](screenshots/RDS_Image1.png) | ![Client detail — hardware, session history](screenshots/RDS_ClientDetail.png) |
| ![Server Health — storage, hardware sensors, dual UPS](screenshots/RDS_Image2.png) | ![Activity log — connection and presence events](screenshots/RDS_Activity.png) |
| ![Client Managers and blocked/revoked clients](screenshots/RDS_Image3.png) | ![Manager detail — access history](screenshots/RDS_ManagerDetail.png) |
| ![Outbound mail configuration](screenshots/RDS_Email.png) | |

# RustDesk Server Program

[![build](https://github.com/rustdesk/rustdesk-server/actions/workflows/build.yaml/badge.svg)](https://github.com/rustdesk/rustdesk-server/actions/workflows/build.yaml)

[**Download**](https://github.com/rustdesk/rustdesk-server/releases)

[**Manual**](https://rustdesk.com/docs/en/self-host/)

[**Configuration & environment variables**](docs/environment-variables.md)

[**FAQ**](https://github.com/rustdesk/rustdesk/wiki/FAQ)

[**How to migrate OSS to Pro**](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/installscript/#convert-from-open-source)

Self-host your own RustDesk server, it is free and open source.

> [!IMPORTANT]
> **Need more features?** [RustDesk Server Pro](https://rustdesk.com/pricing.html) might suit you better.
>
> **Want to develop your own server?** Start with [rustdesk-server-demo](https://github.com/rustdesk/rustdesk-server-demo), a simpler starting point than this repository.

## How to build manually

```bash
cargo build --release
```

Three executables will be generated in target/release.

- hbbs - RustDesk ID/Rendezvous server
- hbbr - RustDesk relay server
- rustdesk-utils - RustDesk CLI utilities

You can find updated binaries on the [Releases](https://github.com/rustdesk/rustdesk-server/releases) page.

## Configuration

`hbbs` and `hbbr` can be configured with command-line flags, environment
variables, or an `.env` / config file. Run `hbbs --help` or `hbbr --help` to see
the available flags.

The most common options:

| Option | Flag | Env var | Applies to | Purpose |
| --- | --- | --- | --- | --- |
| Key | `-k` | `KEY` | hbbs, hbbr | `hbbs` loads/generates one by default |
| Bind address | `-b` | `BIND` | hbbs, hbbr | Local IP address to listen on (default: all interfaces; requires 1.1.17+) |
| Port | `-p` | `PORT` | hbbs, hbbr | Listening port (hbbs `21116`, hbbr `21117`) |
| Relay servers | `-r` | `RELAY-SERVERS` | hbbs | Override when the relay uses a different address or a non-standard port |
| Force relay | — | `ALWAYS_USE_RELAY` | hbbs | `Y` disables direct connections |
| Log level | — | `RUST_LOG` | hbbs, hbbr | e.g. `debug` (default `info`) |

See **[docs/environment-variables.md](docs/environment-variables.md)** for the
full list of variables, the file/flag/env precedence rules, database and relay
bandwidth tuning, Docker image variables, and examples.

## Installation

Please follow this [doc](https://rustdesk.com/docs/en/self-host/rustdesk-server-oss/)
