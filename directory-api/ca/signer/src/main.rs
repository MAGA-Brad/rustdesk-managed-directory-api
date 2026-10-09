//! ca-signer: the CA VM's passport signer.
//!
//! * Pulls jobs from RDS over mutual TLS (RDS never connects to the CA VM).
//! * Applies its own rules: renewals and key updates must be signed by the key on file, revocations are
//!   always honoured, new keys mail the owner, lifetimes are capped, issuance is rate limited.
//! * Root key: an encrypted systemd credential (host+tpm2), read only to certify a new issuing key.
//! * Issuing key: generated in memory at start and every `issuing_key_days`, never written to disk.
//! * Keeps its own device table and an append-only, hash-chained issuance log in the state directory.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD as B64STD, Engine as _};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use rdc_passport as pp;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroize;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REQUEST_MAX_AGE: i64 = 600;
const NONCE_KEEP: i64 = 1800;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn log(level: &str, message: &str) {
    eprintln!("{level} {message}");
}

// ---------------------------------------------------------------- config & credentials

#[derive(Deserialize, Clone)]
struct Config {
    rds_url: String,
    link_ca: String,
    link_client_cert: String,
    state_dir: String,
    mail_from: String,
    mail_to: String,
    smtp_host: String,
    smtp_ip: String,
    smtp_port: u16,
    #[serde(default = "default_max_lifetime_days")]
    max_lifetime_days: i64,
    #[serde(default = "default_issuing_key_days")]
    issuing_key_days: i64,
    #[serde(default = "default_rate")]
    max_issues_per_device_hour: usize,
    #[serde(default = "default_digest_hour")]
    digest_hour_utc: i64,
}

fn default_max_lifetime_days() -> i64 {
    7
}
fn default_issuing_key_days() -> i64 {
    30
}
fn default_rate() -> usize {
    10
}
fn default_digest_hour() -> i64 {
    12
}

fn credential_path(name: &str) -> Result<PathBuf, String> {
    let dir = std::env::var("CREDENTIALS_DIRECTORY").map_err(|_| "CREDENTIALS_DIRECTORY not set".to_string())?;
    Ok(Path::new(&dir).join(name))
}

fn read_root() -> Result<SigningKey, String> {
    let mut text = fs::read_to_string(credential_path("root")?).map_err(|e| format!("root credential: {e}"))?;
    let decoded = B64STD.decode(text.trim()).map_err(|_| "root credential is not base64".to_string());
    text.zeroize();
    let mut raw = decoded?;
    let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| "root seed must be 32 bytes".to_string())?;
    raw.zeroize();
    Ok(SigningKey::from_bytes(&seed))
}

// ---------------------------------------------------------------- state & log

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Device {
    rid: String,
    did: String,
    #[serde(default)]
    name: String,
    idk: String,
    idk_alg: String,
    rdk: String,
    prot: String,
    status: String,
    approved_by: String,
    approved_source: String,
    first_seen: i64,
    #[serde(default)]
    last_issued: i64,
    #[serde(default)]
    recent_issues: Vec<i64>,
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    devices: BTreeMap<String, Device>,
    #[serde(default)]
    nonces: Vec<(String, String, i64)>,
}

impl State {
    fn load(path: &Path) -> Result<State, String> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("state file: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(format!("state file: {e}")),
        }
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let mut file = fs::File::create(&tmp).map_err(|e| format!("state write: {e}"))?;
        file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|e| format!("state write: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("state rename: {e}"))
    }

    fn nonce_seen(&mut self, did: &str, nonce: &str, at: i64) -> bool {
        self.nonces.retain(|(_, _, t)| at - *t < NONCE_KEEP);
        if self.nonces.iter().any(|(d, n, _)| d == did && n == nonce) {
            return true;
        }
        self.nonces.push((did.to_string(), nonce.to_string(), at));
        false
    }
}

struct IssuanceLog {
    path: PathBuf,
    seq: u64,
    head: String,
}

fn entry_hash(prev: &str, line_without_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(b"\n");
    hasher.update(line_without_hash.as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl IssuanceLog {
    /// Opens the log and re-checks the whole chain; a broken chain stops the signer.
    fn open(path: PathBuf) -> Result<IssuanceLog, String> {
        let mut seq = 0;
        let mut head = "genesis".to_string();
        if let Ok(text) = fs::read_to_string(&path) {
            for (n, line) in text.lines().enumerate() {
                let mut value: Value = serde_json::from_str(line).map_err(|_| format!("log line {} unreadable", n + 1))?;
                let stated = value.get("hash").and_then(Value::as_str).unwrap_or_default().to_string();
                if value.get("prev").and_then(Value::as_str) != Some(head.as_str()) {
                    return Err(format!("log chain broken at line {} (prev)", n + 1));
                }
                value.as_object_mut().map(|o| o.remove("hash"));
                let expected = entry_hash(&head, &serde_json::to_string(&value).map_err(|e| e.to_string())?);
                if expected != stated {
                    return Err(format!("log chain broken at line {} (hash)", n + 1));
                }
                head = stated;
                seq = value.get("seq").and_then(Value::as_u64).unwrap_or(0);
            }
        }
        Ok(IssuanceLog { path, seq, head })
    }

    fn append(&mut self, mut entry: Value) -> Result<(), String> {
        let object = entry.as_object_mut().ok_or("log entry must be an object")?;
        object.insert("seq".into(), json!(self.seq + 1));
        object.insert("ts".into(), json!(now()));
        object.insert("prev".into(), json!(self.head));
        let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        let hash = entry_hash(&self.head, &line);
        entry.as_object_mut().map(|o| o.insert("hash".into(), json!(hash)));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("log open: {e}"))?;
        writeln!(file, "{}", serde_json::to_string(&entry).map_err(|e| e.to_string())?)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("log write: {e}"))?;
        self.seq += 1;
        self.head = hash;
        Ok(())
    }
}

// ---------------------------------------------------------------- keys

struct Keys {
    issuing: SigningKey,
    ikc: String,
    kid: String,
    created: i64,
    exp: i64,
}

impl Keys {
    fn new(lifetime_days: i64) -> Result<Keys, String> {
        let root = read_root()?;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let issuing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let created = now();
        let exp = created + (lifetime_days + 5) * 86_400;
        let ikc = pp::sign_ikc(&root, &issuing.verifying_key(), created - 300, exp);
        drop(root);
        let kid = pp::kid_for(&issuing.verifying_key());
        Ok(Keys { issuing, ikc, kid, created, exp })
    }
}

// ---------------------------------------------------------------- jobs

#[derive(Deserialize)]
struct JobsResponse {
    jobs: Vec<Job>,
}

#[derive(Deserialize)]
struct Job {
    id: i64,
    kind: String,
    payload: Value,
}

#[derive(Serialize, Default)]
struct JobResult {
    id: i64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prot: Option<String>,
}

#[derive(Deserialize)]
struct DeviceIn {
    rid: String,
    did: String,
    #[serde(default)]
    name: String,
    idk: String,
    idk_alg: String,
    rdk: String,
    prot: String,
}

#[derive(Deserialize, Default)]
struct Approver {
    #[serde(default)]
    name: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    source: String,
}

#[derive(Deserialize)]
struct IssueJob {
    device: DeviceIn,
    #[serde(default)]
    approver: Approver,
    lifetime_days: i64,
    reason: String,
}

#[derive(Deserialize)]
struct SignedJob {
    rid: String,
    did: String,
    request: String,
    lifetime_days: i64,
}

#[derive(Deserialize)]
struct RevokeJob {
    rid: String,
    did: String,
    reason: String,
}

#[derive(Default, Clone, Serialize)]
struct Counters {
    issued: u64,
    renewed: u64,
    key_updates: u64,
    revoked: u64,
    refused: u64,
    new_devices: u64,
}

struct Signer {
    cfg: Config,
    state: State,
    state_path: PathBuf,
    log: IssuanceLog,
    keys: Keys,
    counters_24h: Vec<(i64, &'static str)>,
    mails: Vec<(String, String)>,
}

fn valid_rid(rid: &str) -> bool {
    !rid.is_empty() && rid.len() <= 32 && rid.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn valid_did(did: &str) -> bool {
    did.len() == 36 && did.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl Signer {
    fn count(&mut self, what: &'static str) {
        let t = now();
        self.counters_24h.retain(|(at, _)| t - at < 86_400);
        self.counters_24h.push((t, what));
    }

    fn counters(&self) -> Counters {
        let t = now();
        let mut c = Counters::default();
        for (at, what) in &self.counters_24h {
            if t - at >= 86_400 {
                continue;
            }
            match *what {
                "issued" => c.issued += 1,
                "renewed" => c.renewed += 1,
                "key_update" => c.key_updates += 1,
                "revoked" => c.revoked += 1,
                "refused" => c.refused += 1,
                "new_device" => c.new_devices += 1,
                _ => {}
            }
        }
        c
    }

    fn mail(&mut self, subject: String, body: String) {
        self.mails.push((subject, body));
    }

    fn rotate_if_needed(&mut self) -> Result<(), String> {
        if now() - self.keys.created >= self.cfg.issuing_key_days * 86_400 {
            let old = self.keys.kid.clone();
            self.keys = Keys::new(self.cfg.issuing_key_days)?;
            self.log.append(json!({"kind": "issuing_key", "kid": self.keys.kid, "replaces": old, "exp": self.keys.exp}))?;
            log("INFO", &format!("issuing key rotated: {old} -> {}", self.keys.kid));
        }
        Ok(())
    }

    fn rate_ok(&mut self, did: &str) -> bool {
        let t = now();
        let max = self.cfg.max_issues_per_device_hour;
        match self.state.devices.get_mut(did) {
            Some(d) => {
                d.recent_issues.retain(|at| t - at < 3600);
                d.recent_issues.len() < max
            }
            None => true,
        }
    }

    /// Signs a passport for a device record that has already passed policy.
    fn issue_for(&mut self, did: &str, lifetime_days: i64, kind: &str, approver: &str) -> Result<JobResult, String> {
        let days = lifetime_days.clamp(1, self.cfg.max_lifetime_days);
        if days != lifetime_days {
            log("WARN", &format!("lifetime {lifetime_days} d for {did} clamped to {days} d"));
        }
        let t = now();
        let device = self.state.devices.get(did).cloned().ok_or("device vanished")?;
        let body = pp::PassportBody {
            typ: "rdc-passport".into(),
            v: pp::VERSION,
            serial: random_hex(16),
            rid: device.rid.clone(),
            did: device.did.clone(),
            idk: device.idk.clone(),
            idk_alg: device.idk_alg.clone(),
            rdk: device.rdk.clone(),
            prot: device.prot.clone(),
            scopes: pp::SCOPES.iter().map(|s| s.to_string()).collect(),
            iat: t,
            nbf: t - 300,
            exp: t + days * 86_400,
            ikid: self.keys.kid.clone(),
        };
        let token = pp::sign_passport(&self.keys.issuing, &self.keys.ikc, &body);
        self.log.append(json!({
            "kind": kind, "rid": body.rid, "did": body.did, "serial": body.serial, "exp": body.exp,
            "idk_fp": pp::fingerprint(&pp::unb64(&body.idk).unwrap_or_default()), "prot": body.prot,
            "ikid": body.ikid, "approver": approver,
        }))?;
        if let Some(d) = self.state.devices.get_mut(did) {
            d.last_issued = t;
            d.recent_issues.push(t);
        }
        self.state.save(&self.state_path)?;
        self.count("issued");
        Ok(JobResult {
            ok: true,
            passport: Some(token),
            serial: Some(body.serial),
            nbf: Some(body.nbf),
            exp: Some(body.exp),
            idk: Some(body.idk),
            prot: Some(body.prot),
            ..Default::default()
        })
    }

    fn handle_issue(&mut self, job: IssueJob) -> Result<JobResult, String> {
        let d = &job.device;
        if !valid_rid(&d.rid) || !valid_did(&d.did) {
            return Err("invalid rid/did".into());
        }
        if d.idk_alg != "ed25519" || !["legacy", "dpapi", "keystore", "tpm"].contains(&d.prot.as_str()) {
            return Err("unsupported key algorithm or protection".into());
        }
        pp::parse_public_key(&d.idk).map_err(|e| format!("idk: {e}"))?;
        pp::parse_public_key(&d.rdk).map_err(|e| format!("rdk: {e}"))?;
        if !["approve", "unblock", "bootstrap", "reissue"].contains(&job.reason.as_str()) {
            return Err(format!("unknown issue reason '{}'", job.reason));
        }
        let name: String = d.name.chars().take(80).collect();
        let approver = format!(
            "{} ({}, {})",
            if job.approver.name.is_empty() { "unknown" } else { job.approver.name.as_str() },
            job.approver.role,
            job.approver.source
        );
        let existing = self.state.devices.get(&d.did).cloned();
        if let Some(e) = &existing {
            if e.rid != d.rid {
                self.mail(
                    format!("[RDC CA] REFUSED: id mismatch for {}", d.did),
                    format!("RDS asked for a passport for device {} as RustDesk id {}, but the CA has it as {}.\nNothing was issued.", d.did, d.rid, e.rid),
                );
                return Err("rid does not match the device on file".into());
            }
        }
        let key_new = existing.as_ref().map(|e| e.idk != d.idk).unwrap_or(true);
        let was_revoked = existing.as_ref().map(|e| e.status == "revoked").unwrap_or(false);
        // A new key for a known device needs a fresh approval; renewals and moves go through signed jobs.
        if existing.is_some() && key_new && job.reason != "approve" {
            return Err("key differs from the one on file and this is not a new approval".into());
        }
        if was_revoked && job.reason == "reissue" {
            return Err("device is revoked; it needs a new approval".into());
        }
        if !self.rate_ok(&d.did) {
            return Err("rate limit".into());
        }
        let t = now();
        let record = Device {
            rid: d.rid.clone(),
            did: d.did.clone(),
            name: name.clone(),
            idk: d.idk.clone(),
            idk_alg: d.idk_alg.clone(),
            rdk: d.rdk.clone(),
            prot: d.prot.clone(),
            status: "approved".into(),
            approved_by: if key_new || was_revoked { approver.clone() } else { existing.as_ref().map(|e| e.approved_by.clone()).unwrap_or_default() },
            approved_source: job.approver.source.clone(),
            first_seen: existing.as_ref().map(|e| e.first_seen).unwrap_or(t),
            last_issued: existing.as_ref().map(|e| e.last_issued).unwrap_or(0),
            recent_issues: existing.as_ref().map(|e| e.recent_issues.clone()).unwrap_or_default(),
        };
        self.state.devices.insert(d.did.clone(), record);
        let result = self.issue_for(&d.did, job.lifetime_days, &format!("issue:{}", job.reason), &approver)?;
        if key_new || was_revoked {
            self.count("new_device");
            let what = if existing.is_none() { "New device approved" } else if was_revoked { "Device re-approved" } else { "Device approved with a NEW key" };
            self.mail(
                format!("[RDC CA] {what}: {} ({})", if name.is_empty() { "unnamed" } else { name.as_str() }, d.rid),
                format!(
                    "{what}.\n\nDevice: {}\nRustDesk id: {}\nRDS device id: {}\nApproved by: {}\nKey fingerprint: {}\nKey protection: {}\nPassport serial: {}\n\nIf you did not expect this, revoke the device in RDS now.",
                    if name.is_empty() { "unnamed" } else { name.as_str() },
                    d.rid, d.did, approver,
                    pp::fingerprint(&pp::unb64(&d.idk).unwrap_or_default()),
                    d.prot,
                    result.serial.clone().unwrap_or_default()
                ),
            );
        }
        Ok(result)
    }

    fn known_approved(&self, rid: &str, did: &str) -> Result<Device, String> {
        let d = self.state.devices.get(did).cloned().ok_or("device not on file")?;
        if d.rid != rid {
            return Err("rid does not match the device on file".into());
        }
        if d.status != "approved" {
            return Err("device is not approved".into());
        }
        Ok(d)
    }

    fn handle_renew(&mut self, job: SignedJob) -> Result<JobResult, String> {
        let device = self.known_approved(&job.rid, &job.did)?;
        let idk = pp::parse_public_key(&device.idk).map_err(|e| e.to_string())?;
        let body = pp::verify_renew(&job.request, &idk, now(), REQUEST_MAX_AGE).map_err(|e| format!("renewal: {e}"))?;
        if body.rid != job.rid || body.did != job.did {
            return Err("renewal names a different device".into());
        }
        if self.state.nonce_seen(&job.did, &body.nonce, now()) {
            return Err("renewal replayed".into());
        }
        if !self.rate_ok(&job.did) {
            return Err("rate limit".into());
        }
        let result = self.issue_for(&job.did, job.lifetime_days, "renew", "device signature")?;
        self.count("renewed");
        Ok(result)
    }

    fn handle_key_update(&mut self, job: SignedJob) -> Result<JobResult, String> {
        let device = self.known_approved(&job.rid, &job.did)?;
        let old = pp::parse_public_key(&device.idk).map_err(|e| e.to_string())?;
        let (body, new_key) =
            pp::verify_key_update(&job.request, &old, now(), REQUEST_MAX_AGE).map_err(|e| format!("key update: {e}"))?;
        if body.rid != job.rid || body.did != job.did {
            return Err("key update names a different device".into());
        }
        if !["dpapi", "keystore", "tpm"].contains(&body.prot.as_str()) {
            return Err("unsupported key protection".into());
        }
        if self.state.nonce_seen(&job.did, &body.nonce, now()) {
            return Err("key update replayed".into());
        }
        let old_prot = device.prot.clone();
        if let Some(d) = self.state.devices.get_mut(&job.did) {
            d.idk = pp::b64(new_key.as_bytes());
            d.prot = body.prot.clone();
        }
        let result = self.issue_for(&job.did, job.lifetime_days, "key_update", "device signatures (old + new key)")?;
        self.count("key_update");
        if old_prot != "legacy" {
            self.mail(
                format!("[RDC CA] Device changed its identity key: {} ({})", device.name, device.rid),
                format!(
                    "Device {} ({}) moved from a {old_prot} key to a new {} key, signed by both keys.\nNew key fingerprint: {}\nIf this was not a reinstall or upgrade you expected, revoke it in RDS.",
                    device.name, device.rid, body.prot, pp::fingerprint(new_key.as_bytes())
                ),
            );
        }
        Ok(result)
    }

    fn handle_revoke(&mut self, job: RevokeJob) -> Result<JobResult, String> {
        if let Some(d) = self.state.devices.get_mut(&job.did) {
            if d.rid != job.rid {
                return Err("rid does not match the device on file".into());
            }
            d.status = "revoked".into();
        }
        self.log.append(json!({"kind": "revoke", "rid": job.rid, "did": job.did, "reason": job.reason}))?;
        self.state.save(&self.state_path)?;
        self.count("revoked");
        Ok(JobResult { ok: true, ..Default::default() })
    }

    fn process(&mut self, job: Job) -> JobResult {
        let id = job.id;
        let outcome = match job.kind.as_str() {
            "issue" => serde_json::from_value(job.payload).map_err(|e| format!("issue job: {e}")).and_then(|j| self.handle_issue(j)),
            "renew" => serde_json::from_value(job.payload).map_err(|e| format!("renew job: {e}")).and_then(|j| self.handle_renew(j)),
            "keyupdate" => serde_json::from_value(job.payload).map_err(|e| format!("keyupdate job: {e}")).and_then(|j| self.handle_key_update(j)),
            "revoke" => serde_json::from_value(job.payload).map_err(|e| format!("revoke job: {e}")).and_then(|j| self.handle_revoke(j)),
            other => Err(format!("unknown job kind '{other}'")),
        };
        match outcome {
            Ok(mut result) => {
                result.id = id;
                result
            }
            Err(error) => {
                self.count("refused");
                let _ = self.log.append(json!({"kind": "refused", "job": id, "job_kind": job.kind, "error": error}));
                log("WARN", &format!("job {id} ({}) refused: {error}", job.kind));
                JobResult { id, ok: false, error: Some(error), ..Default::default() }
            }
        }
    }
}

// ---------------------------------------------------------------- mail (curl, SMTP submission)

async fn send_mail(cfg: &Config, subject: &str, body: &str) {
    let cred = match credential_path("smtp") {
        Ok(path) if fs::read_to_string(&path).map(|t| t.contains("user")).unwrap_or(false) => path,
        _ => {
            log("INFO", &format!("mail not sent (SMTP not configured): {subject}"));
            return;
        }
    };
    let message = format!(
        "From: RDC CA <{from}>\r\nTo: <{to}>\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n",
        from = cfg.mail_from,
        to = cfg.mail_to,
        body = body.replace('\n', "\r\n"),
    );
    let child = tokio::process::Command::new("curl")
        .args([
            "--silent", "--show-error", "--max-time", "30", "--ssl-reqd",
            "--url", &format!("smtp://{}:{}", cfg.smtp_host, cfg.smtp_port),
            "--resolve", &format!("{}:{}:{}", cfg.smtp_host, cfg.smtp_port, cfg.smtp_ip),
            "--mail-from", &cfg.mail_from, "--mail-rcpt", &cfg.mail_to, "--upload-file", "-",
        ])
        .arg("-K")
        .arg(&cred)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            log("ERROR", &format!("mail: curl failed to start: {e}"));
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(message.as_bytes()).await;
    }
    match child.wait_with_output().await {
        Ok(out) if out.status.success() => log("INFO", &format!("mail sent: {subject}")),
        Ok(out) => log("ERROR", &format!("mail failed: {} {}", out.status, String::from_utf8_lossy(&out.stderr).trim())),
        Err(e) => log("ERROR", &format!("mail failed: {e}")),
    }
}

// ---------------------------------------------------------------- link to RDS

fn http_client(cfg: &Config) -> Result<reqwest::Client, String> {
    let ca = fs::read(&cfg.link_ca).map_err(|e| format!("link CA: {e}"))?;
    let mut identity = fs::read(&cfg.link_client_cert).map_err(|e| format!("client cert: {e}"))?;
    let mut key = fs::read(credential_path("link-key")?).map_err(|e| format!("link-key credential: {e}"))?;
    identity.extend_from_slice(b"\n");
    identity.extend_from_slice(&key);
    key.zeroize();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(|e| format!("link CA: {e}"))?)
        .identity(reqwest::Identity::from_pem(&identity).map_err(|e| format!("client identity: {e}"))?)
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string());
    identity.zeroize();
    client
}

#[derive(Default, Clone, Serialize)]
struct Health {
    version: String,
    started_at: i64,
    issuing_kid: String,
    issuing_created: i64,
    issuing_exp: i64,
    devices_known: usize,
    devices_approved: usize,
    counters_24h: Counters,
    log_seq: u64,
    log_head: String,
    last_job_at: i64,
    rds_ok_at: i64,
    apt_upgradable: i64,
    apt_security: i64,
    reboot_required: bool,
    smtp_configured: bool,
    clock_unix: i64,
}

fn apt_status() -> (i64, i64) {
    let out = std::process::Command::new("apt").args(["list", "--upgradable"]).env("LANG", "C").output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let lines: Vec<&str> = text.lines().filter(|l| l.contains("upgradable from")).collect();
            (lines.len() as i64, lines.iter().filter(|l| l.contains("-security")).count() as i64)
        }
        Err(_) => (-1, -1),
    }
}

async fn run(config_path: &str) -> Result<(), String> {
    let cfg: Config = serde_json::from_slice(&fs::read(config_path).map_err(|e| format!("config: {e}"))?)
        .map_err(|e| format!("config: {e}"))?;
    let state_dir = PathBuf::from(&cfg.state_dir);
    let state_path = state_dir.join("devices.json");
    let issuance = IssuanceLog::open(state_dir.join("issuance.log"))?;
    let state = State::load(&state_path)?;
    let keys = Keys::new(cfg.issuing_key_days)?;
    log("INFO", &format!(
        "ca-signer {VERSION} started: issuing key {} (expires {}), {} devices on file, log seq {}",
        keys.kid, keys.exp, state.devices.len(), issuance.seq
    ));
    let client = http_client(&cfg)?;
    let mut signer = Signer { cfg: cfg.clone(), state, state_path, log: issuance, keys, counters_24h: Vec::new(), mails: Vec::new() };
    signer.log.append(json!({"kind": "start", "version": VERSION, "issuing_kid": signer.keys.kid, "issuing_exp": signer.keys.exp}))?;

    let health = Arc::new(Mutex::new(Health { version: VERSION.into(), started_at: now(), ..Default::default() }));
    {
        let health = health.clone();
        let client = client.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move { heartbeat_loop(cfg, client, health).await });
    }

    let mut rds_down_since: Option<i64> = None;
    let mut rds_alerted = false;
    loop {
        if let Err(e) = signer.rotate_if_needed() {
            log("ERROR", &format!("issuing key rotation failed: {e}"));
        }
        let url = format!("{}/ca/v1/jobs?wait=25", cfg.rds_url);
        let polled = async {
            let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("HTTP {}", response.status()));
            }
            response.json::<JobsResponse>().await.map_err(|e| e.to_string())
        }
        .await;
        match polled {
            Ok(batch) => {
                if rds_alerted {
                    signer.mail("[RDC CA] RDS reachable again".into(), "The CA VM is receiving jobs from RDS again.".into());
                }
                rds_down_since = None;
                rds_alerted = false;
                if !batch.jobs.is_empty() {
                    let results: Vec<JobResult> = batch.jobs.into_iter().map(|job| signer.process(job)).collect();
                    let posted = client
                        .post(format!("{}/ca/v1/results", cfg.rds_url))
                        .json(&json!({ "results": results }))
                        .send()
                        .await;
                    if let Err(e) = posted.and_then(|r| r.error_for_status()) {
                        log("ERROR", &format!("posting results failed (RDS will re-send unanswered jobs): {e}"));
                    }
                    health.lock().unwrap().last_job_at = now();
                }
                health.lock().unwrap().rds_ok_at = now();
            }
            Err(e) => {
                let since = *rds_down_since.get_or_insert(now());
                log("WARN", &format!("job poll failed: {e}"));
                if !rds_alerted && now() - since > 600 {
                    rds_alerted = true;
                    signer.mail("[RDC CA] RDS unreachable for 10 minutes".into(),
                        format!("The CA VM has not been able to reach RDS's job listener since {} (unix). Last error: {e}\nPassports keep working until they expire; renewals and new approvals wait.", since));
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
        {
            let mut h = health.lock().unwrap();
            h.issuing_kid = signer.keys.kid.clone();
            h.issuing_created = signer.keys.created;
            h.issuing_exp = signer.keys.exp;
            h.devices_known = signer.state.devices.len();
            h.devices_approved = signer.state.devices.values().filter(|d| d.status == "approved").count();
            h.counters_24h = signer.counters();
            h.log_seq = signer.log.seq;
            h.log_head = signer.log.head.clone();
        }
        for (subject, body) in std::mem::take(&mut signer.mails) {
            send_mail(&cfg, &subject, &body).await;
        }
    }
}

async fn heartbeat_loop(cfg: Config, client: reqwest::Client, health: Arc<Mutex<Health>>) {
    let mut last_apt = 0i64;
    let mut last_digest_day = -1i64;
    loop {
        let t = now();
        if t - last_apt > 3600 {
            let (upgradable, security) = tokio::task::spawn_blocking(apt_status).await.unwrap_or((-1, -1));
            let mut h = health.lock().unwrap();
            h.apt_upgradable = upgradable;
            h.apt_security = security;
            last_apt = t;
        }
        let snapshot = {
            let mut h = health.lock().unwrap();
            h.reboot_required = Path::new("/run/reboot-required").exists();
            h.smtp_configured = credential_path("smtp")
                .ok()
                .and_then(|p| fs::read_to_string(p).ok())
                .map(|t| t.contains("user"))
                .unwrap_or(false);
            h.clock_unix = t;
            h.clone()
        };
        let sent = client
            .post(format!("{}/ca/v1/heartbeat", cfg.rds_url))
            .json(&json!({ "status": snapshot }))
            .send()
            .await;
        if let Err(e) = sent.and_then(|r| r.error_for_status()) {
            log("WARN", &format!("heartbeat failed: {e}"));
        }
        let day = t / 86_400;
        if (t % 86_400) / 3600 == cfg.digest_hour_utc && day != last_digest_day {
            last_digest_day = day;
            let c = &snapshot.counters_24h;
            let body = format!(
                "Daily CA digest (last 24 h)\n\nPassports issued: {}\n  renewals: {}\n  key updates: {}\n  new/re-approved devices: {}\nRevocations: {}\nRefused jobs: {}\n\nDevices on file: {} ({} approved)\nIssuing key: {} (expires {})\nIssuance log: seq {} head {}\nUpdates pending: {} ({} security), reboot required: {}\n",
                c.issued, c.renewed, c.key_updates, c.new_devices, c.revoked, c.refused,
                snapshot.devices_known, snapshot.devices_approved,
                snapshot.issuing_kid, snapshot.issuing_exp, snapshot.log_seq, snapshot.log_head,
                snapshot.apt_upgradable, snapshot.apt_security, snapshot.reboot_required
            );
            send_mail(&cfg, "[RDC CA] Daily digest", &body).await;
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

// ---------------------------------------------------------------- commands

fn gen_root() -> Result<(), String> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    print!("{}", B64STD.encode(seed));
    seed.zeroize();
    Ok(())
}

fn root_pubkey() -> Result<(), String> {
    let mut text = String::new();
    std::io::stdin().read_line(&mut text).map_err(|e| e.to_string())?;
    let mut raw = B64STD.decode(text.trim()).map_err(|_| "not base64".to_string())?;
    text.zeroize();
    let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| "seed must be 32 bytes".to_string())?;
    raw.zeroize();
    let key = SigningKey::from_bytes(&seed).verifying_key();
    println!("root public key: {}", pp::b64(key.as_bytes()));
    println!("fingerprint:     {}", pp::fingerprint(key.as_bytes()));
    Ok(())
}

fn import(config_path: &str, file: &str) -> Result<(), String> {
    let cfg: Config = serde_json::from_slice(&fs::read(config_path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let state_dir = PathBuf::from(&cfg.state_dir);
    let state_path = state_dir.join("devices.json");
    let mut state = State::load(&state_path)?;
    let mut log = IssuanceLog::open(state_dir.join("issuance.log"))?;
    let list: Vec<DeviceIn> = serde_json::from_slice(&fs::read(file).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let (mut added, mut skipped) = (0, 0);
    for d in list {
        if !valid_rid(&d.rid) || !valid_did(&d.did) || pp::parse_public_key(&d.idk).is_err() || pp::parse_public_key(&d.rdk).is_err() {
            eprintln!("skip (invalid): {} {}", d.rid, d.did);
            skipped += 1;
            continue;
        }
        if state.devices.contains_key(&d.did) {
            skipped += 1;
            continue;
        }
        log.append(json!({"kind": "import", "rid": d.rid, "did": d.did, "idk_fp": pp::fingerprint(&pp::unb64(&d.idk).unwrap_or_default()), "prot": d.prot}))?;
        state.devices.insert(d.did.clone(), Device {
            rid: d.rid, did: d.did, name: d.name, idk: d.idk, idk_alg: d.idk_alg, rdk: d.rdk, prot: d.prot,
            status: "approved".into(), approved_by: "bootstrap import (list reviewed by Brad)".into(),
            approved_source: "bootstrap".into(), first_seen: now(), last_issued: 0, recent_issues: Vec::new(),
        });
        added += 1;
    }
    state.save(&state_path)?;
    println!("imported {added}, skipped {skipped}; devices on file: {}", state.devices.len());
    Ok(())
}

fn verify_log(config_path: &str) -> Result<(), String> {
    let cfg: Config = serde_json::from_slice(&fs::read(config_path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let log = IssuanceLog::open(PathBuf::from(&cfg.state_dir).join("issuance.log"))?;
    println!("issuance log OK: seq {} head {}", log.seq, log.head);
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| "/etc/ca-signer/config.json".into());
    let result = match args.get(1).map(String::as_str) {
        Some("run") => run(&config).await,
        Some("gen-root") => gen_root(),
        Some("root-pubkey") => root_pubkey(),
        Some("import") => match args.get(2) {
            Some(file) if file != "--config" => import(&config, file),
            _ => Err("usage: ca-signer import <devices.json> [--config path]".into()),
        },
        Some("verify-log") => verify_log(&config),
        Some("version") => {
            println!("ca-signer {VERSION}");
            Ok(())
        }
        _ => Err("usage: ca-signer run|gen-root|root-pubkey|import <file>|verify-log|version [--config path]".into()),
    };
    if let Err(e) = result {
        log("ERROR", &e);
        std::process::exit(1);
    }
}
