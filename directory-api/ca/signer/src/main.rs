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
/// Jobs answered ok are remembered this long (at most ANSWERED_MAX of them), so a job RDS hands out
/// again because the result was lost on the way back gets the same answer, instead of being judged
/// again against a key the first answer already moved.
const ANSWERED_KEEP: i64 = 86_400;
const ANSWERED_MAX: usize = 20_000;
/// The longest grace hbbs and RDS give a passport past its expiry (hbbs device_auth.rs
/// MAX_GRACE_DAYS, RDS SEC8_GRACE_DAYS_MAX).
const MAX_GRACE_DAYS: i64 = 30;
/// Mail subjects are cut to this many characters.
const SUBJECT_MAX: usize = 200;
/// A device's own key update mails the owner at most once an hour; more are only counted (digest).
const KEY_MAIL_EVERY: i64 = 3600;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn log(level: &str, message: &str) {
    eprintln!("{level} {message}");
}

/// Invisible formatting characters (Unicode Cf and the line/paragraph separators) that could hide
/// or reorder text in a mail: bidi overrides, zero-width characters, soft hyphen, BOM.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
}

/// RDS- or device-supplied text without control or formatting characters (they go into mail and
/// the device table).
fn printable(text: &str) -> String {
    text.chars().filter(|&c| !c.is_control() && !is_format_char(c)).collect()
}

/// A mail Subject header: every control or formatting character becomes a space (no header can be
/// smuggled in after a CR/LF), cut to SUBJECT_MAX characters.
fn mail_subject(subject: &str) -> String {
    subject
        .chars()
        .map(|c| if c.is_control() || is_format_char(c) { ' ' } else { c })
        .take(SUBJECT_MAX)
        .collect()
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
    /// Jobs answered ok in the last ANSWERED_KEEP seconds, by RDS job id.
    #[serde(default)]
    answered: BTreeMap<i64, Answered>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Answered {
    at: i64,
    /// job_digest of the job: an id RDS hands out again for a different job (a restored database)
    /// is judged afresh.
    digest: String,
    result: JobResult,
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

    /// The answer given to job `id` (same job, answered in the last ANSWERED_KEEP seconds), if any.
    fn answered(&self, id: i64, digest: &str, at: i64) -> Option<&JobResult> {
        self.answered
            .get(&id)
            .filter(|a| a.digest == digest && at - a.at < ANSWERED_KEEP)
            .map(|a| &a.result)
    }

    /// Remembers an ok answer; the caller saves the state with it.
    fn remember(&mut self, id: i64, digest: String, result: &JobResult, at: i64) {
        self.answered.retain(|_, a| at - a.at < ANSWERED_KEEP);
        while self.answered.len() >= ANSWERED_MAX && !self.answered.contains_key(&id) {
            self.answered.pop_first();
        }
        self.answered.insert(id, Answered { at, digest, result: result.clone() });
    }
}

/// What identifies a job's content: its kind and payload.
fn job_digest(kind: &str, payload: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload.to_string().as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
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

/// The most an interrupted append can leave behind: one entry (under 5 KiB, see LOG_TEXT_MAX) plus a
/// NUL-filled block from a power cut. More unreadable bytes than this at the end is not a torn write.
const TORN_TAIL_MAX: usize = 16 * 1024;

/// RDS-supplied text (approver, revoke reason, refusal errors) is cut to this many characters
/// before it goes into the log, ids and job kinds to LOG_ID_MAX. JSON escapes a character to at
/// most 6 bytes, so the largest entry (a revoke: two ids and a reason) stays under 5 KiB however
/// long RDS makes them.
const LOG_TEXT_MAX: usize = 512;
const LOG_ID_MAX: usize = 64;

/// At most this many refused jobs an hour get their own log entry. Past that they are only counted
/// (journal, daily digest), and one `refused_unlogged` entry an hour later says how many, so an RDS
/// that keeps sending bad jobs can't grow the log without bound.
const REFUSED_LOG_PER_HOUR: usize = 30;

/// `text` cut to `max` characters (on a character boundary), with a marker when anything was cut.
fn capped(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        None => text.to_string(),
        Some((at, _)) => format!("{}...[{} more chars cut]", &text[..at], text[at..].chars().count()),
    }
}

impl IssuanceLog {
    /// Opens the log and re-checks the whole chain. A chain that doesn't verify, or unreadable bytes
    /// before the last line, stop the signer.
    ///
    /// The one thing tolerated is what an interrupted append leaves (a kill or power cut mid-write):
    /// unreadable bytes in the last line only, with nothing but whitespace or NULs from where the
    /// parse failed on (a cut-off entry is a prefix of a good one). With `repair` those bytes are
    /// saved next to the log as `issuance.log.torn-<unix time>` and cut off, the returned note
    /// says what happened (the caller logs it and records it in the log), and the note is added to
    /// the `repair_marker` file first, which stays until its mail has gone out (`repair_notice`).
    /// Without `repair` they are an error. Entries an older binary glued onto one line (its JSON
    /// and newline were two writes) are read one by one, and a missing final newline is put back
    /// with `repair`; neither loses an entry.
    fn open(path: PathBuf, repair: bool) -> Result<(IssuanceLog, Option<String>), String> {
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("log read: {e}")),
        };
        let mut seq = 0;
        let mut head = "genesis".to_string();
        let mut good_end = 0usize; // just past the last entry that verified
        let mut torn: Option<(usize, usize)> = None; // (line number, where parsing failed)
        let mut start = 0usize;
        let mut n = 0usize;
        while start < bytes.len() {
            n += 1;
            let end = bytes[start..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |i| start + i);
            let mut entries = serde_json::Deserializer::from_slice(&bytes[start..end]).into_iter::<Value>();
            while let Some(parsed) = entries.next() {
                let mut value = match parsed {
                    Ok(value) => value,
                    Err(e) => {
                        // A cut-off entry runs into the end of the line; otherwise parsing stopped at
                        // the first bad byte (the column is 1-based, in bytes; the line has no '\n').
                        let at = if e.is_eof() { end } else { (start + e.column().saturating_sub(1)).min(end) };
                        torn = Some((n, at));
                        break;
                    }
                };
                let stated = value.get("hash").and_then(Value::as_str).unwrap_or_default().to_string();
                if value.get("prev").and_then(Value::as_str) != Some(head.as_str()) {
                    return Err(format!("log chain broken at line {n} (prev)"));
                }
                value.as_object_mut().map(|o| o.remove("hash"));
                let expected = entry_hash(&head, &serde_json::to_string(&value).map_err(|e| e.to_string())?);
                if expected != stated {
                    return Err(format!("log chain broken at line {n} (hash)"));
                }
                head = stated;
                seq = value.get("seq").and_then(Value::as_u64).unwrap_or(0);
                good_end = start + entries.byte_offset();
            }
            if torn.is_some() {
                break;
            }
            start = end + 1;
        }
        let tail = &bytes[good_end..];
        if let Some((line, failed_at)) = torn {
            let only_padding_after = bytes[failed_at..].iter().all(|&b| b == 0 || b.is_ascii_whitespace());
            if !only_padding_after || tail.len() > TORN_TAIL_MAX {
                return Err(format!("log line {line} unreadable"));
            }
            if !repair {
                return Err(format!(
                    "log line {line} unreadable: an interrupted write left {} byte(s) at the end; `ca-signer run` saves and cuts them off",
                    tail.len()
                ));
            }
            let saved = path.with_extension(format!("log.torn-{}", now()));
            fs::write(&saved, tail).map_err(|e| format!("log repair: saving the torn bytes: {e}"))?;
            let note = format!(
                "issuance log: an interrupted write left {} unreadable byte(s) in line {line}; they were saved to {} and cut off. The chain verifies through seq {seq}.",
                tail.len(),
                saved.display()
            );
            // Before the cut: once the bytes are gone, the next start sees a clean log and only this
            // marker still says a repair mail is owed (one note a line).
            let marker = Self::repair_marker(&path);
            let failed = |e: std::io::Error| format!("log repair: {}: {e}", marker.display());
            let mut file = fs::OpenOptions::new().create(true).append(true).open(&marker).map_err(failed)?;
            file.write_all(format!("{note}\n").as_bytes()).and_then(|_| file.sync_all()).map_err(failed)?;
            Self::cut(&path, good_end)?;
            return Ok((IssuanceLog { path, seq, head }, Some(note)));
        }
        if repair && good_end > 0 && !tail.contains(&b'\n') {
            Self::cut(&path, good_end)?;
            log("WARN", &format!("issuance log: the entry at seq {seq} had no newline after it; added it"));
        }
        Ok((IssuanceLog { path, seq, head }, None))
    }

    /// Truncates the log to `len` bytes, ending it with a newline when anything is left.
    fn cut(path: &Path, len: usize) -> Result<(), String> {
        let failed = |e: std::io::Error| format!("log repair: {e}");
        let mut file = fs::OpenOptions::new().append(true).open(path).map_err(failed)?;
        file.set_len(len as u64).map_err(failed)?;
        if len > 0 {
            file.write_all(b"\n").map_err(failed)?;
        }
        file.sync_all().map_err(failed)
    }

    /// `issuance.log.repair-pending`: notes of repairs whose mail hasn't gone out yet.
    fn repair_marker(path: &Path) -> PathBuf {
        path.with_extension("log.repair-pending")
    }

    /// The repair mail still owed for the log at `path` (this start's repair, or one from a start
    /// that failed before it could mail it), or None. The mail removes the marker once it is sent.
    fn repair_notice(path: &Path) -> Option<OutMail> {
        let marker = Self::repair_marker(path);
        let notes = match fs::read_to_string(&marker) {
            Ok(text) => text.lines().filter(|l| !l.trim().is_empty()).collect::<Vec<_>>().join("\n\n"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => format!("(the repair notes in {} could not be read: {e})", marker.display()),
        };
        if notes.is_empty() {
            let _ = fs::remove_file(&marker);
            return None;
        }
        Some(OutMail {
            subject: "[RDC CA] Issuance log repaired at start".into(),
            body: format!("{notes}\n\nThe signer started normally. An append was interrupted (a kill or power cut mid-write); if it belonged to a job, that job was never answered and RDS offers it again."),
            clears: Some(marker),
        })
    }

    fn append(&mut self, mut entry: Value) -> Result<(), String> {
        let object = entry.as_object_mut().ok_or("log entry must be an object")?;
        object.insert("seq".into(), json!(self.seq + 1));
        object.insert("ts".into(), json!(now()));
        object.insert("prev".into(), json!(self.head));
        let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        let hash = entry_hash(&self.head, &line);
        entry.as_object_mut().map(|o| o.insert("hash".into(), json!(hash)));
        let mut record = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        record.push('\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("log open: {e}"))?;
        // The whole entry, newline included, in one write on an O_APPEND file: a kill can no longer
        // leave an entry without its newline for the next one to be glued onto. If the write or the
        // sync fails part-way (a full disk), what was written is cut off again.
        let before = file.metadata().map_err(|e| format!("log open: {e}"))?.len();
        if let Err(e) = file.write_all(record.as_bytes()).and_then(|_| file.sync_all()) {
            let _ = file.set_len(before).and_then(|_| file.sync_all());
            return Err(format!("log write: {e}"));
        }
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

/// When an issuing key's certificate expires. The key signs for `issuing_key_days`, and the last
/// passport it signs must still verify for its whole lifetime plus the longest grace (+5 days slack):
/// verifiers give the grace to passports only, never to the certificate.
fn issuing_key_exp(created: i64, issuing_key_days: i64, max_lifetime_days: i64) -> i64 {
    created + (issuing_key_days + max_lifetime_days + MAX_GRACE_DAYS + 5) * 86_400
}

impl Keys {
    fn new(issuing_key_days: i64, max_lifetime_days: i64) -> Result<Keys, String> {
        let root = read_root()?;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let issuing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let created = now();
        let exp = issuing_key_exp(created, issuing_key_days, max_lifetime_days);
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

#[derive(Serialize, Deserialize, Default, Clone)]
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
    key_update_mails_held: u64,
}

/// A queued mail. `clears` is a marker file that comes off once the mail has actually been sent.
struct OutMail {
    subject: String,
    body: String,
    clears: Option<PathBuf>,
}

impl OutMail {
    /// After the send attempt: removes the marker only if the mail went out, so an unsent notice is
    /// queued again at the next start.
    fn finish(self, sent: bool) {
        if let (true, Some(marker)) = (sent, &self.clears) {
            if let Err(e) = fs::remove_file(marker) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log("WARN", &format!("{}: {e} (the next start mails it again)", marker.display()));
                }
            }
        }
    }
}

struct Signer {
    cfg: Config,
    state: State,
    state_path: PathBuf,
    log: IssuanceLog,
    keys: Keys,
    counters_24h: Vec<(i64, &'static str)>,
    mails: Vec<OutMail>,
    refused_logged: Vec<i64>,
    refused_unlogged: Option<(i64, u64)>, // (first left out at, how many)
    /// The job being processed: (RDS job id, job_digest), for remembering its answer.
    current_job: Option<(i64, String)>,
    /// When a mail last went out, by what it was about (a device's key updates, an id conflict).
    mailed_at: BTreeMap<String, i64>,
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
                "key_update_mail_held" => c.key_update_mails_held += 1,
                _ => {}
            }
        }
        c
    }

    fn mail(&mut self, subject: String, body: String) {
        self.mails.push(OutMail { subject, body, clears: None });
    }

    /// Whether a mail about `topic` may go out at `t` (none in the last `every` seconds, at most a
    /// day); if so, the time is recorded.
    fn mail_due(&mut self, topic: &str, every: i64, t: i64) -> bool {
        self.mailed_at.retain(|_, at| t - *at < 86_400);
        if self.mailed_at.get(topic).map_or(false, |at| t - at < every) {
            return false;
        }
        self.mailed_at.insert(topic.to_string(), t);
        true
    }

    /// Remembers the current job's ok answer for redeliveries (saved with the state by the caller).
    fn remember_answer(&mut self, result: &mut JobResult, t: i64) {
        if let Some((id, digest)) = self.current_job.clone() {
            result.id = id;
            self.state.remember(id, digest, result, t);
        }
    }

    /// Saves the state; if that fails, the current job's answer is forgotten again (it goes back
    /// as a refusal).
    fn save_state(&mut self) -> Result<(), String> {
        self.state.save(&self.state_path).map_err(|e| {
            if let Some((id, _)) = &self.current_job {
                self.state.answered.remove(id);
            }
            e
        })
    }

    /// Whether a job refused at `t` gets its own log entry (REFUSED_LOG_PER_HOUR); if not, it is
    /// counted for `log_unlogged_refusals`.
    fn refused_log_ok(&mut self, t: i64) -> bool {
        self.refused_logged.retain(|at| t - at < 3600);
        if self.refused_logged.len() < REFUSED_LOG_PER_HOUR {
            self.refused_logged.push(t);
            return true;
        }
        self.refused_unlogged.get_or_insert((t, 0)).1 += 1;
        false
    }

    /// Records how many refused jobs were left out of the log, an hour after the first of them.
    fn log_unlogged_refusals(&mut self, t: i64) {
        if let Some((since, count)) = self.refused_unlogged {
            if t - since >= 3600 && self.log.append(json!({"kind": "refused_unlogged", "count": count, "since": since})).is_ok() {
                self.refused_unlogged = None;
            }
        }
    }

    fn rotate_if_needed(&mut self) -> Result<(), String> {
        if now() - self.keys.created >= self.cfg.issuing_key_days * 86_400 {
            let old = self.keys.kid.clone();
            self.keys = Keys::new(self.cfg.issuing_key_days, self.cfg.max_lifetime_days)?;
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
        let mut result = JobResult {
            ok: true,
            passport: Some(token),
            serial: Some(body.serial),
            nbf: Some(body.nbf),
            exp: Some(body.exp),
            idk: Some(body.idk),
            prot: Some(body.prot),
            ..Default::default()
        };
        // In the same save as the record it changes (a key update's new key), so a redelivered job
        // finds its answer even when the key on file has already moved.
        self.remember_answer(&mut result, t);
        self.save_state()?;
        self.count("issued");
        Ok(result)
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
        let name: String = printable(&d.name).chars().take(80).collect();
        let approver_name = printable(&job.approver.name);
        let approver = capped(
            &format!(
                "{} ({}, {})",
                if approver_name.is_empty() { "unknown" } else { approver_name.as_str() },
                printable(&job.approver.role),
                printable(&job.approver.source)
            ),
            LOG_TEXT_MAX,
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
        // One RustDesk id, one device: an id another approved device holds is never given to a
        // second one. A reinstall revokes the old record first, so this is never a legitimate job.
        let holder = self
            .state
            .devices
            .values()
            .find(|o| o.did != d.did && o.status == "approved" && o.rid.eq_ignore_ascii_case(&d.rid))
            .map(|o| (o.did.clone(), printable(&o.name), printable(&o.approved_by)));
        if let Some((holder_did, holder_name, holder_approver)) = holder {
            // At most one mail an hour per id (the ids that can conflict are the approved ones).
            if self.mail_due(&format!("rid-conflict:{}", d.rid.to_ascii_lowercase()), 3600, now()) {
                self.mail(
                    format!("[RDC CA] REFUSED: id {} already belongs to device {}", d.rid, holder_did),
                    format!(
                        "RDS asked for a passport for device {} (\"{}\") as RustDesk id {}, but that id belongs to device {} (\"{}\", approved by {}), which is not revoked.\nNothing was issued.\n\nIf the old device is gone, revoke it in RDS first, then approve the new one. If you did not ask for this, RDS may be compromised.",
                        d.did, name, d.rid, holder_did, holder_name, holder_approver
                    ),
                );
            }
            return Err(format!("rid already belongs to approved device {holder_did}"));
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
            approved_source: capped(&printable(&job.approver.source), LOG_ID_MAX),
            first_seen: existing.as_ref().map(|e| e.first_seen).unwrap_or(t),
            last_issued: existing.as_ref().map(|e| e.last_issued).unwrap_or(0),
            recent_issues: existing.as_ref().map(|e| e.recent_issues.clone()).unwrap_or_default(),
        };
        self.state.devices.insert(d.did.clone(), record);
        let result = self.issue_for(&d.did, job.lifetime_days, &format!("issue:{}", job.reason), &approver)?;
        if key_new || was_revoked {
            self.count("new_device");
            let shown = if name.is_empty() { "unnamed" } else { name.as_str() };
            let new_fp = pp::fingerprint(&pp::unb64(&d.idk).unwrap_or_default());
            match existing.as_ref().filter(|_| key_new) {
                // A known device with a different key, through an RDS approval: the old key did not
                // sign this, so it gets its own, unmistakable subject.
                Some(e) => self.mail(
                    format!("[RDC CA] IDENTITY KEY CHANGED for {} ({shown})", d.rid),
                    format!(
                        "RDS approved device {shown} with a key different from the one the CA had on file{}. The old key did not sign this change.\n\nRustDesk id: {}\nRDS device id: {}\nOld key fingerprint: {}\nNew key fingerprint: {}\nKey protection: {} (was {})\nPreviously approved by: {}\nApproved now by: {}\nPassport serial: {}\n\nIf you did not reinstall or re-approve this device, revoke it in RDS now.",
                        if was_revoked { " (it had been revoked)" } else { "" },
                        d.rid, d.did,
                        pp::fingerprint(&pp::unb64(&e.idk).unwrap_or_default()),
                        new_fp, d.prot, e.prot, printable(&e.approved_by), approver,
                        result.serial.clone().unwrap_or_default()
                    ),
                ),
                None => {
                    let what = if existing.is_none() { "New device approved" } else { "Device re-approved" };
                    self.mail(
                        format!("[RDC CA] {what}: {shown} ({})", d.rid),
                        format!(
                            "{what}.\n\nDevice: {shown}\nRustDesk id: {}\nRDS device id: {}\nApproved by: {}\nKey fingerprint: {}\nKey protection: {}\nPassport serial: {}\n\nIf you did not expect this, revoke the device in RDS now.",
                            d.rid, d.did, approver, new_fp, d.prot,
                            result.serial.clone().unwrap_or_default()
                        ),
                    );
                }
            }
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
        if new_key.as_bytes() == old.as_bytes() {
            return Err("key update names the key already on file".into());
        }
        if !["dpapi", "keystore", "tpm"].contains(&body.prot.as_str()) {
            return Err("unsupported key protection".into());
        }
        if self.state.nonce_seen(&job.did, &body.nonce, now()) {
            return Err("key update replayed".into());
        }
        if !self.rate_ok(&job.did) {
            return Err("rate limit".into());
        }
        let old_prot = device.prot.clone();
        if let Some(d) = self.state.devices.get_mut(&job.did) {
            d.idk = pp::b64(new_key.as_bytes());
            d.prot = body.prot.clone();
        }
        let result = self.issue_for(&job.did, job.lifetime_days, "key_update", "device signatures (old + new key)")?;
        self.count("key_update");
        if old_prot != "legacy" {
            // A device's own key updates mail at most once an hour; more only count (digest).
            if self.mail_due(&format!("key-update:{}", job.did), KEY_MAIL_EVERY, now()) {
                let shown = printable(&device.name);
                let shown = if shown.is_empty() { "unnamed".to_string() } else { shown };
                self.mail(
                    format!("[RDC CA] IDENTITY KEY CHANGED for {} ({shown})", device.rid),
                    format!(
                        "Device {shown} ({}) moved from a {old_prot} key to a new {} key. The device signed the change with both keys.\n\nRDS device id: {}\nOld key fingerprint: {}\nNew key fingerprint: {}\nApproved by: {}\n\nIf this was not a reinstall or upgrade you expected, revoke it in RDS.",
                        device.rid, body.prot, device.did,
                        pp::fingerprint(old.as_bytes()), pp::fingerprint(new_key.as_bytes()),
                        printable(&device.approved_by)
                    ),
                );
            } else {
                self.count("key_update_mail_held");
                log("INFO", &format!("key update for {} not mailed (one mail an hour per device)", device.rid));
            }
        }
        Ok(result)
    }

    fn handle_revoke(&mut self, job: RevokeJob) -> Result<JobResult, String> {
        let mut newly_revoked = None;
        if let Some(d) = self.state.devices.get_mut(&job.did) {
            if d.rid != job.rid {
                return Err("rid does not match the device on file".into());
            }
            if d.status != "revoked" {
                newly_revoked = Some((printable(&d.name), printable(&d.approved_by)));
            }
            d.status = "revoked".into();
        }
        let reason = capped(&job.reason, LOG_TEXT_MAX);
        self.log.append(json!({
            "kind": "revoke", "rid": capped(&job.rid, LOG_ID_MAX), "did": capped(&job.did, LOG_ID_MAX),
            "reason": reason,
        }))?;
        let mut result = JobResult { ok: true, ..Default::default() };
        self.remember_answer(&mut result, now());
        self.save_state()?;
        self.count("revoked");
        // Only a device on file that was approved until now: the number of these mails is bounded
        // by the devices the CA knows, however many revoke jobs RDS sends.
        if let Some((name, approved_by)) = newly_revoked {
            let shown = if name.is_empty() { "unnamed" } else { name.as_str() };
            self.mail(
                format!("[RDC CA] Device revoked: {shown} ({})", job.rid),
                format!(
                    "RDS revoked device {shown}.\n\nRustDesk id: {}\nRDS device id: {}\nReason given: {}\nIt had been approved by: {approved_by}\n\nThe CA issues it nothing more until it is approved again. If you did not revoke it, check RDS.",
                    job.rid, job.did, printable(&reason)
                ),
            );
        }
        Ok(result)
    }

    fn process(&mut self, job: Job) -> JobResult {
        let id = job.id;
        // A job answered before (RDS never got the answer and hands it out again) gets the same
        // answer, before any policy or nonce check: judging it again would compare it with what
        // the first answer already changed (a key update's new key) and refuse it.
        let digest = job_digest(&job.kind, &job.payload);
        if let Some(result) = self.state.answered(id, &digest, now()) {
            log("INFO", &format!("job {id} was answered before; sending the same answer again"));
            return result.clone();
        }
        self.current_job = Some((id, digest));
        let outcome = match job.kind.as_str() {
            "issue" => serde_json::from_value(job.payload).map_err(|e| format!("issue job: {e}")).and_then(|j| self.handle_issue(j)),
            "renew" => serde_json::from_value(job.payload).map_err(|e| format!("renew job: {e}")).and_then(|j| self.handle_renew(j)),
            "keyupdate" => serde_json::from_value(job.payload).map_err(|e| format!("keyupdate job: {e}")).and_then(|j| self.handle_key_update(j)),
            "revoke" => serde_json::from_value(job.payload).map_err(|e| format!("revoke job: {e}")).and_then(|j| self.handle_revoke(j)),
            other => Err(format!("unknown job kind '{other}'")),
        };
        self.current_job = None;
        match outcome {
            Ok(mut result) => {
                result.id = id;
                result
            }
            Err(error) => {
                // Errors can echo RDS's own text (an unknown reason or kind, a parse error).
                let (error, kind) = (capped(&error, LOG_TEXT_MAX), capped(&job.kind, LOG_ID_MAX));
                self.count("refused");
                if self.refused_log_ok(now()) {
                    let _ = self.log.append(json!({"kind": "refused", "job": id, "job_kind": kind, "error": error}));
                }
                log("WARN", &format!("job {id} ({kind}) refused: {error}"));
                JobResult { id, ok: false, error: Some(error), ..Default::default() }
            }
        }
    }
}

// ---------------------------------------------------------------- mail (curl, SMTP submission)

/// Whether the mail was handed to the SMTP server.
async fn send_mail(cfg: &Config, subject: &str, body: &str) -> bool {
    // The one choke point for every subject: device names and RDS text end up in some of them.
    let subject = mail_subject(subject);
    let cred = match credential_path("smtp") {
        Ok(path) if fs::read_to_string(&path).map(|t| t.contains("user")).unwrap_or(false) => path,
        _ => {
            log("INFO", &format!("mail not sent (SMTP not configured): {subject}"));
            return false;
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
            return false;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(message.as_bytes()).await;
    }
    match child.wait_with_output().await {
        Ok(out) if out.status.success() => {
            log("INFO", &format!("mail sent: {subject}"));
            true
        }
        Ok(out) => {
            log("ERROR", &format!("mail failed: {} {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
            false
        }
        Err(e) => {
            log("ERROR", &format!("mail failed: {e}"));
            false
        }
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
    let log_path = state_dir.join("issuance.log");
    let (mut issuance, repaired) = IssuanceLog::open(log_path.clone(), true)?;
    if let Some(note) = &repaired {
        // Recorded at once, so the chain shows it even if a later start step fails (the mail is
        // owed through the repair marker until it has gone out).
        log("WARN", note);
        issuance.append(json!({"kind": "recovered", "note": note}))?;
    }
    let state = State::load(&state_path)?;
    let keys = Keys::new(cfg.issuing_key_days, cfg.max_lifetime_days)?;
    log("INFO", &format!(
        "ca-signer {VERSION} started: issuing key {} (expires {}), {} devices on file, log seq {}",
        keys.kid, keys.exp, state.devices.len(), issuance.seq
    ));
    let client = http_client(&cfg)?;
    let mut signer = Signer {
        cfg: cfg.clone(), state, state_path, log: issuance, keys, counters_24h: Vec::new(), mails: Vec::new(),
        refused_logged: Vec::new(), refused_unlogged: None, current_job: None, mailed_at: BTreeMap::new(),
    };
    if let Some(mail) = IssuanceLog::repair_notice(&log_path) {
        signer.mails.push(mail);
    }
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
        signer.log_unlogged_refusals(now());
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
        for mail in std::mem::take(&mut signer.mails) {
            let sent = send_mail(&cfg, &mail.subject, &mail.body).await;
            mail.finish(sent);
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
                "Daily CA digest (last 24 h)\n\nPassports issued: {}\n  renewals: {}\n  key updates: {} ({} not mailed: one mail an hour per device)\n  new/re-approved devices: {}\nRevocations: {}\nRefused jobs: {}\n\nDevices on file: {} ({} approved)\nIssuing key: {} (expires {})\nIssuance log: seq {} head {}\nUpdates pending: {} ({} security), reboot required: {}\n",
                c.issued, c.renewed, c.key_updates, c.key_update_mails_held, c.new_devices, c.revoked, c.refused,
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
    let (mut log, _) = IssuanceLog::open(state_dir.join("issuance.log"), false)?;
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
            rid: d.rid, did: d.did, name: printable(&d.name).chars().take(80).collect(), idk: d.idk, idk_alg: d.idk_alg, rdk: d.rdk, prot: d.prot,
            status: "approved".into(), approved_by: "bootstrap import (list reviewed by the owner)".into(),
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
    let (log, _) = IssuanceLog::open(PathBuf::from(&cfg.state_dir).join("issuance.log"), false)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ca-signer-test-{tag}-{}-{}", std::process::id(), random_hex(4)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_signer(dir: &Path) -> Signer {
        let cfg = Config {
            rds_url: String::new(), link_ca: String::new(), link_client_cert: String::new(),
            state_dir: dir.display().to_string(), mail_from: String::new(), mail_to: String::new(),
            smtp_host: String::new(), smtp_ip: String::new(), smtp_port: 587,
            max_lifetime_days: 7, issuing_key_days: 30, max_issues_per_device_hour: 10, digest_hour_utc: 12,
        };
        let (log, _) = IssuanceLog::open(dir.join("issuance.log"), true).unwrap();
        let keys = Keys { issuing: SigningKey::from_bytes(&[7; 32]), ikc: String::new(), kid: "test".into(), created: now(), exp: now() + 86_400 };
        Signer {
            cfg, state: State::default(), state_path: dir.join("devices.json"), log, keys, counters_24h: Vec::new(), mails: Vec::new(),
            refused_logged: Vec::new(), refused_unlogged: None, current_job: None, mailed_at: BTreeMap::new(),
        }
    }

    /// A log with two good entries, then `tail` written straight after them.
    fn log_with_tail(dir: &Path, tail: &[u8]) -> PathBuf {
        let path = dir.join("issuance.log");
        let (mut log, _) = IssuanceLog::open(path.clone(), false).unwrap();
        log.append(json!({"kind": "start", "version": "test"})).unwrap();
        log.append(json!({"kind": "start", "version": "test"})).unwrap();
        fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(tail).unwrap();
        path
    }

    fn log_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path).unwrap().lines().map(String::from).collect()
    }

    #[test]
    fn repair_mail_stays_owed_until_it_is_sent() {
        let dir = temp_dir("repair");
        let mut torn = br#"{"kind":"issue:approve","rid":"123456789","approver":"Brad (Ow"#.to_vec();
        torn.extend_from_slice(&[0; 4096]);
        let path = log_with_tail(&dir, &torn);
        let (_, first) = IssuanceLog::open(path.clone(), true).unwrap();
        let first = first.expect("repaired");
        // That start fails after the repair (state, keys, link client), so nothing is mailed; the
        // next start finds a clean log, and is interrupted mid-append again.
        let (mut log, clean) = IssuanceLog::open(path.clone(), true).unwrap();
        assert!(clean.is_none());
        log.append(json!({"kind": "recovered", "note": first})).unwrap();
        fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(br#"{"kind":"st"#).unwrap();
        let (log, second) = IssuanceLog::open(path.clone(), true).unwrap();
        let second = second.expect("repaired again");
        assert_eq!(log.seq, 3);
        // Both repairs are still owed, in one mail.
        let mail = IssuanceLog::repair_notice(&path).expect("mail owed");
        assert!(mail.body.contains(&first) && mail.body.contains(&second));
        mail.finish(false); // SMTP down or not configured: still owed at the next start
        let mail = IssuanceLog::repair_notice(&path).expect("mail still owed after a failed send");
        mail.finish(true);
        assert!(!IssuanceLog::repair_marker(&path).exists());
        assert!(IssuanceLog::repair_notice(&path).is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn torn_check_starts_where_parsing_failed() {
        // Cut-off entries: at the end of the file, NUL-padded (across a newline), mid-escape,
        // mid-literal, and a NUL block with no entry at all.
        let cut_off: [&[u8]; 5] = [
            b"{\"kind\":\"revoke\",\"reason\":\"lost lap",
            b"{\"kind\":\"revoke\",\"seq\":12\0\0\0\0\n\0\0",
            b"{\"kind\":\"re\\",
            b"{\"ok\":tr\0\0\0",
            b"\0\0\0\0",
        ];
        for tail in cut_off {
            let dir = temp_dir("torn-ok");
            let path = log_with_tail(&dir, tail);
            let (log, note) =
                IssuanceLog::open(path.clone(), true).unwrap_or_else(|e| panic!("{:?}: {e}", String::from_utf8_lossy(tail)));
            assert!(note.is_some() && log.seq == 2);
            assert!(IssuanceLog::open(path, false).is_ok());
            fs::remove_dir_all(&dir).unwrap();
        }
        // Not a cut-off entry: more than padding after the bad byte on the same line.
        let damaged: [&[u8]; 3] = [
            b"{\"kind\":\"revoke\"X,\"reason\":\"y\"}",
            b"{\"kind\":\"re\0voke\"}",
            b"\0\0{\"kind\":\"revoke\"}",
        ];
        for tail in damaged {
            let dir = temp_dir("torn-bad");
            let path = log_with_tail(&dir, tail);
            let size = fs::metadata(&path).unwrap().len();
            let error = IssuanceLog::open(path.clone(), true).err().expect("refused");
            assert_eq!(error, "log line 3 unreadable");
            assert_eq!(fs::metadata(&path).unwrap().len(), size);
            assert!(!IssuanceLog::repair_marker(&path).exists());
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn capped_cuts_on_a_char_boundary() {
        assert_eq!(capped("short", LOG_TEXT_MAX), "short");
        assert_eq!(capped(&"x".repeat(512), 512), "x".repeat(512));
        let cut = capped(&"é".repeat(600), 512);
        assert_eq!(cut, format!("{}...[88 more chars cut]", "é".repeat(512)));
    }

    #[test]
    fn rds_text_cannot_make_a_log_entry_too_big() {
        let dir = temp_dir("caps");
        let mut signer = test_signer(&dir);
        let huge = "\u{1}".repeat(100_000); // JSON escapes each to 6 bytes
        let key = pp::b64(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes());
        let device = json!({"rid": "123456789", "did": "0123abcd-0000-4000-8000-000000000001", "name": "test",
            "idk": key, "idk_alg": "ed25519", "rdk": key, "prot": "tpm"});
        let jobs = [
            Job { id: 1, kind: huge.clone(), payload: json!({}) },
            Job { id: 2, kind: "revoke".into(), payload: json!({"rid": huge, "did": huge, "reason": huge}) },
            Job { id: 3, kind: "issue".into(), payload: json!({"device": device, "lifetime_days": 7, "reason": "approve",
                "approver": {"name": huge, "role": huge, "source": huge}}) },
            Job { id: 4, kind: "issue".into(), payload: json!({"device": device, "lifetime_days": 7, "reason": huge}) },
        ];
        let oks: Vec<bool> = jobs.into_iter().map(|job| signer.process(job).ok).collect();
        assert_eq!(oks, [false, true, true, false]);
        let lines = log_lines(&signer.log.path);
        assert_eq!(lines.len(), 4);
        for line in &lines {
            assert!(line.len() < 5 * 1024, "entry of {} bytes", line.len());
        }
        assert!(IssuanceLog::open(signer.log.path.clone(), false).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refused_jobs_are_rate_limited_in_the_log() {
        let dir = temp_dir("refused");
        let mut signer = test_signer(&dir);
        for id in 0..100 {
            assert!(!signer.process(Job { id, kind: "bogus".into(), payload: json!({}) }).ok);
        }
        assert_eq!(signer.counters().refused, 100);
        assert_eq!(log_lines(&signer.log.path).len(), REFUSED_LOG_PER_HOUR);
        let t = now();
        signer.log_unlogged_refusals(t); // not an hour yet
        assert_eq!(log_lines(&signer.log.path).len(), REFUSED_LOG_PER_HOUR);
        signer.log_unlogged_refusals(t + 3600);
        let lines = log_lines(&signer.log.path);
        assert_eq!(lines.len(), REFUSED_LOG_PER_HOUR + 1);
        let summary: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(summary["kind"], json!("refused_unlogged"));
        assert_eq!(summary["count"], json!(100 - REFUSED_LOG_PER_HOUR));
        assert!(signer.refused_unlogged.is_none());
        assert!(signer.refused_log_ok(t + 3600)); // an hour on, refusals are logged again
        assert!(IssuanceLog::open(signer.log.path.clone(), false).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    const RID: &str = "123456789";
    const DID1: &str = "0123abcd-0000-4000-8000-000000000001";
    const DID2: &str = "0123abcd-0000-4000-8000-000000000002";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn fp(key: &SigningKey) -> String {
        pp::fingerprint(key.verifying_key().as_bytes())
    }

    fn issue_payload(did: &str, key: &SigningKey, reason: &str) -> Value {
        let k = pp::b64(key.verifying_key().as_bytes());
        json!({"device": {"rid": RID, "did": did, "name": "lap\r\nBcc: x@y\u{202E}", "idk": k, "idk_alg": "ed25519",
            "rdk": k, "prot": "tpm"}, "lifetime_days": 7, "reason": reason,
            "approver": {"name": "Brad", "role": "Owner", "source": "admin_ui"}})
    }

    fn key_update_payload(did: &str, old: &SigningKey, new: &SigningKey) -> Value {
        let body = pp::KeyUpdateBody {
            typ: "rdc-keyupdate".into(), v: pp::VERSION, rid: RID.into(), did: did.into(),
            old_key: pp::b64(old.verifying_key().as_bytes()), new_key: pp::b64(new.verifying_key().as_bytes()),
            new_alg: "ed25519".into(), prot: "tpm".into(), ts: now(), nonce: random_hex(8),
        };
        json!({"rid": RID, "did": did, "request": pp::sign_key_update(old, new, &body), "lifetime_days": 7})
    }

    fn job(id: i64, kind: &str, payload: &Value) -> Job {
        Job { id, kind: kind.into(), payload: payload.clone() }
    }

    #[test]
    fn a_redelivered_key_update_gets_the_same_answer() {
        let dir = temp_dir("redeliver");
        let mut signer = test_signer(&dir);
        assert!(signer.process(job(1, "issue", &issue_payload(DID1, &key(1), "approve"))).ok);
        let update = key_update_payload(DID1, &key(1), &key(2));
        let first = signer.process(job(2, "keyupdate", &update));
        assert!(first.ok && first.id == 2);
        // The answer was lost on the way back; RDS hands the job out again.
        let again = signer.process(job(2, "keyupdate", &update));
        assert!(again.ok && again.id == 2);
        assert_eq!(again.serial, first.serial);
        assert_eq!(again.passport, first.passport);
        // Judged afresh it would be refused: the key on file has already moved.
        assert!(!signer.process(job(3, "keyupdate", &update)).ok);
        // The answer was saved with the new key, so a restart still has it.
        let saved = State::load(&signer.state_path).unwrap();
        assert_eq!(saved.answered.get(&2).and_then(|a| a.result.serial.clone()), first.serial);
        assert_eq!(saved.devices[DID1].idk, pp::b64(key(2).verifying_key().as_bytes()));
        let mut restarted = test_signer(&dir);
        restarted.state = saved;
        assert_eq!(restarted.process(job(2, "keyupdate", &update)).serial, first.serial);
        // The same id for a different job (a restored RDS database) is judged afresh.
        let other = restarted.process(job(2, "revoke", &json!({"rid": RID, "did": DID1, "reason": "lost"})));
        assert!(other.ok && other.serial.is_none());
        // Old answers are dropped after a day.
        let t = now();
        restarted.state.remember(99, "x".into(), &JobResult { id: 99, ok: true, ..Default::default() }, t - ANSWERED_KEEP);
        assert!(restarted.state.answered(99, "x", t).is_none());
        restarted.state.remember(100, "y".into(), &JobResult::default(), t);
        assert!(!restarted.state.answered.contains_key(&99));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_update_to_the_same_key_or_past_the_rate_cap_is_refused() {
        let dir = temp_dir("keyupdate-caps");
        let mut signer = test_signer(&dir);
        assert!(signer.process(job(1, "issue", &issue_payload(DID1, &key(1), "approve"))).ok);
        let same = signer.process(job(2, "keyupdate", &key_update_payload(DID1, &key(1), &key(1))));
        assert!(!same.ok && same.error.unwrap().contains("already on file"));
        let t = now();
        signer.state.devices.get_mut(DID1).unwrap().recent_issues = vec![t; 10];
        let capped = signer.process(job(3, "keyupdate", &key_update_payload(DID1, &key(1), &key(2))));
        assert_eq!(capped.error.as_deref(), Some("rate limit"));
        assert_eq!(signer.state.devices[DID1].idk, pp::b64(key(1).verifying_key().as_bytes()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_updates_mail_at_most_once_an_hour_per_device() {
        let dir = temp_dir("keyupdate-mail");
        let mut signer = test_signer(&dir);
        assert!(signer.process(job(1, "issue", &issue_payload(DID1, &key(1), "approve"))).ok);
        signer.mails.clear();
        assert!(signer.process(job(2, "keyupdate", &key_update_payload(DID1, &key(1), &key(2)))).ok);
        assert!(signer.process(job(3, "keyupdate", &key_update_payload(DID1, &key(2), &key(3)))).ok);
        assert_eq!(signer.mails.len(), 1);
        let mail = &signer.mails[0];
        assert!(mail.subject.starts_with(&format!("[RDC CA] IDENTITY KEY CHANGED for {RID} (")));
        assert!(mail.body.contains(&fp(&key(1))) && mail.body.contains(&fp(&key(2))));
        let c = signer.counters();
        assert_eq!((c.key_updates, c.key_update_mails_held), (2, 1));
        // An hour on, the next one mails again.
        assert!(signer.mail_due(&format!("key-update:{DID1}"), KEY_MAIL_EVERY, now() + KEY_MAIL_EVERY));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_id_another_approved_device_holds_is_refused() {
        let dir = temp_dir("rid-conflict");
        let mut signer = test_signer(&dir);
        assert!(signer.process(job(1, "issue", &issue_payload(DID1, &key(1), "approve"))).ok);
        signer.mails.clear();
        let refused = signer.process(job(2, "issue", &issue_payload(DID2, &key(2), "approve")));
        assert!(!refused.ok && refused.error.unwrap().contains(DID1));
        assert!(!signer.state.devices.contains_key(DID2));
        assert_eq!(signer.mails.len(), 1);
        assert_eq!(signer.mails[0].subject, format!("[RDC CA] REFUSED: id {RID} already belongs to device {DID1}"));
        // Asked again within the hour: refused, not mailed again.
        assert!(!signer.process(job(3, "issue", &issue_payload(DID2, &key(2), "approve"))).ok);
        assert_eq!(signer.mails.len(), 1);
        // The documented reinstall: revoke the old record, then approve the new one.
        let revoke = json!({"rid": RID, "did": DID1, "reason": "reinstall"});
        assert!(signer.process(job(4, "revoke", &revoke)).ok);
        assert!(signer.mails[1].subject.starts_with("[RDC CA] Device revoked: "));
        assert!(signer.process(job(5, "issue", &issue_payload(DID2, &key(2), "approve"))).ok);
        assert!(signer.mails[2].subject.starts_with("[RDC CA] New device approved: "));
        // A second revoke of an already revoked device mails nothing.
        assert!(signer.process(job(6, "revoke", &revoke)).ok);
        assert_eq!(signer.mails.len(), 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn re_approval_with_another_key_mails_identity_key_changed() {
        let dir = temp_dir("rekey");
        let mut signer = test_signer(&dir);
        assert!(signer.process(job(1, "issue", &issue_payload(DID1, &key(1), "approve"))).ok);
        // Another key is only taken with a fresh approval.
        assert!(!signer.process(job(2, "issue", &issue_payload(DID1, &key(2), "reissue"))).ok);
        assert!(signer.process(job(3, "issue", &issue_payload(DID1, &key(2), "approve"))).ok);
        let mail = signer.mails.last().unwrap();
        assert_eq!(mail.subject, format!("[RDC CA] IDENTITY KEY CHANGED for {RID} (lapBcc: x@y)"));
        assert!(mail.body.contains(&format!("Old key fingerprint: {}", fp(&key(1)))));
        assert!(mail.body.contains(&format!("New key fingerprint: {}", fp(&key(2)))));
        assert!(mail.body.contains("Previously approved by: Brad (Owner, admin_ui)"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_control_characters_reach_a_subject_or_the_device_table() {
        assert_eq!(mail_subject("New device: lap\r\nBcc: x@y\u{202E}!"), "New device: lap  Bcc: x@y !");
        assert_eq!(mail_subject(&"é".repeat(500)).chars().count(), SUBJECT_MAX);
        assert_eq!(printable("a\u{0}b\u{200B}c\u{7F}d\te"), "abcde");
        let dir = temp_dir("names");
        let mut signer = test_signer(&dir);
        let mut payload = issue_payload(DID1, &key(1), "approve");
        payload["approver"]["name"] = json!("Brad\r\nX-Evil: 1");
        assert!(signer.process(job(1, "issue", &payload)).ok);
        let d = &signer.state.devices[DID1];
        assert_eq!(d.name, "lapBcc: x@y");
        assert_eq!(d.approved_by, "BradX-Evil: 1 (Owner, admin_ui)");
        assert!(signer.mails.iter().all(|m| !m.subject.chars().any(char::is_control)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_passport_stays_valid_through_its_grace_past_the_old_35_day_ikc() {
        let root = key(11);
        let issuing = key(12);
        let created = 1_800_000_000;
        let (key_days, lifetime_days) = (30, 7);
        // The issuing key's last passport, signed just before it is rotated out, at the longest
        // lifetime, checked in the last minute of the longest grace.
        let iat = created + key_days * 86_400 - 60;
        let body = pp::PassportBody {
            typ: "rdc-passport".into(), v: pp::VERSION, serial: random_hex(16), rid: RID.into(), did: DID1.into(),
            idk: pp::b64(key(1).verifying_key().as_bytes()), idk_alg: "ed25519".into(),
            rdk: pp::b64(key(1).verifying_key().as_bytes()), prot: "tpm".into(),
            scopes: pp::SCOPES.iter().map(|s| s.to_string()).collect(),
            iat, nbf: iat - 300, exp: iat + lifetime_days * 86_400, ikid: pp::kid_for(&issuing.verifying_key()),
        };
        let window = pp::Window { now: body.exp + MAX_GRACE_DAYS * 86_400 - 60, skew: 600, grace: MAX_GRACE_DAYS * 86_400 };
        let roots = [root.verifying_key()];
        let exp = issuing_key_exp(created, key_days, lifetime_days);
        assert_eq!(exp, created + 72 * 86_400);
        let ikc = pp::sign_ikc(&root, &issuing.verifying_key(), created - 300, exp);
        let verified = pp::verify(&pp::sign_passport(&issuing, &ikc, &body), &roots, window).unwrap();
        assert!(verified.in_grace);
        // The old certificate (key days + 5) expired long before.
        let old_ikc = pp::sign_ikc(&root, &issuing.verifying_key(), created - 300, created + (key_days + 5) * 86_400);
        assert_eq!(pp::verify(&pp::sign_passport(&issuing, &old_ikc, &body), &roots, window), Err(pp::Error::IkcExpired));
    }
}
