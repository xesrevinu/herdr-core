//! Rex control protocol (`rex.control.v1`), terminal data protocol
//! (`rex.data.terminal.v1`), ordered JSON marshaling, and help catalog.

use crate::rpc::RpcError;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONTROL_PROTOCOL: &str = "rex.control.v1";
pub const DATA_PROTOCOL: &str = "rex.data.terminal.v1";
pub const DATA_BYTES_PROTOCOL: &str = "rex.data.bytes.v1";
pub const API_REVISION: i64 = 13;
pub const API_MIN_REVISION: i64 = 7;
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;

pub const TERMINAL_CREATOR: &str = "com.superlogical.terminal";
pub const SHELL_FLAVOR: &str = "com.superlogical.terminal.shell";

pub const CODE_BAD_REQUEST: &str = "bad_request";
pub const CODE_NOT_FOUND: &str = "not_found";
pub const CODE_METHOD_NOT_FOUND: &str = "method_not_found";
pub const CODE_SESSION_NOT_FOUND: &str = "session_not_found";
pub const CODE_CONFLICT: &str = "conflict";
pub const CODE_NOT_SUPPORTED: &str = "not_supported";
pub const CODE_TOO_LARGE: &str = "too_large";
pub const CODE_INTERNAL: &str = "internal";

pub const CLOSE_NORMAL: u16 = 1000;
pub const CLOSE_PROVIDER_CANCELED: u16 = 1001;
pub const CLOSE_PROVIDER_UNAVAILABLE: u16 = 1008;
pub const CLOSE_PROVIDER_FAILED: u16 = 1011;
pub const CLOSE_RECONNECT_REQUIRED: u16 = 1013;
pub const CLOSE_BLOCK_CLOSED: u16 = 4000;
pub const CLOSE_PROTOCOL_VIOLATION: u16 = 4006;

pub const BLANK_SNAPSHOT: &[u8] = include_bytes!("assets/blank_80x24.snap");
pub const REX_HELP_JSON: &str = include_str!("assets/rex-help.json");

pub const MAX_DATA_FRAME: usize = 64 << 10;

pub const MSG_HELLO: u8 = 0x01;
pub const MSG_WELCOME: u8 = 0x81;
pub const MSG_REJECT: u8 = 0x82;

pub const REJECT_UNKNOWN_TICKET: u8 = 0x01;
pub const REJECT_MALFORMED: u8 = 0x05;
pub const REJECT_SUBPROTOCOL: u8 = 0x07;

#[derive(Debug, Clone, Serialize)]
pub struct RexError {
    pub code: String,
    pub message: String,
    pub status: u16,
}

impl RexError {
    pub fn new(code: impl Into<String>, message: impl Into<String>, status: u16) -> Self {
        Self { code: code.into(), message: message.into(), status }
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(CODE_BAD_REQUEST, msg, 400)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(CODE_NOT_FOUND, msg, 404)
    }
    pub fn session_not_found(msg: impl Into<String>) -> Self {
        Self::new(CODE_SESSION_NOT_FOUND, msg, 404)
    }
    pub fn method_not_found(msg: impl Into<String>) -> Self {
        Self::new(CODE_METHOD_NOT_FOUND, msg, 404)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(CODE_CONFLICT, msg, 409)
    }
    pub fn not_supported(msg: impl Into<String>) -> Self {
        Self::new(CODE_NOT_SUPPORTED, msg, 400)
    }
    pub fn too_large(msg: impl Into<String>) -> Self {
        Self::new(CODE_TOO_LARGE, msg, 413)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(CODE_INTERNAL, msg, 500)
    }
    pub fn to_json(&self) -> Value {
        json!({"code": self.code, "message": self.message, "status": self.status})
    }
}

impl fmt::Display for RexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RexError {}

impl From<RpcError> for RexError {
    fn from(e: RpcError) -> Self {
        match e.kind.as_str() {
            "not_found" => Self::not_found(e.message),
            "invalid_params" => Self::bad_request(e.message),
            _ => Self::new(CODE_CONFLICT, e.message, 400),
        }
    }
}

pub fn parse_data_hello(b: &[u8]) -> Option<[u8; 16]> {
    if b.len() < 17 || b[0] != MSG_HELLO {
        return None;
    }
    let mut ticket = [0u8; 16];
    ticket.copy_from_slice(&b[1..17]);
    Some(ticket)
}

pub fn data_welcome(token: [u8; 16], keep_ms: u32, nonce: u64) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[0] = MSG_WELCOME;
    b[1..17].copy_from_slice(&token);
    b[20..24].copy_from_slice(&keep_ms.to_le_bytes());
    b[24..32].copy_from_slice(&nonce.to_le_bytes());
    b
}

pub fn data_reject(reason: u8) -> Vec<u8> {
    vec![MSG_REJECT, reason]
}

pub fn apc_resize(nonce: u64, cols: u16, rows: u16, cell_w: u32, cell_h: u32, owner: Option<&str>) -> Vec<u8> {
    let body = json!({
        "cell_height_px": cell_h,
        "cell_width_px": cell_w,
        "cols": cols,
        "owner": owner,
        "rows": rows,
        "type": "resize",
    });
    encode_apc(nonce, &body)
}

pub fn apc_child_exited(nonce: u64, code: i32) -> Vec<u8> {
    encode_apc(nonce, &json!({"exit_code": code, "type": "child_exited"}))
}

pub fn apc_theme(nonce: u64, body: &Map<String, Value>) -> Vec<u8> {
    let mut m = body.clone();
    m.insert("type".into(), Value::String("theme".into()));
    encode_apc(nonce, &Value::Object(m))
}

fn encode_apc(nonce: u64, body: &Value) -> Vec<u8> {
    let j = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    format!("\x1b_rex1;{nonce};{j}\x1b\\").into_bytes()
}

fn key_rank(k: &str) -> i32 {
    match k {
        "type" => -4,
        "id" => -3,
        "seq" => -2,
        "session_id" => -1,
        "payload" | "error" => 1,
        _ => 0,
    }
}

/// Marshals JSON with Rex's field order (`type`, `id`, `seq`, `session_id` first;
/// `payload`/`error` last; remaining keys alphabetical).
pub fn marshal_rex(v: &Value) -> String {
    let mut out = String::new();
    write_rex_json(v, &mut out);
    out
}

fn write_rex_json(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_by(|a, b| key_rank(a).cmp(&key_rank(b)).then_with(|| a.cmp(b)));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()));
                out.push(':');
                write_rex_json(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_rex_json(item, out);
            }
            out.push(']');
        }
        _ => {
            out.push_str(&serde_json::to_string(v).unwrap_or_else(|_| "null".into()));
        }
    }
}

/// Formats a `SystemTime` as RFC 3339 UTC with nanosecond precision.
pub fn stamp_rfc3339(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    format_unix_ns(dur.as_secs() as i64, dur.subsec_nanos())
}

pub fn stamp_rfc3339_ms(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let nanos = ((ms % 1000) * 1_000_000) as u32;
    format_unix_ns(secs, nanos)
}

fn format_unix_ns(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    let sec = tod % 60;
    let (year, month, day) = civil_from_days(days);
    if nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
    } else {
        let frac = format!("{nanos:09}");
        let trimmed = frac.trim_end_matches('0');
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{trimmed}Z")
    }
}

// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Formats `file://<host><path>` matching Go's `url.URL` path escaping.
pub fn file_url(host: &str, path: &str) -> String {
    let mut out = String::with_capacity(7 + host.len() + path.len() + 8);
    out.push_str("file://");
    out.push_str(host);
    for b in path.as_bytes() {
        let keep = matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' | b'/'
            | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@'
        );
        if keep {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decodes a `file://host/path` URL back to its filesystem path, or returns the input unchanged.
pub fn decode_file_url(raw: &str) -> String {
    let Some(rest) = raw.strip_prefix("file://") else {
        return raw.to_string();
    };
    let path = match rest.find('/') {
        Some(idx) => &rest[idx..],
        None => return String::new(),
    };
    percent_decode(path)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Default)]
pub struct HelpCatalog {
    control: HashMap<String, Value>,
    blocks: Vec<HelpBlockCatalog>,
}

#[derive(Clone)]
struct HelpBlockCatalog {
    creator: String,
    flavors: Vec<String>,
    methods: Vec<(String, Value)>,
}

impl HelpCatalog {
    pub fn parse(raw: &str) -> Self {
        let Ok(doc) = serde_json::from_str::<Value>(raw) else {
            return Self::default();
        };
        let mut control = HashMap::new();
        if let Some(methods) = doc["methods"].as_array() {
            for m in methods {
                if let Some(name) = m["name"].as_str() {
                    control.insert(name.to_string(), m.clone());
                }
            }
        }
        let mut blocks = Vec::new();
        if let Some(btypes) = doc["block_types"].as_array() {
            for b in btypes {
                let creator = b["creator"].as_str().unwrap_or_default().to_string();
                let flavors: Vec<String> = b["flavors"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect();
                let mut methods = Vec::new();
                if let Some(ms) = b["methods"].as_array() {
                    for m in ms {
                        if let Some(name) = m["name"].as_str() {
                            methods.push((format!("{creator}.{name}"), m.clone()));
                        }
                    }
                }
                blocks.push(HelpBlockCatalog { creator, flavors, methods });
            }
        }
        Self { control, blocks }
    }

    pub fn describe(&self, supported: &HashSet<String>, include_http: bool) -> Value {
        let mut block_methods = HashSet::new();
        let mut block_types = Vec::new();
        for b in &self.blocks {
            let mut methods = Vec::new();
            for (full_name, raw) in &b.methods {
                if supported.contains(full_name) {
                    methods.push(raw.clone());
                    block_methods.insert(full_name.clone());
                }
            }
            if !methods.is_empty() {
                block_types.push(json!({
                    "creator": b.creator,
                    "flavors": b.flavors,
                    "methods": methods,
                }));
            }
        }
        let mut names: Vec<&String> = supported.iter().collect();
        names.sort();
        let mut methods = Vec::new();
        for name in names {
            if block_methods.contains(name) {
                continue;
            }
            if let Some(raw) = self.control.get(name) {
                methods.push(raw.clone());
            } else {
                methods.push(json!({"name": name, "invoke": {"method": name}}));
            }
        }
        let mut doc = Map::new();
        doc.insert("methods".into(), Value::Array(methods));
        doc.insert("block_types".into(), Value::Array(block_types));
        if include_http {
            let mut http = BTreeMap::new();
            http.insert("control_path", "/api/control");
            http.insert("data_path", "/api/data");
            http.insert("help_path", "/api/help");
            doc.insert("http".into(), json!(http));
        }
        Value::Object(doc)
    }
}
