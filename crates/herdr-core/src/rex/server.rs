//! Rex HTTP/WebSocket transport (`rex.control.v1`, `rex.data.terminal.v1`,
//! `rex.data.bytes.v1`, `/api/help`), client sessions, outboxes, and tickets.

use super::proto::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message, WebSocketConfig};
use uuid::Uuid;

const MAX_BACKLOG: usize = 8 << 20;
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const PING_EVERY: Duration = Duration::from_secs(20);
const TICKET_TTL: Duration = Duration::from_secs(60);
const STREAM_KEEP_MS: u32 = 60_000;
const DATA_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_UPLOAD_FRAME: usize = 32 << 20;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub type ControlHandler =
    Arc<dyn Fn(Arc<RexClient>, Value) -> BoxFuture<Result<Value, RexError>> + Send + Sync>;
pub type DataSourceFn = Arc<
    dyn Fn(Arc<RexClient>, DataRequest) -> BoxFuture<Result<DataServeFn, RexError>> + Send + Sync,
>;
pub type DataServeFn = Box<dyn FnOnce(DataStream) -> BoxFuture<()> + Send>;
pub type UploadServeFn = Box<dyn FnOnce(UploadStream) -> BoxFuture<()> + Send>;
pub type DisconnectFn = Arc<dyn Fn(Arc<RexClient>) + Send + Sync>;

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq)]
pub struct DataRequest {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub block_id: String,
    #[serde(default)]
    pub data_ref_id: String,
    #[serde(default)]
    pub subprotocol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataTicket {
    pub ticket: String,
    pub expires_in_ms: i64,
}

struct TicketEntry {
    client_id: String,
    client: Arc<RexClient>,
    req: DataRequest,
    sub: String,
    serve: Option<DataServeFn>,
    upload: Option<UploadServeFn>,
    expires: Instant,
}

enum OutMsg {
    Text(String),
    Close(u16, String),
}

pub struct RexClient {
    pub id: String,
    pub principal: Value,
    pub connected_at: SystemTime,
    pub api_revision: i64,
    trace: bool,

    seq: AtomicU64,
    queued: AtomicUsize,
    tx: mpsc::UnboundedSender<OutMsg>,

    state: Mutex<ClientState>,
}

struct ClientState {
    info: Value,
    attached: HashMap<String, SystemTime>,
    last_sid: String,
    attach_all: bool,
    event_all: bool,
    closed: bool,
}

impl RexClient {
    fn new(
        principal: Value,
        info: Value,
        api_revision: i64,
        trace: bool,
        tx: mpsc::UnboundedSender<OutMsg>,
    ) -> Self {
        Self {
            id: format!("client:{}", Uuid::new_v4()),
            principal,
            connected_at: SystemTime::now(),
            api_revision,
            trace,
            seq: AtomicU64::new(0),
            queued: AtomicUsize::new(0),
            tx,
            state: Mutex::new(ClientState {
                info: if info.is_object() { info } else { json!({}) },
                attached: HashMap::new(),
                last_sid: String::new(),
                attach_all: false,
                event_all: false,
                closed: false,
            }),
        }
    }

    pub fn info(&self) -> Value {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).info.clone()
    }

    pub fn is_unix(&self) -> bool {
        self.principal.get("transport").and_then(Value::as_str) == Some("unix")
    }

    pub fn remember_session(&self, sid: &str) {
        if sid.is_empty() {
            return;
        }
        self.state.lock().unwrap_or_else(|p| p.into_inner()).last_sid = sid.to_string();
    }

    pub fn last_session(&self) -> String {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).last_sid.clone()
    }

    pub fn attached(&self, sid: &str) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).attached.contains_key(sid)
    }

    pub fn wants(&self, sid: &str) -> bool {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.attach_all || st.attached.contains_key(sid)
    }

    pub fn wants_block_events(&self, sid: &str) -> bool {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.event_all || st.attached.contains_key(sid)
    }

    pub fn is_attach_all(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).attach_all
    }

    pub fn wants_all(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).event_all
    }

    pub fn describe(&self, sid: &str) -> Value {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut m = Map::new();
        m.insert("client_id".into(), Value::String(self.id.clone()));
        m.insert("principal".into(), self.principal.clone());
        m.insert("info".into(), st.info.clone());
        m.insert("connection_state".into(), Value::String("connected".into()));
        if !sid.is_empty() {
            let at = st.attached.get(sid).copied().unwrap_or(self.connected_at);
            m.insert("connected_at".into(), Value::String(stamp_rfc3339(at)));
            return Value::Object(m);
        }
        m.insert("connected_at".into(), Value::String(stamp_rfc3339(self.connected_at)));
        let mut ids: Vec<String> = st.attached.keys().cloned().collect();
        ids.sort();
        if !ids.is_empty() {
            m.insert("session_ids".into(), json!(ids));
        }
        Value::Object(m)
    }

    pub fn last_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    fn send_raw(&self, text: String) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.closed {
            return;
        }
        let prev = self.queued.fetch_add(text.len(), Ordering::SeqCst);
        if prev + text.len() > MAX_BACKLOG {
            st.closed = true;
            let _ = self.tx.send(OutMsg::Close(1008, "event backlog exceeded".into()));
            return;
        }
        let _ = self.tx.send(OutMsg::Text(text));
    }

    pub fn write_value(&self, v: &Value) {
        self.send_raw(marshal_rex(v));
    }

    pub fn push_event(&self, payload: Value) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.closed {
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let msg = json!({"type": "event", "seq": seq, "payload": payload});
        let mut text = marshal_rex(&msg);
        if text.len() > MAX_MESSAGE_BYTES {
            if self.api_revision >= 18 {
                let dropped = build_event_dropped(&payload, text.len());
                text = marshal_rex(&json!({"type": "event", "seq": seq, "payload": dropped}));
            } else {
                st.closed = true;
                let _ = self.tx.send(OutMsg::Close(1009, "event exceeds message limit".into()));
                return;
            }
        }
        let prev = self.queued.fetch_add(text.len(), Ordering::SeqCst);
        if prev + text.len() > MAX_BACKLOG {
            st.closed = true;
            let _ = self.tx.send(OutMsg::Close(1008, "event backlog exceeded".into()));
            return;
        }
        if self.trace {
            eprintln!("rex event client={} seq={} {}", self.id, seq, payload);
        }
        let _ = self.tx.send(OutMsg::Text(text));
    }

    pub fn session_event(&self, sid: &str, typ: &str, payload: Value) {
        let ok = if typ == "block_event" {
            self.wants_block_events(sid)
        } else {
            self.wants(sid)
        };
        if ok {
            self.push_event(json!({
                "type": "session_event",
                "payload": {
                    "session_id": sid,
                    "event": {"type": typ, "payload": payload},
                }
            }));
        }
    }

    pub fn close(&self, code: u16, reason: &str) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.closed {
            return;
        }
        st.closed = true;
        let _ = self.tx.send(OutMsg::Close(code, reason.into()));
    }
}

pub struct DataStream {
    pub client: Arc<RexClient>,
    pub request: DataRequest,
    pub nonce: u64,
    tx: mpsc::Sender<DataCmd>,
    closed_rx: tokio::sync::watch::Receiver<bool>,
}

enum DataCmd {
    Bytes(Vec<u8>),
    Close(u16, String),
}

impl DataStream {
    #[allow(clippy::result_unit_err)]
    pub async fn send(&self, mut p: &[u8]) -> Result<(), ()> {
        while !p.is_empty() {
            if *self.closed_rx.borrow() {
                return Err(());
            }
            let n = p.len().min(MAX_DATA_FRAME);
            let chunk = p[..n].to_vec();
            if self.tx.send(DataCmd::Bytes(chunk)).await.is_err() {
                return Err(());
            }
            p = &p[n..];
        }
        Ok(())
    }

    #[allow(clippy::result_unit_err)]
    pub async fn send_half_close(&self) -> Result<(), ()> {
        if *self.closed_rx.borrow() {
            return Err(());
        }
        self.tx.send(DataCmd::Bytes(Vec::new())).await.map_err(|_| ())
    }

    pub async fn close(&self, code: u16, reason: &str) {
        let _ = self.tx.send(DataCmd::Close(code, reason.to_string())).await;
    }

    pub async fn wait_closed(&mut self) {
        while !*self.closed_rx.borrow() {
            if self.closed_rx.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        *self.closed_rx.borrow()
    }
}

pub enum UploadChunk {
    Data(Vec<u8>),
    HalfClose,
    Dropped,
}

pub struct UploadStream {
    pub client: Arc<RexClient>,
    pub request: DataRequest,
    pub nonce: u64,
    rx: mpsc::Receiver<UploadChunk>,
    close_tx: mpsc::Sender<(u16, String)>,
}

impl UploadStream {
    pub async fn recv(&mut self) -> UploadChunk {
        self.rx.recv().await.unwrap_or(UploadChunk::Dropped)
    }

    pub async fn close(&self, code: u16, reason: &str) {
        let _ = self.close_tx.send((code, reason.to_string())).await;
    }
}

struct ServerInner {
    handlers: HashMap<String, ControlHandler>,
    clients: HashMap<String, Arc<RexClient>>,
    tickets: HashMap<[u8; 16], TicketEntry>,
    ticket_sweep: Instant,
    data_source: Option<DataSourceFn>,
    on_disconnect: Option<DisconnectFn>,
    help: HelpCatalog,
}

pub struct RexServer {
    pub trace: bool,
    inner: Mutex<ServerInner>,
}

impl RexServer {
    pub fn new(trace: bool) -> Arc<Self> {
        let srv = Arc::new(Self {
            trace,
            inner: Mutex::new(ServerInner {
                handlers: HashMap::new(),
                clients: HashMap::new(),
                tickets: HashMap::new(),
                ticket_sweep: Instant::now() + TICKET_TTL,
                data_source: None,
                on_disconnect: None,
                help: HelpCatalog::parse(REX_HELP_JSON),
            }),
        });
        srv.register_builtins();
        srv
    }

    fn register_builtins(self: &Arc<Self>) {
        self.handle("server.whoami", |c, _| async move {
            Ok(json!({"principal": c.principal}))
        });
        self.handle("client.set_label", |c, p| async move {
            let label = p.get("label").and_then(Value::as_str).unwrap_or_default().to_string();
            let mut st = c.state.lock().unwrap_or_else(|p| p.into_inner());
            let mut info = st.info.as_object().cloned().unwrap_or_default();
            if label.is_empty() {
                info.remove("label");
            } else {
                info.insert("label".into(), Value::String(label));
            }
            st.info = Value::Object(info);
            Ok(json!({}))
        });
        {
            let s = self.clone();
            self.handle("client.list", move |_, p| {
                let s = s.clone();
                async move {
                    let sid = p.get("session_id").and_then(Value::as_str).unwrap_or_default();
                    let kinds: HashSet<String> = p
                        .get("kinds")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect();
                    let mut out = Vec::new();
                    for o in s.clients() {
                        if !sid.is_empty() && !o.attached(sid) {
                            continue;
                        }
                        let d = o.describe("");
                        let kind = d["info"]["kind"].as_str().unwrap_or_default();
                        if !kinds.is_empty() && !kinds.contains(kind) {
                            continue;
                        }
                        out.push(d);
                    }
                    Ok(json!({"clients": out}))
                }
            });
        }
        {
            let s = self.clone();
            self.handle("session.detach", move |c, p| {
                let s = s.clone();
                async move {
                    let sid = p.get("session_id").and_then(Value::as_str).unwrap_or_default();
                    s.detach(&c, sid);
                    Ok(json!({}))
                }
            });
        }
        {
            let s = self.clone();
            self.handle("data.connect", move |c, p| {
                let s = s.clone();
                async move {
                    let req: DataRequest = serde_json::from_value(if p.is_null() { json!({}) } else { p })
                        .map_err(|e| RexError::bad_request(format!("bad payload: {e}")))?;
                    let tk = s.issue_data_ticket(c, req).await?;
                    Ok(serde_json::to_value(tk).unwrap_or_else(|_| json!({})))
                }
            });
        }
        {
            let s = self.clone();
            self.handle("help.all", move |_, _| {
                let s = s.clone();
                async move { Ok(s.describe_help(false)) }
            });
        }
    }

    pub fn handle<F, Fut>(&self, method: &str, f: F)
    where
        F: Fn(Arc<RexClient>, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, RexError>> + Send + 'static,
    {
        let h: ControlHandler = Arc::new(move |c, p| Box::pin(f(c, p)));
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).handlers.insert(method.to_string(), h);
    }

    pub fn set_data_source(&self, f: DataSourceFn) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).data_source = Some(f);
    }

    pub fn set_on_disconnect(&self, f: DisconnectFn) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).on_disconnect = Some(f);
    }

    pub fn describe_help(&self, include_http: bool) -> Value {
        let st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let supported: HashSet<String> = st.handlers.keys().cloned().collect();
        st.help.describe(&supported, include_http)
    }

    pub fn clients(&self) -> Vec<Arc<RexClient>> {
        let st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut cs: Vec<Arc<RexClient>> = st.clients.values().cloned().collect();
        cs.sort_by_key(|c| c.connected_at);
        cs
    }

    pub fn attach_all(&self, c: &RexClient, scope: &str) -> Result<(), RexError> {
        if scope != "all" && scope != "session" {
            return Err(RexError::bad_request(r#"event_scope must be "all" or "session""#));
        }
        let mut st = c.state.lock().unwrap_or_else(|p| p.into_inner());
        st.attach_all = true;
        st.event_all = st.event_all || scope == "all";
        Ok(())
    }

    pub fn attach(&self, c: &RexClient, sid: &str) {
        let (at, first) = {
            let mut st = c.state.lock().unwrap_or_else(|p| p.into_inner());
            st.last_sid = sid.to_string();
            match st.attached.get(sid).copied() {
                Some(at) => (at, false),
                None => {
                    let now = SystemTime::now();
                    st.attached.insert(sid.to_string(), now);
                    (now, true)
                }
            }
        };
        if first {
            self.session_event(
                sid,
                "client_connected",
                json!({
                    "client_id": c.id,
                    "principal": c.principal,
                    "connected_at": stamp_rfc3339(at),
                }),
            );
        }
    }

    pub fn detach(&self, c: &RexClient, sid: &str) {
        let was = c.state.lock().unwrap_or_else(|p| p.into_inner()).attached.remove(sid).is_some();
        {
            let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            st.tickets.retain(|_, t| !(t.client_id == c.id && t.serve.is_some() && t.req.session_id == sid));
        }
        if was {
            self.session_event(
                sid,
                "client_disconnected",
                json!({"client_id": c.id, "principal": c.principal}),
            );
        }
    }

    pub fn session_event(&self, sid: &str, typ: &str, payload: Value) {
        for c in self.clients() {
            c.session_event(sid, typ, payload.clone());
        }
    }

    pub fn emit(&self, typ: &str, payload: Value) {
        let msg = json!({"type": typ, "payload": payload});
        let sid = payload.get("session_id").and_then(Value::as_str).unwrap_or_default();
        for c in self.clients() {
            let ok = match typ {
                "session_destroyed" => c.wants(sid),
                "keymap_changed" | "hosts_changed" => true,
                "client_joined" | "client_left" => c.wants_all(),
                _ => c.is_attach_all(),
            };
            if ok {
                c.push_event(msg.clone());
            }
        }
    }

    fn joined(&self, c: &RexClient) {
        let ev = json!({"type": "client_joined", "payload": {"client": c.describe("")}});
        for o in self.clients() {
            if o.id != c.id && o.wants_all() {
                o.push_event(ev.clone());
            }
        }
    }

    fn left(&self, c: &RexClient) {
        let sids: Vec<String> = c
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .attached
            .keys()
            .cloned()
            .collect();
        for sid in sids {
            self.detach(c, &sid);
        }
        self.emit("client_left", json!({"client_id": c.id}));
    }

    pub async fn issue_data_ticket(
        &self,
        c: Arc<RexClient>,
        req: DataRequest,
    ) -> Result<DataTicket, RexError> {
        if !c.attached(&req.session_id) {
            return Err(RexError::conflict("connection is not attached to this session"));
        }
        let data_fn = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .data_source
            .clone()
            .ok_or_else(|| RexError::not_found(format!("block has no data source {}", req.data_ref_id)))?;
        let serve = data_fn(c.clone(), req.clone()).await?;
        if !req.subprotocol.is_empty() && req.subprotocol != DATA_PROTOCOL {
            return Err(RexError::bad_request(format!("unsupported subprotocol {}", req.subprotocol)));
        }
        Ok(self.new_ticket(c, req, Some(serve), None, DATA_PROTOCOL))
    }

    pub fn issue_upload_ticket(
        &self,
        c: Arc<RexClient>,
        sub: &str,
        upload: UploadServeFn,
    ) -> DataTicket {
        let req = DataRequest {
            session_id: String::new(),
            block_id: String::new(),
            data_ref_id: String::new(),
            subprotocol: sub.to_string(),
        };
        self.new_ticket(c, req, None, Some(upload), sub)
    }

    pub fn issue_download_ticket(
        &self,
        c: Arc<RexClient>,
        sub: &str,
        serve: DataServeFn,
    ) -> DataTicket {
        let req = DataRequest {
            session_id: String::new(),
            block_id: String::new(),
            data_ref_id: String::new(),
            subprotocol: sub.to_string(),
        };
        self.new_ticket(c, req, Some(serve), None, sub)
    }

    fn new_ticket(
        &self,
        client: Arc<RexClient>,
        req: DataRequest,
        serve: Option<DataServeFn>,
        upload: Option<UploadServeFn>,
        sub: &str,
    ) -> DataTicket {
        let mut raw = [0u8; 16];
        rand::rng().fill_bytes(&mut raw);
        let now = Instant::now();
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if now >= st.ticket_sweep {
            st.tickets.retain(|_, item| now < item.expires);
            st.ticket_sweep = now + TICKET_TTL;
        }
        st.tickets.insert(
            raw,
            TicketEntry {
                client_id: client.id.clone(),
                client,
                req,
                sub: sub.to_string(),
                serve,
                upload,
                expires: now + TICKET_TTL,
            },
        );
        DataTicket {
            ticket: URL_SAFE_NO_PAD.encode(raw),
            expires_in_ms: TICKET_TTL.as_millis() as i64,
        }
    }

    fn redeem(&self, raw: [u8; 16]) -> Option<TicketEntry> {
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let tk = st.tickets.remove(&raw)?;
        if Instant::now() > tk.expires {
            return None;
        }
        Some(tk)
    }

    /// Serves one accepted TCP or Unix connection speaking HTTP/1.1 + WebSocket.
    pub async fn serve_stream<S>(self: Arc<Self>, mut stream: S, peer_addr: Option<String>, is_unix: bool)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut head = Vec::with_capacity(1024);
        let mut buf = [0u8; 2048];
        let header_end = loop {
            if let Some(pos) = find_header_end(&head) {
                break pos;
            }
            if head.len() >= 16384 {
                let _ = write_http_response(&mut stream, 431, "Request Header Fields Too Large", "text/plain", b"").await;
                return;
            }
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(n)) => head.extend_from_slice(&buf[..n]),
            }
        };

        let header_str = String::from_utf8_lossy(&head[..header_end]);
        let mut lines = header_str.split("\r\n");
        let req_line = lines.next().unwrap_or_default();
        let mut parts = req_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let raw_target = parts.next().unwrap_or_default();
        let path = raw_target.split('?').next().unwrap_or(raw_target).to_string();

        let mut host = String::new();
        let mut origin = String::new();
        let mut upgrade = String::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let kl = k.trim().to_ascii_lowercase();
                let v = v.trim();
                match kl.as_str() {
                    "host" => host = v.to_string(),
                    "origin" => origin = v.to_string(),
                    "upgrade" => upgrade = v.to_ascii_lowercase(),
                    _ => {}
                }
            }
        }

        if path == "/api/help" {
            if method != "GET" && method != "HEAD" {
                let resp = "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes()).await;
                return;
            }
            let body = serde_json::to_vec(&self.describe_help(true)).unwrap_or_else(|_| b"{}".to_vec());
            let body_ref = if method == "HEAD" { &[][..] } else { &body[..] };
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            if !body_ref.is_empty() {
                let _ = stream.write_all(body_ref).await;
            }
            return;
        }

        if path != "/api/control" && path != "/api/data" {
            let _ = write_http_response(&mut stream, 404, "Not Found", "text/plain", b"not found\n").await;
            return;
        }

        if upgrade != "websocket" {
            let _ = write_http_response(&mut stream, 426, "Upgrade Required", "text/plain", b"websocket required\n").await;
            return;
        }

        if !trusted_host(is_unix, &origin, &host) {
            let _ = write_http_response(
                &mut stream,
                403,
                "Forbidden",
                "text/plain",
                b"forbidden: a browser may connect only by IP address or localhost\n",
            )
            .await;
            return;
        }

        let prefixed = PrefixedStream { prefix: head, pos: 0, inner: stream };
        if path == "/api/control" {
            self.serve_control(prefixed, peer_addr, is_unix).await;
        } else {
            self.serve_data(prefixed).await;
        }
    }

    async fn serve_control<S>(self: Arc<Self>, stream: S, peer_addr: Option<String>, is_unix: bool)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut negotiated = String::new();
        let ws_cfg = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        let ws = match tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            #[allow(clippy::result_large_err)]
            |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
                if let Some(proto) = pick_subprotocol(req, &[CONTROL_PROTOCOL]) {
                    negotiated = proto.clone();
                    if let Ok(val) = proto.parse() {
                        resp.headers_mut().insert("sec-websocket-protocol", val);
                    }
                }
                Ok(resp)
            },
            Some(ws_cfg),
        )
        .await
        {
            Ok(ws) => ws,
            Err(_) => return,
        };

        let (mut ws_tx, mut ws_rx) = ws.split();
        if negotiated != CONTROL_PROTOCOL {
            let _ = ws_tx
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Protocol,
                    reason: "protocol error".into(),
                })))
                .await;
            return;
        }

        // Read hello
        let hello_msg = match tokio::time::timeout(HANDSHAKE_TIMEOUT, ws_rx.next()).await {
            Ok(Some(Ok(Message::Text(txt)))) => txt,
            _ => {
                let _ = ws_tx
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Protocol,
                        reason: "protocol error".into(),
                    })))
                    .await;
                return;
            }
        };
        let hello: Value = match serde_json::from_str::<Value>(&hello_msg) {
            Ok(v) if v["type"] == "hello" => v,
            _ => {
                let _ = ws_tx
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Protocol,
                        reason: "protocol error".into(),
                    })))
                    .await;
                return;
            }
        };
        let api_rev = hello["api_revision"].as_i64().unwrap_or(0);
        let api_min = hello["api_min_revision"].as_i64().unwrap_or(0);
        let revision = api_rev.min(API_REVISION);
        if revision < api_min.max(API_MIN_REVISION) {
            let side = if api_min > API_REVISION { "server" } else { "client" };
            let _ = ws_tx
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: format!("no common API revision: update the {side}").into(),
                })))
                .await;
            return;
        }

        let principal = make_principal(peer_addr.as_deref(), is_unix);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<OutMsg>();
        let client = Arc::new(RexClient::new(principal, hello["client"].clone(), revision, self.trace, out_tx));

        let client_writer = client.clone();
        let writer_task = tokio::spawn(async move {
            let mut ping = tokio::time::interval(PING_EVERY);
            ping.tick().await;
            loop {
                tokio::select! {
                    msg = out_rx.recv() => match msg {
                        Some(OutMsg::Text(txt)) => {
                            let len = txt.len();
                            let res = tokio::time::timeout(CONTROL_WRITE_TIMEOUT, ws_tx.send(Message::Text(txt.into()))).await;
                            client_writer.queued.fetch_sub(len, Ordering::SeqCst);
                            if !matches!(res, Ok(Ok(()))) {
                                let _ = ws_tx.send(Message::Close(Some(CloseFrame {
                                    code: CloseCode::Away,
                                    reason: "write failed".into(),
                                }))).await;
                                break;
                            }
                        }
                        Some(OutMsg::Close(code, reason)) => {
                            let _ = tokio::time::timeout(
                                CONTROL_WRITE_TIMEOUT,
                                ws_tx.send(Message::Close(Some(CloseFrame {
                                    code: CloseCode::from(code),
                                    reason: reason.into(),
                                }))),
                            ).await;
                            break;
                        }
                        None => break,
                    },
                    _ = ping.tick() => {
                        let res = tokio::time::timeout(CONTROL_WRITE_TIMEOUT, ws_tx.send(Message::Ping(Vec::new().into()))).await;
                        if !matches!(res, Ok(Ok(()))) {
                            break;
                        }
                    }
                }
            }
        });

        let mut tok = [0u8; 16];
        rand::rng().fill_bytes(&mut tok);
        client.write_value(&json!({
            "type": "welcome",
            "protocol": CONTROL_PROTOCOL,
            "limits": {"max_message_bytes": MAX_MESSAGE_BYTES},
            "client": {
                "id": client.id,
                "reconnect_token": URL_SAFE_NO_PAD.encode(tok),
                "resumed": false,
            },
            "api_revision": revision,
            "api_server_revision": API_REVISION,
            "api_min_revision": API_MIN_REVISION,
        }));

        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clients
            .insert(client.id.clone(), client.clone());
        self.joined(&client);

        while let Some(item) = ws_rx.next().await {
            match item {
                Ok(Message::Text(txt)) => {
                    let req: Value = match serde_json::from_str(&txt) {
                        Ok(v) => v,
                        Err(_) => {
                            client.close(1002, "protocol error");
                            break;
                        }
                    };
                    let id = req["id"].as_str().unwrap_or_default().to_string();
                    let method = req["method"].as_str().unwrap_or_default().to_string();
                    if id.is_empty() || method.is_empty() {
                        client.close(1002, "protocol error");
                        break;
                    }
                    let payload = req.get("payload").cloned().unwrap_or(Value::Null);
                    if let Some(sid) = payload.get("session_id").and_then(Value::as_str) {
                        client.remember_session(sid);
                    }
                    self.dispatch(&client, &id, &method, payload).await;
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                Ok(Message::Binary(_)) => {
                    client.close(1003, "protocol error");
                    break;
                }
                Ok(Message::Close(_)) | Ok(Message::Frame(_)) | Err(_) => break,
            }
        }

        let on_disc = {
            let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            st.clients.remove(&client.id);
            st.tickets.retain(|_, t| t.client_id != client.id);
            st.on_disconnect.clone()
        };
        self.left(&client);
        if let Some(cb) = on_disc {
            cb(client.clone());
        }
        client.close(CLOSE_NORMAL, "");
        let _ = writer_task.await;
    }

    async fn dispatch(&self, c: &Arc<RexClient>, id: &str, method: &str, payload: Value) {
        let handler = self.inner.lock().unwrap_or_else(|p| p.into_inner()).handlers.get(method).cloned();
        let seq = c.last_seq();
        let mut out = Map::new();
        out.insert("type".into(), Value::String("response".into()));
        out.insert("id".into(), Value::String(id.to_string()));
        out.insert("seq".into(), json!(seq));

        let Some(h) = handler else {
            eprintln!("rex: unknown method {method:?}");
            out.insert("error".into(), RexError::method_not_found(format!("unknown method {method}")).to_json());
            c.write_value(&Value::Object(out));
            return;
        };

        let res = match tokio::time::timeout(REQUEST_TIMEOUT, h(c.clone(), payload.clone())).await {
            Ok(r) => r,
            Err(_) => Err(RexError::new("timeout", format!("{method}: timed out"), 504)),
        };
        if self.trace {
            eprintln!("rex req client={} {} {} -> seq={} ok={}", c.id, id, method, seq, res.is_ok());
        }
        match res {
            Ok(val) => {
                out.insert("payload".into(), if val.is_null() { json!({}) } else { val });
            }
            Err(err) => {
                if err.code == CODE_CONFLICT || err.code == CODE_INTERNAL {
                    eprintln!("rex {method}: {err}");
                }
                out.insert("error".into(), err.to_json());
            }
        }
        let text = marshal_rex(&Value::Object(out.clone()));
        if text.len() > MAX_MESSAGE_BYTES {
            out.remove("payload");
            out.insert("error".into(), RexError::too_large("result exceeds the message limit").to_json());
            c.write_value(&Value::Object(out));
        } else {
            c.send_raw(text);
        }
    }

    async fn serve_data<S>(self: Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut negotiated = String::new();
        let ws_cfg = WebSocketConfig::default()
            .max_message_size(Some(MAX_UPLOAD_FRAME))
            .max_frame_size(Some(MAX_UPLOAD_FRAME));
        let ws = match tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            #[allow(clippy::result_large_err)]
            |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
                if let Some(proto) = pick_subprotocol(req, &[DATA_PROTOCOL, DATA_BYTES_PROTOCOL]) {
                    negotiated = proto.clone();
                    if let Ok(val) = proto.parse() {
                        resp.headers_mut().insert("sec-websocket-protocol", val);
                    }
                }
                Ok(resp)
            },
            Some(ws_cfg),
        )
        .await
        {
            Ok(ws) => ws,
            Err(_) => return,
        };

        let (mut ws_tx, mut ws_rx) = ws.split();
        let hello_bytes = match tokio::time::timeout(HANDSHAKE_TIMEOUT, ws_rx.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => b,
            _ => {
                reject_ws(&mut ws_tx, REJECT_MALFORMED, 1002).await;
                return;
            }
        };
        let Some(ticket_raw) = parse_data_hello(&hello_bytes) else {
            reject_ws(&mut ws_tx, REJECT_MALFORMED, 1002).await;
            return;
        };
        let Some(tk) = self.redeem(ticket_raw) else {
            reject_ws(&mut ws_tx, REJECT_UNKNOWN_TICKET, 1008).await;
            return;
        };
        if !tk.sub.is_empty() && negotiated != tk.sub {
            reject_ws(&mut ws_tx, REJECT_SUBPROTOCOL, 1002).await;
            return;
        }

        let mut token = [0u8; 16];
        let mut nb = [0u8; 8];
        rand::rng().fill_bytes(&mut token);
        rand::rng().fill_bytes(&mut nb);
        let nonce = u64::from_le_bytes(nb) | 1;
        let welcome = data_welcome(token, STREAM_KEEP_MS, nonce);
        if ws_tx.send(Message::Binary(welcome.into())).await.is_err() {
            return;
        }

        if let Some(upload_fn) = tk.upload {
            let (in_tx, in_rx) = mpsc::channel::<UploadChunk>(16);
            let (close_tx, mut close_rx) = mpsc::channel::<(u16, String)>(4);
            let reader = tokio::spawn(async move {
                let mut sent_end = false;
                while let Some(item) = ws_rx.next().await {
                    match item {
                        Ok(Message::Binary(b)) if b.is_empty() => {
                            let _ = in_tx.send(UploadChunk::HalfClose).await;
                            sent_end = true;
                            break;
                        }
                        Ok(Message::Binary(b)) => {
                            if in_tx.send(UploadChunk::Data(b.to_vec())).await.is_err() {
                                sent_end = true;
                                break;
                            }
                        }
                        Ok(Message::Close(Some(cf))) if cf.code == CloseCode::Normal => {
                            let _ = in_tx.send(UploadChunk::HalfClose).await;
                            sent_end = true;
                            break;
                        }
                        Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                        _ => {
                            let _ = in_tx.send(UploadChunk::Dropped).await;
                            sent_end = true;
                            break;
                        }
                    }
                }
                if !sent_end {
                    let _ = in_tx.send(UploadChunk::Dropped).await;
                }
            });
            let closer = tokio::spawn(async move {
                if let Some((code, reason)) = close_rx.recv().await {
                    let _ = tokio::time::timeout(
                        CONTROL_WRITE_TIMEOUT,
                        ws_tx.send(Message::Close(Some(CloseFrame {
                            code: CloseCode::from(code),
                            reason: reason.into(),
                        }))),
                    )
                    .await;
                    let _ = tokio::time::timeout(CONTROL_WRITE_TIMEOUT, ws_tx.flush()).await;
                }
            });
            let st = UploadStream {
                client: tk.client,
                request: tk.req,
                nonce,
                rx: in_rx,
                close_tx,
            };
            upload_fn(st).await;
            reader.abort();
            let _ = closer.await;
            return;
        }

        if let Some(serve_fn) = tk.serve {
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<DataCmd>(64);
            let (closed_tx, closed_rx) = tokio::sync::watch::channel(false);

            let reader_closed = closed_tx.clone();
            let reader = tokio::spawn(async move {
                while let Some(item) = ws_rx.next().await {
                    match item {
                        Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                        Ok(Message::Close(_)) | Err(_) => break,
                        _ => {}
                    }
                }
                let _ = reader_closed.send(true);
            });

            let writer_closed = closed_tx.clone();
            let writer = tokio::spawn(async move {
                let mut ping = tokio::time::interval(PING_EVERY);
                ping.tick().await;
                let mut closed_watch = writer_closed.subscribe();
                loop {
                    tokio::select! {
                        cmd = cmd_rx.recv() => match cmd {
                            Some(DataCmd::Bytes(b)) => {
                                let res = tokio::time::timeout(DATA_WRITE_TIMEOUT, ws_tx.send(Message::Binary(b.into()))).await;
                                if !matches!(res, Ok(Ok(()))) {
                                    break;
                                }
                            }
                            Some(DataCmd::Close(code, reason)) => {
                                let _ = tokio::time::timeout(
                                    CONTROL_WRITE_TIMEOUT,
                                    ws_tx.send(Message::Close(Some(CloseFrame {
                                        code: CloseCode::from(code),
                                        reason: reason.into(),
                                    }))),
                                ).await;
                                let _ = tokio::time::timeout(CONTROL_WRITE_TIMEOUT, ws_tx.flush()).await;
                                break;
                            }
                            None => break,
                        },
                        _ = ping.tick() => {
                            let res = tokio::time::timeout(CONTROL_WRITE_TIMEOUT, ws_tx.send(Message::Ping(Vec::new().into()))).await;
                            if !matches!(res, Ok(Ok(()))) {
                                break;
                            }
                        }
                        _ = closed_watch.changed() => {
                            if *closed_watch.borrow() {
                                break;
                            }
                        }
                    }
                }
                let _ = writer_closed.send(true);
            });

            let st = DataStream {
                client: tk.client,
                request: tk.req,
                nonce,
                tx: cmd_tx,
                closed_rx,
            };
            serve_fn(st).await;
            reader.abort();
            let _ = writer.await;
            let _ = closed_tx.send(true);
        }
    }
}

fn build_event_dropped(payload: &Value, size: usize) -> Value {
    let mut inner = Map::new();
    let top_type = payload.get("type").and_then(Value::as_str).unwrap_or_default();
    if top_type == "session_event" {
        let p = payload.get("payload");
        if let Some(sid) = p.and_then(|v| v.get("session_id")).and_then(Value::as_str)
            && !sid.is_empty()
        {
            inner.insert("session_id".into(), Value::String(sid.to_string()));
        }
        let ev = p.and_then(|v| v.get("event"));
        let ev_type = ev.and_then(|v| v.get("type")).and_then(Value::as_str).unwrap_or("session_event");
        inner.insert("event_type".into(), Value::String(ev_type.to_string()));
        if ev_type == "block_event"
            && let Some(bp) = ev.and_then(|v| v.get("payload"))
        {
            if let Some(bid) = bp.get("block_id").and_then(Value::as_str) {
                inner.insert("block_id".into(), Value::String(bid.to_string()));
            }
            if let Some(cn) = bp.get("creator_name").and_then(Value::as_str) {
                inner.insert("creator_name".into(), Value::String(cn.to_string()));
            }
            if let Some(name) = bp.get("name").and_then(Value::as_str) {
                inner.insert("block_event_name".into(), Value::String(name.to_string()));
            }
        }
    } else {
        inner.insert("event_type".into(), Value::String(top_type.to_string()));
    }
    inner.insert("size".into(), json!(size));
    json!({"type": "event_dropped", "payload": Value::Object(inner)})
}

async fn reject_ws<S>(ws_tx: &mut futures_util::stream::SplitSink<WebSocketStream<S>, Message>, reason: u8, code: u16)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        ws_tx.send(Message::Binary(data_reject(reason).into())),
    )
    .await;
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        ws_tx.send(Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: "data handshake rejected".into(),
        }))),
    )
    .await;
}

fn pick_subprotocol(req: &Request, supported: &[&str]) -> Option<String> {
    let hdr = req.headers().get("sec-websocket-protocol")?.to_str().ok()?;
    for item in hdr.split(',') {
        let p = item.trim();
        if supported.contains(&p) {
            return Some(p.to_string());
        }
    }
    None
}

fn make_principal(peer_addr: Option<&str>, is_unix: bool) -> Value {
    if is_unix {
        return json!({"kind": "anonymous", "transport": "unix", "display": "unix socket"});
    }
    let raw = peer_addr.unwrap_or("unknown");
    let host = raw
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or(raw);
    json!({"kind": "anonymous", "transport": "tcp", "display": host, "remote_addr": raw})
}

fn trusted_host(is_unix: bool, origin: &str, host: &str) -> bool {
    if origin.is_empty() || is_unix {
        return true;
    }
    let h = host
        .rsplit_once(':')
        .and_then(|(left, port)| if port.chars().all(|c| c.is_ascii_digit()) { Some(left) } else { None })
        .unwrap_or(host);
    let h = h.trim_matches(|c| c == '[' || c == ']').trim_end_matches('.').to_ascii_lowercase();
    h.parse::<IpAddr>().is_ok() || h == "localhost" || h.ends_with(".localhost")
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

async fn write_http_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    Ok(())
}

/// Replays already-read HTTP request header bytes before delegating reads to the underlying stream.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remain = &self.prefix[self.pos..];
            let n = remain.len().min(buf.remaining());
            buf.put_slice(&remain[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
