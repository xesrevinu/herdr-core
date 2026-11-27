//! Zero-socket in-process terminal hub over `wire::Conn`, PTY mode filtering,
//! OSC 52 extraction, Full screen paint, SGR mouse, scrollback, and data stream delivery.

use super::bridge::{
    BLOB_KIND_RESULT, BLOB_TTL_RESULT, DragState, MAX_CLIPBOARD_TEXT, RexBridge,
};
use super::proto::*;
use super::server::{DataStream, RexClient};
use crate::rpc::RpcError;
use crate::server::{call_internal, dispatch_frame_internal};
use crate::wire::{self, Conn};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

pub const SCREEN_HISTORY: usize = 2000;
pub const DEFAULT_CELL_W: u32 = 8;
pub const DEFAULT_CELL_H: u32 = 16;
const MAX_STREAM_BACKLOG: usize = 4 << 20;
const MAX_PENDING_CSI: usize = 64;
const MAX_PENDING_OSC: usize = 256 << 10;

pub const SHELL_MOUSE_MODE: &[u8] = b"\x1b[?1002l\x1b[?1003l\x1b[?1006l";
pub const TUI_MOUSE_MODE: &[u8] = b"\x1b[?1002l\x1b[?1003h\x1b[?1006h";
pub const BRACKETED_PASTE: &[u8] = b"\x1b[?2004h";
pub const FOCUS_REPORT: &[u8] = b"\x1b[?1004h";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermGridSize {
    pub cols: u16,
    pub rows: u16,
    pub cell_width_px: u32,
    pub cell_height_px: u32,
}

impl Default for TermGridSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24, cell_width_px: DEFAULT_CELL_W, cell_height_px: DEFAULT_CELL_H }
    }
}

#[derive(Debug, Clone)]
pub struct TermFrame {
    pub width: u16,
    pub height: u16,
    pub full: bool,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StreamMsg {
    pub frame: Option<TermFrame>,
    pub theme: Option<Map<String, Value>>,
    pub mouse: bool,
    pub code: u16,
    pub why: String,
    pub exited: bool,
    pub exit_code: i32,
}

impl StreamMsg {
    fn is_incremental(&self) -> bool {
        self.frame.as_ref().is_some_and(|f| !f.full && !f.bytes.is_empty())
            && self.theme.is_none()
            && !self.mouse
            && self.code == 0
    }
}

struct SubInner {
    q: VecDeque<StreamMsg>,
    queued: usize,
    closed: bool,
    wait_full: bool,
}

pub struct Sub {
    id: u64,
    inner: Mutex<SubInner>,
    wake: Notify,
}

static NEXT_SUB_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Sub {
    pub fn new(wait_full: bool) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_SUB_ID.fetch_add(1, Ordering::Relaxed),
            inner: Mutex::new(SubInner {
                q: VecDeque::new(),
                queued: 0,
                closed: false,
                wait_full,
            }),
            wake: Notify::new(),
        })
    }

    pub fn enqueue(&self, m: StreamMsg) -> bool {
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if st.closed {
            return false;
        }
        if m.code != 0 {
            st.q.push_back(m);
            st.closed = true;
            self.wake.notify_one();
            return false;
        }
        if m.is_incremental()
            && let Some(last) = st.q.back_mut()
            && last.is_incremental()
            && let (Some(lf), Some(mf)) = (&mut last.frame, &m.frame)
            && lf.width == mf.width
            && lf.height == mf.height
        {
            lf.bytes.extend_from_slice(&mf.bytes);
            st.queued += mf.bytes.len();
            self.wake.notify_one();
            return trim_locked(&mut st, &self.wake);
        }
        if m.frame.as_ref().is_some_and(|f| f.full) {
            let mut kept = VecDeque::with_capacity(st.q.len());
            let mut dropped = 0usize;
            for item in st.q.drain(..) {
                if item.is_incremental() {
                    if let Some(f) = &item.frame {
                        dropped += f.bytes.len();
                    }
                    continue;
                }
                kept.push_back(item);
            }
            st.queued = st.queued.saturating_sub(dropped);
            st.q = kept;
        }
        if let Some(f) = &m.frame {
            st.queued += f.bytes.len();
        }
        st.q.push_back(m);
        self.wake.notify_one();
        trim_locked(&mut st, &self.wake)
    }

    pub async fn recv(&self) -> Option<StreamMsg> {
        loop {
            {
                let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(m) = st.q.pop_front() {
                    if let Some(f) = &m.frame {
                        st.queued = st.queued.saturating_sub(f.bytes.len());
                    }
                    return Some(m);
                }
                if st.closed {
                    return None;
                }
            }
            self.wake.notified().await;
        }
    }
}

fn trim_locked(st: &mut SubInner, wake: &Notify) -> bool {
    if st.queued <= MAX_STREAM_BACKLOG {
        return false;
    }
    st.q.clear();
    st.q.push_back(StreamMsg {
        frame: None,
        theme: None,
        mouse: false,
        code: CLOSE_RECONNECT_REQUIRED,
        why: "data reconnect required".into(),
        exited: false,
        exit_code: 0,
    });
    st.queued = 0;
    st.closed = true;
    wake.notify_one();
    true
}

struct HubInner {
    subs: HashMap<u64, Arc<Sub>>,
    size: TermGridSize,
    mouse: bool,
    alt: bool,
    focus: bool,
    paste: bool,
    pty_pending: Vec<u8>,
    osc52: Vec<u8>,
    /// Lightweight zero-scrollback VT mirror for remote panes (local panes
    /// read `core.lock().screens` directly). Tracks DEC modes & Kitty keyboard.
    remote_vt: Option<ghostty_vt::Terminal>,
}

pub struct Hub {
    pub bridge: Arc<RexBridge>,
    pub pane: String,
    pub conn: Arc<Conn>,
    pub channel: u32,
    pub control: bool,
    pub closing: AtomicBool,
    done_tx: tokio::sync::watch::Sender<bool>,
    inner: Mutex<HubInner>,
}

impl Hub {
    pub fn current(&self) -> TermGridSize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).size
    }

    pub fn reports_mouse(&self) -> bool {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).mouse
    }

    pub fn on_alt_screen(&self) -> bool {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).alt
    }

    pub fn wants_paste(&self) -> bool {
        let fallback = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(vt) = inner.remote_vt.as_ref() {
                return vt.dec_mode(2004);
            }
            inner.paste
        };
        if let Some(id) = crate::terminals::parse_id(&self.pane) {
            let st = self.bridge.core.lock();
            if let Some(screen) = st.screens.get(&id) {
                return screen.dec_mode(2004);
            }
        }
        fallback
    }

    pub fn encode_key_event(&self, ev: &super::term::RexKeyEvent) -> Option<Vec<u8>> {
        {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(vt) = inner.remote_vt.as_ref() {
                return Some(vt.encode_key_event(
                    ev.action,
                    ev.key,
                    ev.mods,
                    ev.consumed_mods,
                    ev.composing,
                    &ev.text,
                    ev.unshifted,
                    ev.option_as_alt,
                ));
            }
        }
        if let Some(id) = crate::terminals::parse_id(&self.pane) {
            let st = self.bridge.core.lock();
            if let Some(screen) = st.screens.get(&id) {
                return Some(screen.encode_key_event(
                    ev.action,
                    ev.key,
                    ev.mods,
                    ev.consumed_mods,
                    ev.composing,
                    &ev.text,
                    ev.unshifted,
                    ev.option_as_alt,
                ));
            }
        }
        None
    }

    pub fn write_input(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        dispatch_frame_internal(&self.bridge.core, &self.conn, self.channel, wire::DATA, data);
    }

    pub fn send_focus(&self, focused: bool) {
        let b = [u8::from(focused)];
        dispatch_frame_internal(&self.bridge.core, &self.conn, self.channel, wire::FOCUS, &b);
    }

    pub fn apply_size(&self, s: TermGridSize) {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if inner.size == s {
                return;
            }
            inner.size = s;
        }
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&s.cols.to_le_bytes());
        buf[2..4].copy_from_slice(&s.rows.to_le_bytes());
        dispatch_frame_internal(&self.bridge.core, &self.conn, self.channel, wire::RESIZE, &buf);
    }

    pub fn send_theme(&self, theme: Map<String, Value>) {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        for s in inner.subs.values() {
            s.enqueue(StreamMsg {
                frame: None,
                theme: Some(theme.clone()),
                mouse: false,
                code: 0,
                why: String::new(),
                exited: false,
                exit_code: 0,
            });
        }
    }

    pub fn push_full(&self, frame: TermFrame) {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        for s in inner.subs.values() {
            s.inner.lock().unwrap_or_else(|p| p.into_inner()).wait_full = false;
            s.enqueue(StreamMsg {
                frame: Some(frame.clone()),
                theme: None,
                mouse: false,
                code: 0,
                why: String::new(),
                exited: false,
                exit_code: 0,
            });
        }
    }

    pub fn fanout(&self, frame: TermFrame) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut lagged = Vec::new();
        for (&id, s) in &inner.subs {
            {
                let mut sst = s.inner.lock().unwrap_or_else(|p| p.into_inner());
                if sst.wait_full && !frame.full {
                    continue;
                }
                sst.wait_full = false;
            }
            if s.enqueue(StreamMsg {
                frame: Some(frame.clone()),
                theme: None,
                mouse: false,
                code: 0,
                why: String::new(),
                exited: false,
                exit_code: 0,
            }) {
                lagged.push(id);
            }
        }
        for id in lagged {
            inner.subs.remove(&id);
            eprintln!("rex terminal {}: data stream lagged, reconnecting", self.pane);
        }
    }

    fn note_size(&self, cols: u16, rows: u16) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.size.cols = cols;
        inner.size.rows = rows;
        if let Some(vt) = inner.remote_vt.as_mut() {
            vt.resize(cols, rows);
        }
    }

    fn apply_pty_note(&self, note: PtyNote) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(m) = note.mouse
            && inner.mouse != m
        {
            inner.mouse = m;
            for s in inner.subs.values() {
                s.enqueue(StreamMsg {
                    frame: None,
                    theme: None,
                    mouse: true,
                    code: 0,
                    why: String::new(),
                    exited: false,
                    exit_code: 0,
                });
            }
        }
        if let Some(a) = note.alt {
            inner.alt = a;
        }
        if let Some(f) = note.focus {
            inner.focus = f;
        }
        if let Some(p) = note.paste {
            inner.paste = p;
        }
    }

    pub fn send_mouse(&self, m: MouseInput) {
        let b = sgr_mouse(m);
        if !b.is_empty() {
            self.write_input(&b);
        }
    }

    pub fn send_arrows(&self, lines: i32) {
        if lines == 0 {
            return;
        }
        let seq = if lines < 0 { b"\x1b[A" } else { b"\x1b[B" };
        let count = lines.unsigned_abs().min(32) as usize;
        let mut buf = Vec::with_capacity(count * 3);
        for _ in 0..count {
            buf.extend_from_slice(seq);
        }
        self.write_input(&buf);
    }

    async fn run_core(self: Arc<Self>) {
        let mut reason = "closed".to_string();
        let mut code = CLOSE_RECONNECT_REQUIRED;
        let mut why = "data reconnect required".to_string();
        let mut exited = false;
        let mut exit_code = 0i32;

        'outer: loop {
            self.bridge.core.prepare_repaints(&self.conn);
            let mut got_any = false;
            loop {
                let next = self.conn.outbox().next_frame();
                let Some(frame) = next else { break };
                got_any = true;
                if frame.len() < wire::HEADER {
                    continue;
                }
                let ch = u32::from_le_bytes(frame[0..4].try_into().unwrap());
                let kind = frame[4];
                let payload = &frame[wire::HEADER..];
                if ch != self.channel {
                    continue;
                }
                match kind {
                    wire::CLOSE => {
                        if let Ok(end) = serde_json::from_slice::<Value>(payload) {
                            let r = end["reason"].as_str().unwrap_or_default();
                            match r {
                                "exited" | "killed" | "signaled" => {
                                    reason = r.to_string();
                                    code = CLOSE_BLOCK_CLOSED;
                                    why = "block closed".into();
                                    exited = true;
                                    exit_code = end["exit_code"].as_i64().unwrap_or(0) as i32;
                                }
                                other if !other.is_empty() => {
                                    reason = other.to_string();
                                }
                                _ => {}
                            }
                        }
                        break 'outer;
                    }
                    wire::RESIZE => {
                        if payload.len() >= 4 {
                            let cols = u16::from_le_bytes([payload[0], payload[1]]);
                            let rows = u16::from_le_bytes([payload[2], payload[3]]);
                            self.note_size(cols, rows);
                            self.fanout(TermFrame { width: cols, height: rows, full: false, bytes: Vec::new() });
                        }
                    }
                    wire::DATA => {
                        if !payload.is_empty() {
                            let credit = (payload.len() as u32).to_le_bytes();
                            dispatch_frame_internal(&self.bridge.core, &self.conn, self.channel, wire::CREDIT, &credit);
                        }
                        let (filtered, note, clips) = {
                            let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                            if let Some(vt) = inner.remote_vt.as_mut() {
                                vt.write(payload);
                                let _ = vt.take_responses();
                            }
                            let pending = std::mem::take(&mut inner.pty_pending);
                            let (filtered, rest, note) = feed_pty_modes(&pending, payload);
                            inner.pty_pending = rest;
                            let osc_pending = std::mem::take(&mut inner.osc52);
                            let (filtered, osc_rest, clips) = take_osc52(&osc_pending, &filtered);
                            inner.osc52 = osc_rest;
                            (filtered, note, clips)
                        };
                        self.apply_pty_note(note);
                        if filtered.contains(&b'\x07') {
                            self.bridge.pane_bell(&self.pane);
                        }
                        for data in clips {
                            self.bridge.pane_clipboard(&self.pane, &data);
                        }
                        if !filtered.is_empty() {
                            let sz = self.current();
                            self.fanout(TermFrame { width: sz.cols, height: sz.rows, full: false, bytes: filtered });
                        }
                    }
                    _ => {}
                }
            }
            if self.closing.load(Ordering::SeqCst) {
                break;
            }
            if !got_any {
                self.conn.wake.notified().await;
            }
        }

        // Clean up Core viewer registration
        self.bridge.core.detach(&self.conn, Some(self.channel));
        crate::remote::conn_gone(&self.bridge.core, &self.conn);
        self.conn.gone.store(true, Ordering::SeqCst);
        let _ = self.done_tx.send(true);
        {
            let mut hubs = self.bridge.hubs.lock().unwrap_or_else(|p| p.into_inner());
            if hubs.get(&self.pane).is_some_and(|cur| Arc::ptr_eq(cur, &self)) {
                hubs.remove(&self.pane);
            }
        }
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        eprintln!("rex terminal {}: ended ({reason})", self.pane);
        let subs: Vec<Arc<Sub>> = {
            let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            inner.subs.drain().map(|(_, s)| s).collect()
        };
        for s in subs {
            s.enqueue(StreamMsg {
                frame: None,
                theme: None,
                mouse: false,
                code,
                why: why.clone(),
                exited,
                exit_code,
            });
        }
    }
}

impl RexBridge {
    pub fn hub(&self, pane: &str) -> Option<Arc<Hub>> {
        self.hubs.lock().unwrap_or_else(|p| p.into_inner()).get(pane).cloned()
    }

    pub fn layout_size(&self, pane: &str) -> TermGridSize {
        if let Some(t) = self.live_term(pane)
            && t.cols > 0
            && t.rows > 0
        {
            return TermGridSize {
                cols: t.cols as u16,
                rows: t.rows as u16,
                cell_width_px: DEFAULT_CELL_W,
                cell_height_px: DEFAULT_CELL_H,
            };
        }
        let (cols, rows) = self.pane_size(pane);
        TermGridSize {
            cols: cols as u16,
            rows: rows as u16,
            cell_width_px: DEFAULT_CELL_W,
            cell_height_px: DEFAULT_CELL_H,
        }
    }

    pub fn pane_size(&self, pane: &str) -> (i32, i32) {
        if let Some(s) = self.snapshot() {
            for l in &s.layouts {
                for x in &l.panes {
                    if x.pane_id == pane {
                        return (x.rect.width.max(1), x.rect.height.max(1));
                    }
                }
            }
        }
        (80, 24)
    }

    pub fn owner_desired(&self, block: &str) -> Option<TermGridSize> {
        let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let owner = st.owners.get(block).map(String::as_str).unwrap_or_default();
        let list = st.desired.get(block)?;
        for d in list {
            if owner.is_empty() || d.client == owner {
                return Some(d.size);
            }
        }
        None
    }

    pub async fn join_hub(self: &Arc<Self>, pane: &str, block: &str) -> Result<(Arc<Hub>, Arc<Sub>), RpcError> {
        let _guard = self.hub_mu.lock().await;
        if let Some(h) = self.hub(pane) {
            let s = Sub::new(true);
            let size = {
                let mut inner = h.inner.lock().unwrap_or_else(|p| p.into_inner());
                inner.subs.insert(s.id, s.clone());
                inner.size
            };
            drop(_guard);
            self.align_host_viewport(pane).await;
            let frame = self.screen_frame(pane, size).await;
            {
                let inner = h.inner.lock().unwrap_or_else(|p| p.into_inner());
                if inner.subs.contains_key(&s.id) {
                    s.inner.lock().unwrap_or_else(|p| p.into_inner()).wait_full = false;
                    s.enqueue(StreamMsg {
                        frame: Some(frame),
                        theme: None,
                        mouse: false,
                        code: 0,
                        why: String::new(),
                        exited: false,
                        exit_code: 0,
                    });
                }
            }
            return Ok((h, s));
        }

        let mut size = self.owner_desired(block).unwrap_or_else(|| self.layout_size(pane));
        let conn = Arc::new(Conn::default());
        let mut observe = self.observe;
        let attach_params = |obs: bool| {
            json!({
                "terminal": pane,
                "cols": size.cols,
                "rows": size.rows,
                "history": SCREEN_HISTORY,
                "observe": obs,
                "resize_notifications": true,
            })
        };
        let res = match call_internal(&self.core, Some(&conn), "terminal.attach", attach_params(observe)).await {
            Ok(v) => v,
            Err(e) if !observe && e.kind != "not_found" && e.kind != "finished" => {
                eprintln!("rex terminal {pane}: control attach failed ({}), observing", e.message);
                observe = true;
                call_internal(&self.core, Some(&conn), "terminal.attach", attach_params(true)).await?
            }
            Err(e) => return Err(e),
        };
        let channel = res["channel"].as_u64().unwrap_or(0) as u32;
        if channel == 0 {
            return Err(RpcError::internal("attach returned channel 0"));
        }
        if let Some(c) = res["terminal"]["cols"].as_u64()
            && c > 0
        {
            size.cols = c as u16;
        }
        if let Some(r) = res["terminal"]["rows"].as_u64()
            && r > 0
        {
            size.rows = r as u16;
        }
        conn.with(|out| out.resume(channel));
        if !observe {
            dispatch_frame_internal(&self.core, &conn, channel, wire::FOCUS, &[1]);
        }
        self.align_host_viewport(pane).await;
        eprintln!("rex terminal {pane}: attached (in-core control={}) {}x{}", !observe, size.cols, size.rows);

        let (done_tx, _) = tokio::sync::watch::channel(false);
        let s = Sub::new(false);
        let mut subs = HashMap::new();
        subs.insert(s.id, s.clone());
        let remote_vt = (!super::appdoc::machine_of(pane).is_empty())
            .then(|| ghostty_vt::Terminal::new(size.cols.max(1), size.rows.max(1), 0));
        let h = Arc::new(Hub {
            bridge: self.clone(),
            pane: pane.to_string(),
            conn,
            channel,
            control: !observe,
            closing: AtomicBool::new(false),
            done_tx,
            inner: Mutex::new(HubInner {
                subs,
                size,
                mouse: false,
                alt: false,
                focus: false,
                paste: false,
                pty_pending: Vec::new(),
                osc52: Vec::new(),
                remote_vt,
            }),
        });
        self.hubs.lock().unwrap_or_else(|p| p.into_inner()).insert(pane.to_string(), h.clone());
        tokio::spawn(h.clone().run_core());
        Ok((h, s))
    }

    pub async fn leave_hub(&self, h: &Arc<Hub>, s: &Arc<Sub>) {
        let last = {
            let _guard = self.hub_mu.lock().await;
            let remaining = {
                let mut inner = h.inner.lock().unwrap_or_else(|p| p.into_inner());
                inner.subs.remove(&s.id);
                inner.subs.len()
            };
            let mut hubs = self.hubs.lock().unwrap_or_else(|p| p.into_inner());
            if remaining == 0 && hubs.get(&h.pane).is_some_and(|cur| Arc::ptr_eq(cur, h)) {
                hubs.remove(&h.pane);
                true
            } else {
                false
            }
        };
        if !last {
            return;
        }
        h.closing.store(true, Ordering::SeqCst);
        dispatch_frame_internal(&self.core, &h.conn, h.channel, wire::CLOSE, &[]);
        h.conn.wake.notify_one();
        let mut done_rx = h.done_tx.subscribe();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while !*done_rx.borrow() {
                if done_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        eprintln!("rex terminal {}: detached", h.pane);
    }

    pub async fn serve_terminal_stream(self: Arc<Self>, pane: String, mut st: DataStream) {
        if st.send(BLANK_SNAPSHOT).await.is_err() {
            return;
        }
        eprintln!("rex data stream open: pane {pane}");
        let block = self.ids.rex("block", &pane);
        let (h, s) = match self.join_hub(&pane, &block).await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("rex terminal {pane}: {}", err.message);
                if matches!(err.kind.as_str(), "not_found" | "finished")
                    || err.message.contains("not found")
                {
                    st.close(CLOSE_BLOCK_CLOSED, "block closed").await;
                } else {
                    st.close(CLOSE_PROVIDER_FAILED, "data provider failed").await;
                }
                eprintln!("rex data stream closed: pane {pane}");
                return;
            }
        };

        if st.send(BRACKETED_PASTE).await.is_err() || st.send(FOCUS_REPORT).await.is_err() {
            self.leave_hub(&h, &s).await;
            eprintln!("rex data stream closed: pane {pane}");
            return;
        }

        let mut w: u16 = 0;
        let mut ht: u16 = 0;
        let mut cell_w: u32 = 0;
        let mut cell_h: u32 = 0;
        let mut themed = false;
        let mut mouse_mode: Option<&'static [u8]> = None;

        loop {
            let msg = tokio::select! {
                m = s.recv() => m,
                _ = st.wait_closed() => None,
            };
            if st.is_closed() {
                break;
            }
            let Some(m) = msg else {
                st.close(CLOSE_RECONNECT_REQUIRED, "data reconnect required").await;
                break;
            };
            if let Some(theme) = m.theme {
                if w != 0 && st.send(&apc_theme(st.nonce, &theme)).await.is_err() {
                    break;
                }
                continue;
            }
            if m.mouse {
                if w != 0 && h.control {
                    let want = if h.reports_mouse() { TUI_MOUSE_MODE } else { SHELL_MOUSE_MODE };
                    if mouse_mode != Some(want) {
                        mouse_mode = Some(want);
                        if st.send(want).await.is_err() {
                            break;
                        }
                    }
                }
                continue;
            }
            let Some(f) = m.frame else {
                if m.exited {
                    let _ = st.send(&apc_child_exited(st.nonce, m.exit_code)).await;
                }
                st.close(m.code, &m.why).await;
                break;
            };
            let cs = h.current();
            if f.width != w || f.height != ht || cs.cell_width_px != cell_w || cs.cell_height_px != cell_h {
                w = f.width;
                ht = f.height;
                cell_w = cs.cell_width_px;
                cell_h = cs.cell_height_px;
                let owner = self.owner(&block);
                let owner_opt = if owner.is_empty() { None } else { Some(owner.as_str()) };
                let r = apc_resize(st.nonce, w, ht, cell_w, cell_h, owner_opt);
                if st.send(&r).await.is_err() {
                    break;
                }
            }
            if !themed {
                themed = true;
                if let Some(t) = self.theme(&block)
                    && st.send(&apc_theme(st.nonce, &t)).await.is_err()
                {
                    break;
                }
            }
            if h.control {
                let want = if h.reports_mouse() { TUI_MOUSE_MODE } else { SHELL_MOUSE_MODE };
                if mouse_mode != Some(want) {
                    mouse_mode = Some(want);
                    if st.send(want).await.is_err() {
                        break;
                    }
                }
            }
            if !f.bytes.is_empty() && st.send(&f.bytes).await.is_err() {
                break;
            }
        }

        self.leave_hub(&h, &s).await;
        eprintln!("rex data stream closed: pane {pane}");
    }

    pub async fn screen_frame(&self, pane: &str, mut size: TermGridSize) -> TermFrame {
        if size.cols < 1 {
            size.cols = 80;
        }
        if size.rows < 1 {
            size.rows = 24;
        }
        if let Ok(v) = call_internal(
            &self.core,
            None,
            "terminal.paint",
            json!({"terminal": pane, "history": SCREEN_HISTORY}),
        )
        .await
            && let Some(vt) = v["vt"].as_str()
            && !vt.is_empty()
        {
            if let Some(c) = v["cols"].as_u64()
                && c > 0
            {
                size.cols = c as u16;
            }
            if let Some(r) = v["rows"].as_u64()
                && r > 0
            {
                size.rows = r as u16;
            }
            return TermFrame {
                width: size.cols,
                height: size.rows,
                full: true,
                bytes: finalize_paint(vt.as_bytes()),
            };
        }
        let text = call_internal(
            &self.core,
            None,
            "terminal.read",
            json!({"terminal": pane, "lines": SCREEN_HISTORY}),
        )
        .await
        .ok()
        .and_then(|v| v["text"].as_str().map(String::from))
        .unwrap_or_default();
        TermFrame {
            width: size.cols,
            height: size.rows,
            full: true,
            bytes: paint_screen(&text, size),
        }
    }

    pub async fn unscroll(&self, pane: &str) {
        {
            let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            if st.scroll_sync.contains(pane) && st.scroll_off.get(pane).copied().unwrap_or(0) == 0 {
                return;
            }
        }
        if let Ok(v) = call_internal(&self.core, None, "terminal.unscroll", json!({"terminal": pane})).await {
            self.remember_scroll_val(pane, &v);
        }
    }

    pub async fn align_host_viewport(&self, pane: &str) {
        if let Ok(v) = call_internal(&self.core, None, "terminal.unscroll", json!({"terminal": pane})).await {
            self.remember_scroll_val(pane, &v);
        }
    }

    pub fn remember_scroll_val(&self, pane: &str, v: &Value) {
        let off = v["offset_from_bottom"].as_u64().unwrap_or(0) as u32;
        let top = v["view_top"].as_u64().unwrap_or(0) as u32;
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        st.scroll_sync.insert(pane.to_string());
        if off == 0 {
            st.scroll_off.remove(pane);
        } else {
            st.scroll_off.insert(pane.to_string(), off);
        }
        st.view_top.insert(pane.to_string(), top);
    }

    pub fn note_drag_view_top(&self, pane: &str, view_top: u32) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        for ((_, p), d) in &mut st.drags {
            if p == pane {
                d.view_top = view_top;
            }
        }
    }

    pub async fn fresh_view_top(&self, pane: &str) -> u32 {
        match call_internal(&self.core, None, "terminal.scroll", json!({"terminal": pane})).await {
            Ok(v) => {
                self.remember_scroll_val(pane, &v);
                v["view_top"].as_u64().unwrap_or(0) as u32
            }
            Err(_) => self.st.lock().unwrap_or_else(|p| p.into_inner()).view_top.get(pane).copied().unwrap_or(0),
        }
    }

    pub async fn scroll_by(&self, pane: &str, lines: i32) -> Result<(), RexError> {
        if lines == 0 {
            return Ok(());
        }
        let synced = self.st.lock().unwrap_or_else(|p| p.into_inner()).scroll_sync.contains(pane);
        if !synced {
            let v = call_internal(&self.core, None, "terminal.scroll", json!({"terminal": pane})).await?;
            self.remember_scroll_val(pane, &v);
        }
        let cur = self.st.lock().unwrap_or_else(|p| p.into_inner()).scroll_off.get(pane).copied().unwrap_or(0) as i64;
        let off = (cur - lines as i64).max(0) as u32;
        let v = call_internal(
            &self.core,
            None,
            "terminal.scroll",
            json!({"terminal": pane, "offset_from_bottom": off}),
        )
        .await?;
        self.remember_scroll_val(pane, &v);
        self.note_drag_view_top(pane, v["view_top"].as_u64().unwrap_or(0) as u32);
        Ok(())
    }

    pub async fn select_drag(&self, c: &RexClient, pane: &str, m: MouseInput) -> Result<(), RexError> {
        let key = (c.id.clone(), pane.to_string());
        if m.kind == MouseKind::Drag {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(d) = st.drags.get_mut(&key) {
                d.last = [d.view_top.saturating_add(m.row as u32), m.column as u32];
                d.moved = true;
            }
            return Ok(());
        }
        if m.kind == MouseKind::Down {
            let top = self.fresh_view_top(pane).await;
            let at = [top.saturating_add(m.row as u32), m.column as u32];
            self.st.lock().unwrap_or_else(|p| p.into_inner()).drags.insert(
                key,
                DragState { anchor: at, last: at, view_top: top, moved: false },
            );
            return Ok(());
        }
        let d = self.st.lock().unwrap_or_else(|p| p.into_inner()).drags.remove(&key);
        let Some(d) = d else { return Ok(()) };
        let at = [d.view_top.saturating_add(m.row as u32), m.column as u32];
        let mut from = d.anchor;
        let mut to = if from == at {
            if !d.moved {
                return Ok(());
            }
            d.last
        } else {
            at
        };
        let cols = self
            .hub(pane)
            .map(|h| h.current().cols as i32)
            .unwrap_or_else(|| self.pane_size(pane).0);
        let last_col = (cols - 1).max(0) as u32;
        if to[0] < from[0] || (to[0] == from[0] && to[1] < from[1]) {
            std::mem::swap(&mut from, &mut to);
            if to[1] > 0 {
                to[1] -= 1;
            } else if to[0] > 0 {
                to = [to[0] - 1, last_col];
            }
        }
        from[1] = from[1].min(last_col);
        to[1] = to[1].min(last_col);

        let text = match call_internal(
            &self.core,
            None,
            "terminal.selection_read",
            json!({
                "terminal": pane,
                "start_row": from[0],
                "start_col": from[1],
                "end_row": to[0],
                "end_col": to[1],
            }),
        )
        .await
        {
            Ok(v) => v["text"].as_str().unwrap_or_default().to_string(),
            Err(e) => {
                let max_off = call_internal(&self.core, None, "terminal.scroll", json!({"terminal": pane}))
                    .await
                    .ok()
                    .and_then(|v| v["max_offset_from_bottom"].as_u64())
                    .unwrap_or(0);
                let dump = call_internal(
                    &self.core,
                    None,
                    "terminal.read",
                    json!({"terminal": pane, "lines": max_off}),
                )
                .await
                .map_err(|_| RexError::from(e))?;
                crop_visible(dump["text"].as_str().unwrap_or_default(), from, to, 0)
            }
        };
        if text.is_empty() {
            return Ok(());
        }
        let Some(sid) = self.pane_session(pane) else { return Ok(()) };
        let id = self.put_blob(BLOB_KIND_RESULT, text.clone(), BLOB_TTL_RESULT);
        let mut ev = Map::new();
        ev.insert("bytes".into(), json!(text.len()));
        ev.insert("id".into(), json!(id));
        if text.len() <= MAX_CLIPBOARD_TEXT {
            ev.insert("text".into(), Value::String(text));
        }
        c.session_event(
            &sid,
            "block_event",
            json!({
                "block_id": self.ids.rex("block", pane),
                "creator_name": TERMINAL_CREATOR,
                "name": "selection_copied",
                "payload": Value::Object(ev),
            }),
        );
        Ok(())
    }

    pub async fn inject_bytes(&self, pane: &str, data: &[u8]) -> Result<(), RexError> {
        if let Some(h) = self.hub(pane) {
            h.write_input(data);
            return Ok(());
        }
        if data.is_empty() {
            return Ok(());
        }
        let sz = self.layout_size(pane);
        let conn = Arc::new(Conn::default());
        let res = call_internal(
            &self.core,
            Some(&conn),
            "terminal.attach",
            json!({"terminal": pane, "cols": sz.cols, "rows": sz.rows, "history": 0, "observe": false}),
        )
        .await?;
        let ch = res["channel"].as_u64().unwrap_or(0) as u32;
        if ch != 0 {
            dispatch_frame_internal(&self.core, &conn, ch, wire::DATA, data);
            dispatch_frame_internal(&self.core, &conn, ch, wire::CLOSE, &[]);
        }
        self.core.detach(&conn, None);
        crate::remote::conn_gone(&self.core, &conn);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct PtyNote {
    pub mouse: Option<bool>,
    pub alt: Option<bool>,
    pub focus: Option<bool>,
    pub paste: Option<bool>,
}

/// Filters PTY bytes for Rex.app: strips mouse/focus/paste DECSET so Rex stays
/// controlled by herdrex, records mode transitions, and reasserts paste/focus
/// after RIS (`\x1bc`) and DECSTR (`\x1b[!p`). Never disables autowrap.
pub fn feed_pty_modes(pending: &[u8], chunk: &[u8]) -> (Vec<u8>, Vec<u8>, PtyNote) {
    let mut buf = Vec::with_capacity(pending.len() + chunk.len());
    buf.extend_from_slice(pending);
    buf.extend_from_slice(chunk);
    let mut out = Vec::with_capacity(buf.len());
    let mut note = PtyNote::default();
    let mut i = 0;
    while i < buf.len() {
        let Some(rel) = buf[i..].iter().position(|&b| b == 0x1b) else {
            out.extend_from_slice(&buf[i..]);
            return (out, Vec::new(), note);
        };
        let esc = i + rel;
        out.extend_from_slice(&buf[i..esc]);
        let remain = &buf[esc..];
        if remain.len() < 2 {
            return (out, cap_pending(remain), note);
        }
        if remain[1] == b'c' {
            note.mouse = Some(false);
            note.alt = Some(false);
            note.focus = Some(false);
            note.paste = Some(false);
            out.extend_from_slice(&remain[..2]);
            out.extend_from_slice(BRACKETED_PASTE);
            out.extend_from_slice(FOCUS_REPORT);
            i = esc + 2;
            continue;
        }
        if remain[1] != b'[' {
            out.push(remain[0]);
            i = esc + 1;
            continue;
        }
        if remain.len() < 3 {
            return (out, cap_pending(remain), note);
        }
        if remain[2] == b'!' {
            if remain.len() < 4 {
                return (out, cap_pending(remain), note);
            }
            if remain[3] == b'p' {
                note.mouse = Some(false);
                note.alt = Some(false);
                note.focus = Some(false);
                note.paste = Some(false);
                out.extend_from_slice(&remain[..4]);
                out.extend_from_slice(BRACKETED_PASTE);
                out.extend_from_slice(FOCUS_REPORT);
                i = esc + 4;
                continue;
            }
            out.extend_from_slice(&remain[..3]);
            i = esc + 3;
            continue;
        }
        if remain[2] != b'?' {
            out.extend_from_slice(&remain[..2]);
            i = esc + 2;
            continue;
        }
        let mut j = 3;
        while j < remain.len() && (remain[j].is_ascii_digit() || remain[j] == b';') {
            j += 1;
        }
        if j >= remain.len() {
            return (out, cap_pending(remain), note);
        }
        let final_b = remain[j];
        if final_b != b'h' && final_b != b'l' {
            out.extend_from_slice(&remain[..=j]);
            i = esc + j + 1;
            continue;
        }
        let on = final_b == b'h';
        let mut keep = Vec::new();
        for part in remain[3..j].split(|&b| b == b';') {
            if let Ok(s) = std::str::from_utf8(part)
                && let Ok(m) = s.parse::<u32>()
            {
                match m {
                    9 | 1000 | 1002 | 1003 => note.mouse = Some(on),
                    1005 | 1006 | 1015 | 1016 => {}
                    1004 => note.focus = Some(on),
                    2004 => note.paste = Some(on),
                    47 | 1047 | 1049 => {
                        note.alt = Some(on);
                        keep.push(m);
                    }
                    _ => keep.push(m),
                }
            }
        }
        if !keep.is_empty() {
            out.extend_from_slice(b"\x1b[?");
            for (k, m) in keep.iter().enumerate() {
                if k > 0 {
                    out.push(b';');
                }
                out.extend_from_slice(m.to_string().as_bytes());
            }
            out.push(final_b);
        }
        i = esc + j + 1;
    }
    (out, Vec::new(), note)
}

fn cap_pending(p: &[u8]) -> Vec<u8> {
    if p.len() <= MAX_PENDING_CSI { p.to_vec() } else { Vec::new() }
}

pub fn take_osc52(pending: &[u8], chunk: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<String>) {
    let mut buf = Vec::with_capacity(pending.len() + chunk.len());
    buf.extend_from_slice(pending);
    buf.extend_from_slice(chunk);
    let mut out = Vec::with_capacity(buf.len());
    let mut copies = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let Some(rel) = buf[i..].windows(2).position(|w| w == [0x1b, b']']) else {
            out.extend_from_slice(&buf[i..]);
            return (out, Vec::new(), copies);
        };
        let j = i + rel;
        out.extend_from_slice(&buf[i..j]);
        let Some(end) = osc_end(&buf[j..]) else {
            let rem = &buf[j..];
            if rem.len() > MAX_PENDING_OSC {
                out.extend_from_slice(rem);
                return (out, Vec::new(), copies);
            }
            return (out, rem.to_vec(), copies);
        };
        let seq = &buf[j..j + end];
        out.extend_from_slice(seq);
        if let Some(data) = parse_osc52(seq) {
            copies.push(data);
        }
        i = j + end;
    }
    (out, Vec::new(), copies)
}

fn osc_end(b: &[u8]) -> Option<usize> {
    if b.len() < 2 || b[0] != 0x1b || b[1] != b']' {
        return None;
    }
    let mut i = 2;
    while i < b.len() {
        if b[i] == 0x07 {
            return Some(i + 1);
        }
        if b[i] == 0x1b && i + 1 < b.len() && b[i + 1] == b'\\' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

fn parse_osc52(seq: &[u8]) -> Option<String> {
    if seq.len() < 5 || seq[0] != 0x1b || seq[1] != b']' {
        return None;
    }
    let mut body = &seq[2..];
    if body.ends_with(&[0x07]) {
        body = &body[..body.len() - 1];
    } else if body.ends_with(&[0x1b, b'\\']) {
        body = &body[..body.len() - 2];
    }
    let body = body.strip_prefix(b"52;")?;
    let semi = body.iter().position(|&b| b == b';')?;
    let data = std::str::from_utf8(&body[semi + 1..]).ok()?;
    if data.is_empty() || data == "?" {
        return None;
    }
    Some(data.to_string())
}

pub fn finalize_paint(vt: &[u8]) -> Vec<u8> {
    let (mut filtered, rest, _) = feed_pty_modes(&[], vt);
    if !rest.is_empty() {
        filtered.extend_from_slice(&rest);
    }
    filtered.extend_from_slice(BRACKETED_PASTE);
    filtered.extend_from_slice(FOCUS_REPORT);
    filtered
}

pub fn client_clear_frame(size: TermGridSize) -> TermFrame {
    let mut b = b"\x1b[H\x1b[2J\x1b[3J".to_vec();
    b.extend_from_slice(BRACKETED_PASTE);
    b.extend_from_slice(FOCUS_REPORT);
    TermFrame { width: size.cols, height: size.rows, full: true, bytes: b }
}

pub fn paint_screen(text: &str, size: TermGridSize) -> Vec<u8> {
    let rows = (size.rows as usize).max(1);
    let cols = size.cols as usize;
    let mut lines: Vec<String> = split_text_lines(text)
        .into_iter()
        .flat_map(|l| wrap_line(&l, cols))
        .collect();
    if lines.len() < rows {
        let mut pad = vec![String::new(); rows - lines.len()];
        pad.append(&mut lines);
        lines = pad;
    }
    let mut out = b"\x1b[H\x1b[2J\x1b[3J".to_vec();
    for (i, line) in lines.iter().enumerate() {
        out.extend_from_slice(line.as_bytes());
        if i + 1 < lines.len() {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

fn split_text_lines(text: &str) -> Vec<String> {
    let norm = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = norm.split('\n').map(String::from).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

fn char_cols(c: char) -> usize {
    let u = c as u32;
    if u < 0x20 || u == 0x7f || (0x7f..0xa0).contains(&u) {
        return 0;
    }
    if u < 0x7f {
        return 1;
    }
    if matches!(u, 0x200b | 0x200c | 0x200d | 0xfeff | 0xfe00..=0xfe0f | 0xe0100..=0xe01ef | 0x0300..=0x036f) {
        return 0;
    }
    if matches!(
        u,
        0x1100..=0x115F
            | 0x2329..=0x232A
            | 0x2E80..=0x303E
            | 0x3040..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1B000..=0x1B122
            | 0x1F200..=0x1F2FF
            | 0x1F300..=0x1F64F
            | 0x1F680..=0x1F6FF
            | 0x1F7E0..=0x1F7FF
            | 0x1F900..=0x1F9FF
            | 0x1FA70..=0x1FAFF
            | 0x20000..=0x3FFFD
    ) {
        return 2;
    }
    1
}

fn wrap_line(line: &str, cols: usize) -> Vec<String> {
    if cols == 0 {
        return vec![line.to_string()];
    }
    let total: usize = line.chars().map(char_cols).sum();
    if total <= cols {
        return vec![line.to_string()];
    }
    let mut rows = Vec::new();
    let mut row = String::new();
    let mut used = 0;
    for ch in line.chars() {
        let w = char_cols(ch);
        if w > cols {
            if used > 0 {
                rows.push(std::mem::take(&mut row));
                used = 0;
            }
            rows.push(ch.to_string());
            continue;
        }
        if used + w > cols {
            rows.push(std::mem::take(&mut row));
            used = 0;
        }
        row.push(ch);
        used += w;
    }
    if !row.is_empty() {
        rows.push(row);
    }
    rows
}

pub fn crop_visible(text: &str, from: [u32; 2], to: [u32; 2], rows: usize) -> String {
    let mut lines = split_text_lines(text);
    if rows > 0 && lines.len() < rows {
        let mut pad = vec![String::new(); rows - lines.len()];
        pad.append(&mut lines);
        lines = pad;
    } else if rows > 0 && lines.len() > rows {
        lines = lines.split_off(lines.len() - rows);
    }
    let (fr, fc) = (from[0] as usize, from[1] as usize);
    let (tr, tc) = (to[0] as usize, to[1] as usize);
    let mut out = String::new();
    for r in fr..=tr.min(lines.len().saturating_sub(1)) {
        if r >= lines.len() {
            break;
        }
        let start = if r == fr { fc } else { 0 };
        let end = if r == tr { tc } else { usize::MAX / 2 };
        if r > fr {
            out.push('\n');
        }
        out.push_str(&crop_cells(&lines[r], start, end));
    }
    out
}

fn crop_cells(line: &str, start_col: usize, end_col: usize) -> String {
    if end_col < start_col {
        return String::new();
    }
    let mut out = String::new();
    let mut col = 0usize;
    let mut included = false;
    for ch in line.chars() {
        let w = char_cols(ch);
        if w == 0 {
            if included {
                out.push(ch);
            }
            continue;
        }
        if col > end_col {
            break;
        }
        let keep = col + w > start_col && col <= end_col;
        if keep {
            out.push(ch);
        }
        included = keep;
        col += w;
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MouseKind {
    Down,
    Up,
    Drag,
    Moved,
    ScrollUp,
    ScrollDown,
    ScrollLeft,
    ScrollRight,
}

pub const BTN_LEFT: u8 = 0;
pub const BTN_RIGHT: u8 = 1;
pub const BTN_MIDDLE: u8 = 2;

pub const MOD_SHIFT: u8 = 1 << 0;
pub const MOD_CTRL: u8 = 1 << 1;
pub const MOD_ALT: u8 = 1 << 2;
pub const MOD_SUPER: u8 = 1 << 3;

#[derive(Debug, Clone, Copy)]
pub struct MouseInput {
    pub kind: MouseKind,
    pub button: u8,
    pub column: u16,
    pub row: u16,
    pub mods: u8,
}

fn sgr_button(b: u8) -> i32 {
    match b {
        BTN_MIDDLE => 1,
        BTN_RIGHT => 2,
        _ => 0,
    }
}

pub fn sgr_mouse(m: MouseInput) -> Vec<u8> {
    let mut final_b = 'M';
    let mut cb = match m.kind {
        MouseKind::Down => sgr_button(m.button),
        MouseKind::Up => {
            final_b = 'm';
            sgr_button(m.button)
        }
        MouseKind::Drag => 32 + sgr_button(m.button),
        MouseKind::Moved => 32 + 3,
        MouseKind::ScrollUp => 64,
        MouseKind::ScrollDown => 65,
        MouseKind::ScrollLeft => 66,
        MouseKind::ScrollRight => 67,
    };
    if m.mods & MOD_SHIFT != 0 {
        cb += 4;
    }
    if m.mods & MOD_ALT != 0 {
        cb += 8;
    }
    if m.mods & MOD_CTRL != 0 {
        cb += 16;
    }
    format!("\x1b[<{};{};{}{}", cb, (m.column as usize) + 1, (m.row as usize) + 1, final_b).into_bytes()
}
