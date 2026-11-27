//! In-process Rex bridge state, direct `Core` event sync, snapshot diffing, and blobs.

use super::appdoc::*;
use super::hub::{Hub, TermGridSize};
use super::model::{FloatLayer, Ids};
use super::proto::*;
use super::server::{RexClient, RexServer};
use crate::events::{Filter, Sink};
use crate::rpc::RpcError;
use crate::runtime::Core;
use crate::server::call_internal;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, mpsc};
use uuid::Uuid;

pub const WATCH_SETTLE: Duration = Duration::from_millis(8);
pub const REBALANCE_WINDOW: Duration = Duration::from_millis(500);
pub const BLOB_KIND_CLIPBOARD: &str = "clipboard";
pub const BLOB_KIND_RESULT: &str = "result";
pub const BLOB_TTL_CLIPBOARD: Duration = Duration::from_secs(60);
pub const BLOB_TTL_RESULT: Duration = Duration::from_secs(300);
pub const DEFAULT_BLOB_MAX: usize = 1 << 20;
pub const MAX_CLIPBOARD_TEXT: usize = 64 << 10;
pub const MAX_CORE_PUT: usize = 8 << 20;
pub const MAX_UPLOAD_COUNT: usize = 64;
pub const MAX_UPLOAD_BYTES: usize = 64 << 20;
pub const MAX_UPLOAD_BATCHES: usize = MAX_UPLOAD_COUNT;
pub const UPLOAD_IDLE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct DesiredSize {
    pub client: String,
    pub size: TermGridSize,
    pub updated: SystemTime,
}

#[derive(Debug, Clone, Default)]
pub struct ProcState {
    pub generation: i64,
    pub pid: i64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct StatusSeen {
    pub state: String,
    pub at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct StoredBlob {
    pub kind: String,
    pub text: String,
    pub expires: Instant,
}

#[derive(Debug, Clone)]
pub struct DragState {
    pub anchor: [u32; 2],
    pub last: [u32; 2],
    pub view_top: u32,
    pub moved: bool,
}

#[derive(Debug, Clone)]
pub struct FloatMark {
    pub client: String,
    pub at: Instant,
}

pub struct UploadFile {
    pub name: String,
    pub size: usize,
    pub got: Vec<u8>,
    pub path: String,
    pub done: bool,
}

pub struct UploadBatch {
    pub key: String,
    pub client_id: String,
    pub pane: String,
    pub files: Mutex<Vec<Option<UploadFile>>>,
    pub seen: Mutex<Instant>,
    pub cancel_tx: tokio::sync::watch::Sender<bool>,
}

#[derive(Default)]
struct DocCache {
    local: Option<DocPack>,
    remote: HashMap<String, DocPack>,
    connected: Vec<String>,
}

#[derive(Default)]
struct PendingRefresh {
    full: bool,
    cache: bool,
    docs: HashSet<String>,
}

#[derive(Default)]
pub struct BridgeState {
    pub snap: Option<Snapshot>,
    pub sigs: HashMap<String, String>,
    pub revs: HashMap<String, i64>,
    pub asked: Duration,
    pub owners: HashMap<String, String>,
    pub desired: HashMap<String, Vec<DesiredSize>>,
    pub themes: HashMap<String, Map<String, Value>>,
    pub procs: HashMap<String, ProcState>,
    pub statuses: HashMap<String, StatusSeen>,
    pub exited: HashSet<String>,
    pub order: Vec<String>,
    pub clips: i64,
    pub blobs: HashMap<i64, StoredBlob>,
    pub wheel: HashMap<String, f64>,
    pub scroll_off: HashMap<String, u32>,
    pub scroll_sync: HashSet<String>,
    pub view_top: HashMap<String, u32>,
    pub drags: HashMap<(String, String), DragState>,
    pub floats: HashMap<String, Vec<FloatLayer>>,
    pub floated: HashMap<String, FloatMark>,
    pub layouts: HashMap<String, LayoutNode>,
    pub space_on: HashMap<String, String>,
    pub active_tab: HashMap<String, String>,
    pub active_pane: HashMap<String, String>,
    pub zoomed: HashMap<String, bool>,
    pub keymap_gen: i64,
    pub keymap_hash: String,
}

pub struct RexBridge {
    pub core: Arc<Core>,
    pub srv: Arc<RexServer>,
    pub ids: Ids,
    pub observe: bool,
    pub notify: bool,
    pub rex_config: String,
    pub instance: String,
    pub rev0: i64,
    pub epoch: Instant,
    pub local_host: String,

    pub refresh_mu: tokio::sync::Mutex<()>,
    edit_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    docs: Mutex<DocCache>,
    req: Mutex<PendingRefresh>,
    kick: Notify,

    pub st: Mutex<BridgeState>,
    pub hub_mu: tokio::sync::Mutex<()>,
    pub hubs: Mutex<HashMap<String, Arc<Hub>>>,
    pub uploads: Mutex<HashMap<String, Arc<UploadBatch>>>,
}

impl RexBridge {
    pub fn new(core: Arc<Core>, srv: Arc<RexServer>, observe: bool, notify: bool, rex_config: String) -> Arc<Self> {
        let host_path = std::path::absolute(&core.paths.socket)
            .unwrap_or_else(|_| core.paths.socket.clone())
            .to_string_lossy()
            .into_owned();
        let rev0 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |d| d.as_millis() as i64);
        let local_host = crate::platform::hostname();
        Arc::new(Self {
            core,
            srv,
            ids: Ids::new(&host_path),
            observe,
            notify,
            rex_config,
            instance: Uuid::new_v4().to_string(),
            rev0,
            epoch: Instant::now(),
            local_host,
            refresh_mu: tokio::sync::Mutex::new(()),
            edit_locks: Mutex::new(HashMap::new()),
            docs: Mutex::new(DocCache::default()),
            req: Mutex::new(PendingRefresh::default()),
            kick: Notify::new(),
            st: Mutex::new(BridgeState::default()),
            hub_mu: tokio::sync::Mutex::new(()),
            hubs: Mutex::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
        })
    }

    pub fn since(&self) -> Duration {
        self.epoch.elapsed()
    }

    pub fn local_home(&self) -> String {
        std::env::var("HOME").unwrap_or_default()
    }

    pub fn machine_home(&self, on: &str) -> String {
        if on.is_empty() {
            return self.local_home();
        }
        self.docs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remote
            .get(on)
            .map(|p| p.home.clone())
            .unwrap_or_default()
    }

    pub fn pack(&self, on: &str) -> Option<DocPack> {
        let cache = self.docs.lock().unwrap_or_else(|p| p.into_inner());
        if on.is_empty() {
            cache.local.clone()
        } else {
            cache.remote.get(on).cloned()
        }
    }

    pub fn doc_version(&self, on: &str) -> Option<u64> {
        self.pack(on).map(|p| p.version)
    }

    pub fn connected_machines(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        for n in &self.docs.lock().unwrap_or_else(|p| p.into_inner()).connected {
            if !n.is_empty() {
                seen.insert(n.clone());
            }
        }
        for on in self.st.lock().unwrap_or_else(|p| p.into_inner()).space_on.values() {
            if !on.is_empty() {
                seen.insert(on.clone());
            }
        }
        let mut out: Vec<String> = seen.into_iter().collect();
        out.sort();
        out
    }

    /// Reads all live local + mirrored remote terminals directly from `Core::State` (0 RPC).
    pub fn live_terms(&self) -> HashMap<String, TerminalRec> {
        let vals = {
            let st = self.core.lock();
            self.core.matching(&st, &Filter::default())
        };
        let mut out = HashMap::with_capacity(vals.len());
        for v in vals {
            if let Ok(rec) = serde_json::from_value::<TerminalRec>(v)
                && !rec.address.is_empty()
            {
                out.insert(rec.address.clone(), rec);
            }
        }
        out
    }

    pub fn live_term(&self, addr: &str) -> Option<TerminalRec> {
        let st = self.core.lock();
        for v in self.core.matching(&st, &Filter::default()) {
            if v["address"].as_str() == Some(addr) {
                return serde_json::from_value(v).ok();
            }
        }
        None
    }

    fn fetch_local_pack_inmem(&self) -> DocPack {
        let (val, ver) = {
            let st = self.core.lock();
            match st.docs.get(APP_DOC_NAME) {
                Some(d) => (d.value.clone(), d.version),
                None => (Value::Null, 0),
            }
        };
        let pack = DocPack {
            on: String::new(),
            label: self.core.info.name.clone(),
            home: self.local_home(),
            version: ver,
            raw: parse_doc(&val),
        };
        self.docs.lock().unwrap_or_else(|p| p.into_inner()).local = Some(pack.clone());
        pack
    }

    async fn connected_machine_names(&self) -> Vec<String> {
        let res = call_internal(&self.core, None, "machine.list", json!({})).await;
        let mut names = Vec::new();
        if let Ok(v) = res
            && let Some(arr) = v["machines"].as_array()
        {
            for m in arr {
                if m["state"].as_str() == Some("connected")
                    && let Some(name) = m["name"].as_str().filter(|s| !s.is_empty())
                {
                    names.push(name.to_string());
                }
            }
        }
        names.sort();
        self.docs.lock().unwrap_or_else(|p| p.into_inner()).connected = names.clone();
        names
    }

    async fn fetch_remote_packs(&self, names: &[String], terms: &HashMap<String, TerminalRec>) -> Vec<DocPack> {
        let mut handles = Vec::with_capacity(names.len());
        for name in names {
            let core = self.core.clone();
            let on = name.clone();
            handles.push(tokio::spawn(async move {
                let res = tokio::time::timeout(
                    Duration::from_secs(6),
                    call_internal(&core, None, "doc.get", json!({"name": APP_DOC_NAME, "on": on})),
                )
                .await;
                (on, res)
            }));
        }
        let mut packs = Vec::new();
        for h in handles {
            let Ok((name, res)) = h.await else { continue };
            match res {
                Ok(Ok(d)) => {
                    let p = DocPack {
                        on: name.clone(),
                        label: name.clone(),
                        home: infer_home(&name, terms),
                        version: d["version"].as_u64().unwrap_or(0),
                        raw: parse_doc(&d["value"]),
                    };
                    {
                        let mut cache = self.docs.lock().unwrap_or_else(|p| p.into_inner());
                        cache.remote.insert(name.clone(), p.clone());
                        if !cache.connected.contains(&name) {
                            cache.connected.push(name);
                            cache.connected.sort();
                        }
                    }
                    packs.push(p);
                }
                Ok(Err(e)) => {
                    if let Some(cached) = self.pack(&name) {
                        eprintln!("rex doc.get on={name}: {}; using cached pack", e.message);
                        packs.push(cached);
                    } else {
                        eprintln!("rex doc.get on={name}: {}", e.message);
                    }
                }
                Err(_) => {
                    if let Some(cached) = self.pack(&name) {
                        eprintln!("rex doc.get on={name}: timed out; using cached pack");
                        packs.push(cached);
                    } else {
                        eprintln!("rex doc.get on={name}: timed out");
                    }
                }
            }
        }
        packs
    }

    fn drop_packs_except(&self, connected: &[String]) {
        let live: HashSet<&str> = connected.iter().map(String::as_str).collect();
        self.docs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remote
            .retain(|k, _| live.contains(k.as_str()));
    }

    pub fn remember_doc(&self, on: &str, raw: Map<String, Value>, version: u64) {
        let terms = self.live_terms();
        let mut cache = self.docs.lock().unwrap_or_else(|p| p.into_inner());
        if on.is_empty() {
            let home = self.local_home();
            let label = self.core.info.name.clone();
            cache.local = Some(DocPack { on: String::new(), label, home, version, raw });
        } else {
            let home = cache
                .remote
                .get(on)
                .map(|p| p.home.clone())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| infer_home(on, &terms));
            cache.remote.insert(
                on.to_string(),
                DocPack { on: on.to_string(), label: on.to_string(), home, version, raw },
            );
        }
    }

    pub async fn edit_doc<E, F>(&self, on: &str, edit: F) -> Result<(Map<String, Value>, u64), E>
    where
        E: From<RpcError>,
        F: FnMut(&mut Map<String, Value>) -> Result<(), E>,
    {
        let lock = {
            let mut m = self.edit_locks.lock().unwrap_or_else(|p| p.into_inner());
            m.entry(on.to_string()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
        };
        let _guard = lock.lock().await;
        let (doc, ver) = edit_app_doc(&self.core, on, edit).await?;
        self.remember_doc(on, doc.clone(), ver);
        Ok((doc, ver))
    }

    fn focus_maps(&self) -> FocusMaps {
        let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        FocusMaps {
            tab: st.active_tab.clone(),
            pane: st.active_pane.clone(),
            zoom: st.zoomed.clone(),
        }
    }

    async fn build_snapshot(&self, mode: RefreshMode<'_>) -> (Snapshot, DocMeta) {
        let terms = self.live_terms();
        let focus = self.focus_maps();
        let home = self.local_home();
        let mut packs = Vec::new();

        match mode {
            RefreshMode::Cache => {
                let local = self.pack("").unwrap_or_else(|| self.fetch_local_pack_inmem());
                packs.push(local);
                let connected = self.docs.lock().unwrap_or_else(|p| p.into_inner()).connected.clone();
                for name in connected {
                    if let Some(p) = self.pack(&name) {
                        packs.push(p);
                    }
                }
            }
            RefreshMode::Machines => {
                let names = self.connected_machine_names().await;
                self.drop_packs_except(&names);
                let missing: Vec<String> = names.iter().filter(|n| self.pack(n).is_none()).cloned().collect();
                if !missing.is_empty() {
                    let _ = self.fetch_remote_packs(&missing, &terms).await;
                }
                let local = self.pack("").unwrap_or_else(|| self.fetch_local_pack_inmem());
                packs.push(local);
                for name in names {
                    if let Some(p) = self.pack(&name) {
                        packs.push(p);
                    }
                }
            }
            RefreshMode::Only(on) => {
                let names = self.docs.lock().unwrap_or_else(|p| p.into_inner()).connected.clone();
                if on.is_empty() {
                    packs.push(self.fetch_local_pack_inmem());
                    for name in names {
                        if let Some(p) = self.pack(&name) {
                            packs.push(p);
                        }
                    }
                } else {
                    packs.push(self.pack("").unwrap_or_else(|| self.fetch_local_pack_inmem()));
                    let fetched = self.fetch_remote_packs(&[on.to_string()], &terms).await;
                    let mut by_name: HashMap<String, DocPack> =
                        fetched.into_iter().map(|p| (p.on.clone(), p)).collect();
                    for name in names {
                        if let Some(p) = by_name.remove(&name).or_else(|| self.pack(&name)) {
                            packs.push(p);
                        }
                    }
                    for (_, p) in by_name {
                        packs.push(p);
                    }
                }
            }
            RefreshMode::Full => {
                let names = self.connected_machine_names().await;
                packs.push(self.fetch_local_pack_inmem());
                if !names.is_empty() {
                    packs.extend(self.fetch_remote_packs(&names, &terms).await);
                }
                self.drop_packs_except(&names);
            }
        }
        build_from_docs(&packs, &terms, &home, &focus)
    }

    pub async fn refresh_full(&self) {
        self.refresh_apply(None, RefreshMode::Full).await;
    }

    pub async fn refresh_cached(&self) {
        self.refresh_apply(None, RefreshMode::Cache).await;
    }

    pub async fn refresh_machines(&self) {
        self.refresh_apply(None, RefreshMode::Machines).await;
    }

    pub async fn refresh_doc(&self, on: &str) {
        self.refresh_apply(None, RefreshMode::Only(on)).await;
    }

    pub async fn refresh_from_cache_after(&self, t: Duration) {
        self.refresh_apply(Some(t), RefreshMode::Cache).await;
    }

    async fn refresh_apply(&self, min_time: Option<Duration>, mode: RefreshMode<'_>) {
        let _guard = self.refresh_mu.lock().await;
        if let Some(t) = min_time
            && self.st.lock().unwrap_or_else(|p| p.into_inner()).asked > t
        {
            return;
        }
        let (snap, meta) = self.build_snapshot(mode).await;
        let now_since = self.since();
        let sigs = signatures(&snap);

        let (prev, first, created, changed, destroyed) = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            st.asked = now_since;
            st.layouts = meta.layouts;
            st.space_on = meta.space_on;
            let prev = st.snap.replace(snap.clone());
            let old = std::mem::replace(&mut st.sigs, sigs.clone());
            let first = prev.is_none();
            prune_floats_locked(&mut st.floats, &snap);

            let mut created = Vec::new();
            let mut changed = Vec::new();
            let mut destroyed = Vec::new();
            for (id, sig) in &sigs {
                match old.get(id) {
                    None => {
                        st.revs.insert(id.clone(), self.rev0);
                        created.push(id.clone());
                    }
                    Some(prev_sig) if prev_sig != sig => {
                        *st.revs.entry(id.clone()).or_insert(self.rev0) += 1;
                        changed.push(id.clone());
                    }
                    _ => {}
                }
            }
            for id in old.keys() {
                if !sigs.contains_key(id) {
                    destroyed.push(id.clone());
                }
            }
            if first {
                st.order = workspace_order(&snap);
            }
            (prev, first, created, changed, destroyed)
        };

        self.register_ids(&snap);
        if first {
            return;
        }

        let created_set: HashSet<&str> = created.iter().map(String::as_str).collect();
        for w in &snap.workspaces {
            if !created_set.contains(w.id.as_str()) {
                continue;
            }
            self.srv.emit(
                "session_created",
                json!({"session": {"session_id": self.ids.rex("session", &w.id), "label": w.label}}),
            );
            for p in &snap.panes {
                if p.workspace_id == w.id {
                    for (typ, payload) in self.created_events(&p.id) {
                        self.session_event(&w.id, &typ, payload);
                    }
                }
            }
            self.view_changed(&w.id);
        }
        for id in &destroyed {
            self.srv.emit("session_destroyed", json!({"session_id": self.ids.rex("session", id)}));
        }
        self.session_moves(&snap);
        if let Some(prev_snap) = prev.as_ref() {
            self.pane_events(prev_snap, &snap);
            for id in &changed {
                let (pre, post) = self.diff_workspace(prev_snap, &snap, id);
                for (typ, payload) in pre {
                    self.session_event(id, &typ, payload);
                }
                self.view_changed(id);
                for (typ, payload) in post {
                    self.session_event(id, &typ, payload);
                }
            }
            self.forget_closed(prev_snap, &snap, &destroyed);
        }
    }

    pub fn register_ids(&self, s: &Snapshot) {
        for w in &s.workspaces {
            self.ids.rex("session", &w.id);
        }
        for t in &s.tabs {
            self.ids.rex("window", &t.id);
        }
        for p in &s.panes {
            self.ids.rex("block", &p.id);
        }
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        self.st.lock().unwrap_or_else(|p| p.into_inner()).snap.clone()
    }

    pub async fn current(&self) -> Snapshot {
        if let Some(s) = self.snapshot() {
            return s;
        }
        self.refresh_full().await;
        self.snapshot().unwrap_or_default()
    }

    pub fn herdr_id(&self, rex_id: &str, kind: &str) -> Result<String, RexError> {
        if let Some(h) = self.ids.herdr(rex_id)
            && self.ids.rex(kind, &h) == rex_id
        {
            return Ok(h);
        }
        if kind == "session" {
            Err(RexError::session_not_found(format!("unknown {kind} {rex_id}")))
        } else {
            Err(RexError::not_found(format!("unknown {kind} {rex_id}")))
        }
    }

    pub fn on_of(&self, space: &str) -> String {
        self.st
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .space_on
            .get(space)
            .cloned()
            .unwrap_or_default()
    }

    pub fn tab_layout(&self, tab_id: &str) -> Option<LayoutNode> {
        self.st.lock().unwrap_or_else(|p| p.into_inner()).layouts.get(tab_id).cloned()
    }

    pub fn current_rev(&self, wid: &str) -> i64 {
        let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        st.revs.get(wid).copied().filter(|r| *r != 0).unwrap_or(self.rev0)
    }

    pub fn bump(&self, wid: &str) -> i64 {
        let rev = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            let r = st.revs.entry(wid.to_string()).or_insert(self.rev0);
            *r += 1;
            *r
        };
        self.view_changed(wid);
        rev
    }

    pub fn view_changed(&self, wid: &str) {
        let sid = self.ids.rex("session", wid);
        let rev = self.current_rev(wid);
        self.srv.session_event(&sid, "session_view_changed", json!({"revision": rev}));
    }

    pub fn session_event(&self, wid: &str, typ: &str, payload: Value) {
        self.srv.session_event(&self.ids.rex("session", wid), typ, payload);
    }

    pub fn emit_block_event(&self, sid: &str, block: &str, name: &str, payload: Value) {
        self.srv.session_event(
            sid,
            "block_event",
            json!({
                "block_id": block,
                "creator_name": TERMINAL_CREATOR,
                "name": name,
                "payload": payload,
            }),
        );
    }

    pub async fn settle(&self, ws: &str) -> i64 {
        let done = self.since();
        let before = self.st.lock().unwrap_or_else(|p| p.into_inner()).revs.get(ws).copied().unwrap_or(0);
        self.refresh_from_cache_after(done).await;
        let (r, exists) = {
            let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            (st.revs.get(ws).copied().unwrap_or(0), st.sigs.contains_key(ws))
        };
        if !exists {
            return before;
        }
        if r == before {
            return self.bump(ws);
        }
        r
    }

    pub fn request_full_refresh(&self) {
        self.req.lock().unwrap_or_else(|p| p.into_inner()).full = true;
        self.kick.notify_one();
    }

    pub fn request_cache_refresh(&self) {
        self.req.lock().unwrap_or_else(|p| p.into_inner()).cache = true;
        self.kick.notify_one();
    }

    pub fn request_doc_refresh(&self, machine: &str) {
        self.req.lock().unwrap_or_else(|p| p.into_inner()).docs.insert(machine.to_string());
        self.kick.notify_one();
    }

    /// Starts the in-process event watcher, burst coalescer, 5s local machine poll, and keymap watcher.
    pub fn start_background(self: &Arc<Self>) -> Vec<tokio::task::AbortHandle> {
        let mut handles = Vec::new();

        // 1. Coalesced refresh worker
        {
            let b = self.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    b.kick.notified().await;
                    tokio::time::sleep(WATCH_SETTLE).await;
                    let (full, cache, mut docs) = {
                        let mut r = b.req.lock().unwrap_or_else(|p| p.into_inner());
                        let full = std::mem::take(&mut r.full);
                        let cache = std::mem::take(&mut r.cache);
                        let docs: Vec<String> = r.docs.drain().collect();
                        (full, cache, docs)
                    };
                    if full {
                        b.refresh_full().await;
                    } else if !docs.is_empty() {
                        docs.sort();
                        for m in docs {
                            b.refresh_doc(&m).await;
                        }
                    } else if cache {
                        b.refresh_cached().await;
                    }
                }
            }).abort_handle());
        }

        // 2. Direct in-process herdr-core event subscription (Sink::Waiter)
        {
            let b = self.clone();
            let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
            {
                let mut st = self.core.lock();
                self.core.subscribe(&mut st, Filter::default(), Sink::Waiter(tx));
            }
            handles.push(tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    let kind = ev["type"].as_str().unwrap_or_default();
                    match kind {
                        "missed" => b.request_full_refresh(),
                        "doc" => {
                            let name = ev["data"]["name"].as_str().unwrap_or_default();
                            if name != APP_DOC_NAME {
                                continue;
                            }
                            let machine = ev["machine"].as_str().unwrap_or_default();
                            let ver = ev["data"]["version"].as_u64().unwrap_or(0);
                            if let Some(cur) = b.doc_version(machine)
                                && ver > 0
                                && ver <= cur
                            {
                                continue;
                            }
                            b.request_doc_refresh(machine);
                        }
                        "finished" => {
                            let addr = ev["terminal"].as_str().unwrap_or_default().to_string();
                            let code = ev["data"]["exit_code"].as_i64().unwrap_or(0) as i32;
                            b.mark_exited(&addr, code);
                            let bp = b.clone();
                            let a = addr.clone();
                            tokio::spawn(async move {
                                bp.prune_finished_pane(&a).await;
                            });
                            b.request_cache_refresh();
                        }
                        "created" | "restarted" | "removed" | "lost" | "status" | "title"
                        | "foreground" | "size" | "labels" => {
                            let addr = ev["terminal"].as_str().unwrap_or_default();
                            let m = machine_of(addr);
                            if !m.is_empty() && b.pack(m).is_none() {
                                b.request_doc_refresh(m);
                            } else {
                                b.request_cache_refresh();
                            }
                        }
                        _ => {}
                    }
                }
            }).abort_handle());
        }

        // 3. Lightweight 5s machine-connection poll (local machine.list only),
        //    plus a fast 1s check right after boot so newly connected remotes appear immediately.
        {
            let b = self.clone();
            handles.push(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                b.refresh_machines().await;
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    b.refresh_machines().await;
                }
            }).abort_handle());
        }

        // 4. Keymap file watcher (2s)
        {
            let b = self.clone();
            handles.push(tokio::spawn(async move {
                b.watch_keymap().await;
            }).abort_handle());
        }

        handles
    }

    async fn prune_finished_pane(&self, addr: &str) {
        if addr.is_empty() || self.pane_session(addr).is_none() {
            return;
        }
        let on = machine_of(addr);
        let local = local_addr(addr, on);
        let res: Result<_, RexError> = self
            .edit_doc(on, |doc| {
                if doc_close_pane(doc, &local).is_none() {
                    return Err(RexError::not_found("absent"));
                }
                Ok(())
            })
            .await;
        if res.is_ok() {
            self.request_cache_refresh();
        }
    }

    pub fn pane_session(&self, pane: &str) -> Option<String> {
        let s = self.snapshot()?;
        s.panes
            .iter()
            .find(|p| p.id == pane)
            .map(|p| self.ids.rex("session", &p.workspace_id))
    }

    pub fn pane_workspace(&self, pane: &str) -> String {
        self.snapshot()
            .and_then(|s| s.panes.into_iter().find(|p| p.id == pane).map(|p| p.workspace_id))
            .unwrap_or_default()
    }

    pub fn pane_bell(&self, pane: &str) {
        if let Some(sid) = self.pane_session(pane) {
            self.emit_block_event(&sid, &self.ids.rex("block", pane), "bell", json!({}));
        }
    }

    pub fn pane_clipboard(&self, pane: &str, data_b64: &str) {
        let Some(sid) = self.pane_session(pane) else { return };
        let Ok(raw) = B64.decode(data_b64) else { return };
        let text = String::from_utf8_lossy(&raw).into_owned();
        let id = self.put_blob(BLOB_KIND_CLIPBOARD, text.clone(), BLOB_TTL_CLIPBOARD);
        let mut p = Map::new();
        p.insert("id".into(), json!(id));
        p.insert("bytes".into(), json!(raw.len()));
        if !raw.is_empty() && raw.len() <= MAX_CLIPBOARD_TEXT {
            p.insert("text".into(), Value::String(text));
        }
        self.emit_block_event(&sid, &self.ids.rex("block", pane), "clipboard_written", Value::Object(p));
    }

    pub fn mark_exited(&self, addr: &str, exit_code: i32) {
        if addr.is_empty() {
            return;
        }
        let Some(sid) = self.pane_session(addr) else { return };
        let first = self.st.lock().unwrap_or_else(|p| p.into_inner()).exited.insert(addr.to_string());
        if first {
            self.emit_block_event(&sid, &self.ids.rex("block", addr), "child_exited", json!({"exit_code": exit_code}));
        }
    }

    pub fn take_exited(&self, pane: &str) -> bool {
        self.st.lock().unwrap_or_else(|p| p.into_inner()).exited.remove(pane)
    }

    pub fn owner(&self, block: &str) -> String {
        self.st
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .owners
            .get(block)
            .cloned()
            .unwrap_or_default()
    }

    pub fn theme(&self, block: &str) -> Option<Map<String, Value>> {
        self.st.lock().unwrap_or_else(|p| p.into_inner()).themes.get(block).cloned()
    }

    pub fn put_blob(&self, kind: &str, text: String, ttl: Duration) -> i64 {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        st.blobs.retain(|_, b| now <= b.expires);
        st.clips += 1;
        let id = st.clips;
        st.blobs.insert(id, StoredBlob { kind: kind.into(), text, expires: now + ttl });
        id
    }

    pub fn read_blob(&self, kind: &str, mut id: i64, offset: i64, max_bytes: i64) -> Result<(i64, String, usize, bool), RexError> {
        if offset < 0 {
            return Err(RexError::bad_request("offset must not be negative"));
        }
        if max_bytes < 0 {
            return Err(RexError::bad_request("max_bytes must not be negative"));
        }
        let max_b = if max_bytes == 0 { DEFAULT_BLOB_MAX } else { max_bytes as usize };
        let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let blob = if id == 0 {
            let best = st
                .blobs
                .iter()
                .filter(|(_, b)| b.kind == kind && now <= b.expires)
                .max_by_key(|(k, _)| **k);
            match best {
                Some((&k, b)) => {
                    id = k;
                    b
                }
                None => return Err(RexError::not_found("blob not found")),
            }
        } else {
            match st.blobs.get(&id) {
                Some(b) if b.kind == kind && now <= b.expires => b,
                _ => return Err(RexError::not_found("blob not found")),
            }
        };
        let text = &blob.text;
        let mut off = (offset as usize).min(text.len());
        while off > 0 && !text.is_char_boundary(off) {
            off -= 1;
        }
        let mut end = off.saturating_add(max_b).min(text.len());
        while end > off && !text.is_char_boundary(end) {
            end -= 1;
        }
        Ok((id, text[off..end].to_string(), text.len(), end >= text.len()))
    }

    pub fn on_client_disconnect(&self, c: &RexClient) {
        self.release_owner(c);
        self.forget_client(&c.id);
        self.drop_uploads(&c.id);
    }

    pub fn release_owner(&self, c: &RexClient) {
        let gone: Vec<String> = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            let mut g = Vec::new();
            st.owners.retain(|id, o| {
                if o == &c.id {
                    g.push(id.clone());
                    false
                } else {
                    true
                }
            });
            g
        };
        let mut touched = HashSet::new();
        for id in gone {
            let Some(pane) = self.ids.herdr(&id) else { continue };
            let wid = self.pane_workspace(&pane);
            if wid.is_empty() {
                continue;
            }
            self.srv.session_event(
                &self.ids.rex("session", &wid),
                "block_owner_changed",
                json!({"block_id": id, "previous": c.id, "reason": "disconnect"}),
            );
            touched.insert(wid);
        }
        for wid in touched {
            self.bump(&wid);
        }
    }

    pub fn forget_client(&self, client_id: &str) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        st.drags.retain(|(cid, _), _| cid != client_id);
        for list in st.desired.values_mut() {
            list.retain(|d| d.client != client_id);
        }
    }

    pub fn drop_uploads(&self, client_id: &str) {
        let mut ups = self.uploads.lock().unwrap_or_else(|p| p.into_inner());
        ups.retain(|_, u| {
            if u.client_id == client_id {
                let _ = u.cancel_tx.send(true);
                false
            } else {
                true
            }
        });
    }

    pub async fn claim(&self, c: &RexClient, ws: &str, blocks: &[String]) {
        let _r = self.refresh_mu.lock().await;
        let late: Vec<String> = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            let mut late = Vec::new();
            for id in blocks {
                if st.owners.contains_key(id) {
                    continue;
                }
                st.owners.insert(id.clone(), c.id.clone());
                if let Some(pane) = self.ids.herdr(id)
                    && st.snap.as_ref().is_some_and(|s| s.panes.iter().any(|p| p.id == pane))
                {
                    late.push(id.clone());
                }
            }
            late
        };
        let sid = self.ids.rex("session", ws);
        for id in &late {
            self.srv.session_event(
                &sid,
                "block_owner_changed",
                json!({"block_id": id, "owner": c.id, "reason": "create"}),
            );
        }
        if !late.is_empty() {
            self.bump(ws);
        }
    }

    pub fn pwd_url_for(&self, p: &Pane) -> String {
        let m = machine_of(&p.id);
        let host = if m.is_empty() { self.local_host.as_str() } else { m };
        file_url(host, pwd_of(p))
    }

    fn created_events(&self, pane: &str) -> Vec<(String, Value)> {
        let block = self.ids.rex("block", pane);
        let mut out = vec![("block_created".into(), json!({"block_id": block}))];
        let (first_gen, owner) = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            let generation = st.procs.get(&block).map_or(0, |p| p.generation);
            let first = if generation == 0 {
                st.procs.insert(block.clone(), ProcState { generation: 1, pid: 0, name: String::new() });
                true
            } else {
                false
            };
            (first, st.owners.get(&block).cloned().unwrap_or_default())
        };
        if first_gen {
            out.push((
                "block_event".into(),
                json!({
                    "block_id": block,
                    "creator_name": TERMINAL_CREATOR,
                    "name": "process_changed",
                    "payload": {"generation": 1, "foreground": Value::Null},
                }),
            ));
        }
        if !owner.is_empty() {
            out.push((
                "block_owner_changed".into(),
                json!({"block_id": block, "owner": owner, "reason": "create"}),
            ));
        }
        out
    }

    #[allow(clippy::type_complexity)]
    fn diff_workspace(&self, old: &Snapshot, cur: &Snapshot, wid: &str) -> (Vec<(String, Value)>, Vec<(String, Value)>) {
        let mut pre = Vec::new();
        let mut post = Vec::new();
        let old_panes = panes_in(old, wid);
        let cur_panes = panes_in(cur, wid);
        for id in cur_panes.keys() {
            if !old_panes.contains_key(id) {
                pre.extend(self.created_events(id));
            }
        }
        let old_tabs = tabs_in(old, wid);
        let cur_tabs = tabs_in(cur, wid);
        for t in &cur.tabs {
            if t.workspace_id != wid {
                continue;
            }
            let w = self.ids.rex("window", &t.id);
            match old_tabs.get(&t.id) {
                None => pre.push(("window_created".into(), json!({"window_id": w, "label": t.label}))),
                Some(ot) if ot.label != t.label => {
                    pre.push(("window_label_changed".into(), json!({"window_id": w, "label": t.label})));
                }
                _ => {}
            }
        }
        for id in old_tabs.keys() {
            if !cur_tabs.contains_key(id) {
                pre.push(("window_closed".into(), json!({"window_id": self.ids.rex("window", id)})));
            }
        }
        if let (Some(ow), Some(cw)) = (workspace_of(old, wid), workspace_of(cur, wid)) {
            if ow.active_tab_id != cw.active_tab_id && !cw.active_tab_id.is_empty() {
                pre.push((
                    "active_window_changed".into(),
                    json!({"window_id": self.ids.rex("window", &cw.active_tab_id)}),
                ));
            }
            if ow.label != cw.label {
                pre.push(("session_label_changed".into(), json!({"label": cw.label})));
            }
        }
        let mut exited = Vec::new();
        for (id, tab) in &old_panes {
            if cur_panes.contains_key(id) {
                continue;
            }
            let e = ("block_closed".into(), json!({"block_id": self.ids.rex("block", id)}));
            if self.take_exited(id) {
                exited.push(e);
            } else if cur_tabs.contains_key(tab) {
                pre.push(e);
            } else {
                post.push(e);
            }
        }
        if !exited.is_empty() {
            exited.append(&mut pre);
            pre = exited;
        }
        (pre, post)
    }

    fn session_moves(&self, cur_snap: &Snapshot) {
        let cur = workspace_order(cur_snap);
        let old = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::replace(&mut st.order, cur.clone())
        };
        let pos: HashMap<&str, usize> = old.iter().enumerate().map(|(i, id)| (id.as_str(), i)).collect();
        let seq: Vec<&str> = cur.iter().filter(|id| pos.contains_key(id.as_str())).map(String::as_str).collect();
        let keep = longest_run(&seq, &pos);
        for i in (0..seq.len()).rev() {
            if keep.contains(seq[i]) {
                continue;
            }
            let mut p = Map::new();
            p.insert("session_id".into(), Value::String(self.ids.rex("session", seq[i])));
            if i + 1 < seq.len() {
                p.insert("before_session_id".into(), Value::String(self.ids.rex("session", seq[i + 1])));
            }
            self.srv.emit("session_moved", Value::Object(p));
        }
    }

    fn pane_events(&self, old: &Snapshot, cur: &Snapshot) {
        let before: HashMap<&str, &Pane> = old.panes.iter().map(|p| (p.id.as_str(), p)).collect();
        for p in &cur.panes {
            let Some(&o) = before.get(p.id.as_str()) else { continue };
            let sid = self.ids.rex("session", &p.workspace_id);
            let block = self.ids.rex("block", &p.id);
            if o.terminal_title != p.terminal_title {
                let mut ev = Map::new();
                ev.insert("title".into(), Value::String(p.terminal_title.clone()));
                if let Some(own) = process_owner(p) {
                    ev.insert("owner".into(), own);
                }
                self.emit_block_event(&sid, &block, "title_changed", Value::Object(ev));
            }
            if pwd_of(o) != pwd_of(p) && !pwd_of(p).is_empty() {
                let mut ev = Map::new();
                ev.insert("pwd".into(), Value::String(self.pwd_url_for(p)));
                if let Some(own) = process_owner(p) {
                    ev.insert("owner".into(), own);
                }
                self.emit_block_event(&sid, &block, "pwd_changed", Value::Object(ev));
            }
            self.status_events(cur, o, p, &sid, &block);
            if o.terminal_title != p.terminal_title
                || pwd_of(o) != pwd_of(p)
                || o.foreground_name != p.foreground_name
                || o.foreground_pid != p.foreground_pid
            {
                self.process_changed(&sid, &block, p);
            }
        }
    }

    fn status_events(&self, cur: &Snapshot, o: &Pane, p: &Pane, sid: &str, block: &str) {
        let old_recs = rec_by_id(&pane_status_recs(o));
        let new_recs = rec_by_id(&pane_status_recs(p));
        if old_recs.is_empty() && new_recs.is_empty() {
            return;
        }
        for (id, sig) in &new_recs {
            if old_recs.get(id) == Some(sig) {
                continue;
            }
            let mut payload = Map::new();
            payload.insert("record".into(), self.status_record_id(p, id).unwrap_or(Value::Null));
            payload.insert("reason".into(), Value::String("report".into()));
            if !id.is_empty() {
                payload.insert("id".into(), Value::String(id.clone()));
            }
            self.emit_block_event(sid, block, "program_status_changed", Value::Object(payload));
        }
        let gone: Vec<String> = old_recs.keys().filter(|id| !new_recs.contains_key(*id)).cloned().collect();
        if !gone.is_empty() {
            self.emit_block_event(
                sid,
                block,
                "program_status_removed",
                json!({"ids": gone, "reason": "foreground"}),
            );
        }
        if o.agent_status != p.agent_status
            && self.notify
            && let Some(what) = attention(&p.agent_status)
        {
            self.emit_block_event(
                sid,
                block,
                "desktop_notification",
                json!({
                    "title": format!("{} {what}", agent_name(p)),
                    "body": pane_context(cur, p),
                }),
            );
        }
    }

    pub fn status_records(&self, p: &Pane) -> Vec<Value> {
        pane_status_recs(p)
            .into_iter()
            .filter_map(|r| self.status_record_from(p, &r))
            .collect()
    }

    fn status_record_id(&self, p: &Pane, id: &str) -> Option<Value> {
        pane_status_recs(p)
            .into_iter()
            .find(|r| r.id == id)
            .and_then(|r| self.status_record_from(p, &r))
    }

    fn status_record_from(&self, p: &Pane, r: &StatusRec) -> Option<Value> {
        if !detected(&r.state) {
            return None;
        }
        let at = self.status_time(p, &r.state);
        let mut rec = Map::new();
        rec.insert("state".into(), Value::String(r.state.clone()));
        rec.insert("updated_at".into(), Value::String(at));
        if !r.id.is_empty() {
            rec.insert("id".into(), Value::String(r.id.clone()));
        }
        let app = if !r.app.is_empty() { &r.app } else { &p.agent };
        if !app.is_empty() {
            rec.insert("app".into(), Value::String(app.clone()));
            rec.insert("effective_app".into(), Value::String(app.clone()));
        }
        if !r.title.is_empty() {
            rec.insert("title".into(), Value::String(r.title.clone()));
        }
        if !r.msg.is_empty() {
            rec.insert("msg".into(), Value::String(r.msg.clone()));
        }
        if !r.kind.is_empty() {
            rec.insert("kind".into(), Value::String(r.kind.clone()));
        }
        if let Some(prog) = r.progress {
            rec.insert("progress".into(), json!(prog));
        }
        if let Some(o) = process_owner(p) {
            rec.insert("owner".into(), o);
        }
        Some(Value::Object(rec))
    }

    fn status_time(&self, p: &Pane, state: &str) -> String {
        if p.status_updated_ms > 0 {
            return stamp_rfc3339_ms(p.status_updated_ms as u64);
        }
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let entry = st.statuses.entry(p.id.clone()).or_insert_with(|| StatusSeen {
            state: state.to_string(),
            at: SystemTime::now(),
        });
        if entry.state != state {
            entry.state = state.to_string();
            entry.at = SystemTime::now();
        }
        stamp_rfc3339(entry.at)
    }

    pub fn process_changed(&self, sid: &str, block: &str, p: &Pane) {
        let (fg, pid, name) = if p.foreground_pid != 0 || !p.foreground_name.is_empty() {
            let mut m = Map::new();
            m.insert("pid".into(), json!(p.foreground_pid));
            m.insert("name".into(), Value::String(p.foreground_name.clone()));
            if let Some(a0) = p.foreground_argv.first() {
                m.insert("argv0".into(), Value::String(a0.clone()));
            }
            if !p.foreground_cwd.is_empty() {
                m.insert("cwd".into(), Value::String(p.foreground_cwd.clone()));
            }
            (Value::Object(m), p.foreground_pid, p.foreground_name.clone())
        } else if p.pid != 0 {
            let mut m = Map::new();
            m.insert("pid".into(), json!(p.pid));
            if let Some(a0) = p.argv.first() {
                m.insert("argv0".into(), Value::String(a0.clone()));
            }
            if !p.cwd.is_empty() {
                m.insert("cwd".into(), Value::String(p.cwd.clone()));
            }
            (Value::Object(m), p.pid, String::new())
        } else {
            (Value::Null, 0, String::new())
        };
        let generation = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(last) = st.procs.get(block)
                && last.pid == pid
                && last.name == name
            {
                return;
            }
            let next = st.procs.get(block).map_or(0, |l| l.generation) + 1;
            st.procs.insert(block.to_string(), ProcState { generation: next, pid, name });
            next
        };
        self.emit_block_event(sid, block, "process_changed", json!({"generation": generation, "foreground": fg}));
    }

    fn forget_closed(&self, old: &Snapshot, cur: &Snapshot, workspaces: &[String]) {
        let open: HashSet<&str> = cur.panes.iter().map(|p| p.id.as_str()).collect();
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        for p in &old.panes {
            if open.contains(p.id.as_str()) {
                continue;
            }
            let block = self.ids.rex("block", &p.id);
            st.procs.remove(&block);
            st.themes.remove(&block);
            st.owners.remove(&block);
            st.desired.remove(&block);
            st.statuses.remove(&p.id);
            st.exited.remove(&p.id);
            st.wheel.remove(&p.id);
            st.scroll_off.remove(&p.id);
            st.scroll_sync.remove(&p.id);
            st.view_top.remove(&p.id);
        }
        st.drags.retain(|(_, pane), _| open.contains(pane.as_str()));
        for w in workspaces {
            st.revs.remove(w);
        }
    }
}

#[derive(Clone, Copy)]
enum RefreshMode<'a> {
    Full,
    Cache,
    Machines,
    Only(&'a str),
}

pub fn pwd_of(p: &Pane) -> &str {
    if !p.foreground_cwd.is_empty() {
        &p.foreground_cwd
    } else {
        &p.cwd
    }
}

pub fn process_owner(p: &Pane) -> Option<Value> {
    if p.foreground_pid == 0 && p.foreground_name.is_empty() {
        None
    } else {
        Some(json!({"pid": p.foreground_pid, "name": p.foreground_name}))
    }
}

fn detected(state: &str) -> bool {
    matches!(state, "idle" | "working" | "blocked" | "done" | "error")
}

fn attention(state: &str) -> Option<&'static str> {
    match state {
        "blocked" => Some("needs attention"),
        "done" => Some("finished"),
        _ => None,
    }
}

fn agent_name(p: &Pane) -> &str {
    if !p.display_agent.is_empty() {
        &p.display_agent
    } else if !p.agent.is_empty() {
        &p.agent
    } else {
        "agent"
    }
}

fn pane_context(s: &Snapshot, p: &Pane) -> String {
    let ws = s
        .workspaces
        .iter()
        .find(|w| w.id == p.workspace_id)
        .map(|w| w.label.as_str())
        .unwrap_or_default();
    let mut tabs = 0;
    let mut tab_lbl = "";
    for t in &s.tabs {
        if t.workspace_id == p.workspace_id {
            tabs += 1;
            if t.id == p.tab_id {
                tab_lbl = &t.label;
            }
        }
    }
    if tabs > 1 && !tab_lbl.is_empty() {
        format!("{ws} · {tab_lbl}")
    } else {
        ws.to_string()
    }
}

fn pane_status_recs(p: &Pane) -> Vec<StatusRec> {
    if !p.status_records.is_empty() {
        return p.status_records.clone();
    }
    if detected(&p.agent_status) {
        return vec![StatusRec {
            id: String::new(),
            state: p.agent_status.clone(),
            app: p.agent.clone(),
            title: p.status_title.clone(),
            msg: p.status_msg.clone(),
            kind: p.status_kind.clone(),
            progress: p.status_progress,
        }];
    }
    Vec::new()
}

fn rec_by_id(recs: &[StatusRec]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for r in recs {
        let mut s = format!("{}\0{}\0{}\0{}\0{}", r.state, r.app, r.title, r.msg, r.kind);
        if let Some(p) = r.progress {
            s.push('\0');
            s.push_str(&p.to_string());
        }
        m.insert(r.id.clone(), s);
    }
    m
}

fn signatures(s: &Snapshot) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for w in &s.workspaces {
        let mut ws = w.clone();
        ws.agent_status.clear();
        ws.focused = false;
        let ts: Vec<&Tab> = s.tabs.iter().filter(|t| t.workspace_id == w.id).collect();
        let ps: Vec<Value> = s
            .panes
            .iter()
            .filter(|p| p.workspace_id == w.id)
            .map(|p| {
                json!({
                    "id": p.id, "tab_id": p.tab_id, "workspace_id": p.workspace_id,
                    "focused": p.focused, "label": p.label,
                })
            })
            .collect();
        let ls: Vec<&TabLayout> = s.layouts.iter().filter(|l| l.workspace_id == w.id).collect();
        let sig = serde_json::to_string(&json!({"w": ws, "t": ts, "p": ps, "l": ls})).unwrap_or_default();
        out.insert(w.id.clone(), sig);
    }
    out
}

fn workspace_order(s: &Snapshot) -> Vec<String> {
    s.workspaces.iter().map(|w| w.id.clone()).collect()
}

fn panes_in(s: &Snapshot, wid: &str) -> HashMap<String, String> {
    s.panes
        .iter()
        .filter(|p| p.workspace_id == wid)
        .map(|p| (p.id.clone(), p.tab_id.clone()))
        .collect()
}

fn tabs_in(s: &Snapshot, wid: &str) -> HashMap<String, Tab> {
    s.tabs
        .iter()
        .filter(|t| t.workspace_id == wid)
        .map(|t| (t.id.clone(), t.clone()))
        .collect()
}

pub fn workspace_of<'a>(s: &'a Snapshot, wid: &str) -> Option<&'a Workspace> {
    s.workspaces.iter().find(|w| w.id == wid)
}

fn prune_floats_locked(floats: &mut HashMap<String, Vec<FloatLayer>>, snap: &Snapshot) {
    let where_map: HashMap<&str, &str> = snap.panes.iter().map(|p| (p.id.as_str(), p.tab_id.as_str())).collect();
    floats.retain(|tab, fs| {
        fs.retain(|f| where_map.get(f.pane_id.as_str()).copied() == Some(tab.as_str()));
        !fs.is_empty()
    });
}

fn longest_run<'a>(seq: &[&'a str], pos: &HashMap<&str, usize>) -> HashSet<&'a str> {
    let n = seq.len();
    if n == 0 {
        return HashSet::new();
    }
    let mut len = vec![1usize; n];
    let mut prev = vec![None::<usize>; n];
    let mut best = 0usize;
    for i in 0..n {
        for j in 0..i {
            if pos[seq[j]] < pos[seq[i]] && len[j] + 1 > len[i] {
                len[i] = len[j] + 1;
                prev[i] = Some(j);
            }
        }
        if len[i] > len[best] {
            best = i;
        }
    }
    let mut keep = HashSet::new();
    let mut cur = Some(best);
    while let Some(i) = cur {
        keep.insert(seq[i]);
        cur = prev[i];
    }
    keep
}
