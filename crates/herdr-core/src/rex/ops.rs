//! Rex control RPC handlers: sessions, windows, splits, navigation, floating layers,
//! block ownership, bootstrap tickets, and `herdr-app` doc mutations.

use super::appdoc::*;
use super::bridge::{FloatMark, REBALANCE_WINDOW, RexBridge, pwd_of, workspace_of};
use super::model::{FloatLayer, RexView};
use super::proto::*;
use super::server::{DataRequest, RexClient};
use crate::server::call_internal;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use uuid::Uuid;

pub const REX_VERSION: &str = "herdr-core-rex/0.1";

pub(crate) fn str_arg<'a>(p: &'a Value, k: &str) -> &'a str {
    p.get(k).and_then(Value::as_str).unwrap_or_default()
}

pub(crate) fn num_arg(p: &Value, k: &str) -> Option<f64> {
    p.get(k).and_then(Value::as_f64)
}

pub(crate) fn obj_arg<'a>(p: &'a Value, k: &str) -> Option<&'a Value> {
    p.get(k).filter(|v| v.is_object())
}

pub(crate) fn gone(e: &RexError) -> bool {
    e.code == CODE_NOT_FOUND || e.code == CODE_SESSION_NOT_FOUND
}

pub(crate) fn idle(e: &RexError) -> bool {
    gone(e)
        || (e.code == CODE_CONFLICT
            && (e.message.contains("no windows") || e.message.contains("no focused")))
}

impl RexBridge {
    pub fn status(&self) -> Value {
        let (n, kgen, khash) = {
            let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            (st.sigs.len(), st.keymap_gen.max(1), st.keymap_hash.clone())
        };
        json!({
            "pid": std::process::id(),
            "instance_id": self.instance,
            "host_id": self.ids.host_id,
            "started_at": stamp_rfc3339(SystemTime::now()),
            "exit_empty": false,
            "session_count": n,
            "api_revision": API_REVISION,
            "api_min_revision": API_MIN_REVISION,
            "tailscale": {"state": "disabled", "allow_tailnet_members": false},
            "config": {"generation": kgen, "hash": khash},
        })
    }

    pub async fn sessions(&self) -> Vec<Value> {
        let s = self.current().await;
        s.workspaces
            .iter()
            .map(|w| json!({"session_id": self.ids.rex("session", &w.id), "label": w.label}))
            .collect()
    }

    pub fn set_owners(&self, v: &mut RexView) {
        for win in &mut v.windows {
            for layer in &mut win.layers {
                for blk in &mut layer.blocks {
                    blk.owner = self.owner(&blk.block_id);
                }
            }
        }
    }

    pub fn tab_floats(&self, tab: &str) -> Vec<FloatLayer> {
        self.st
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .floats
            .get(tab)
            .cloned()
            .unwrap_or_default()
    }

    pub fn float_of(&self, tab: &str, pane: &str) -> Option<FloatLayer> {
        self.tab_floats(tab).into_iter().find(|f| f.pane_id == pane)
    }

    pub fn unfloat(&self, tab: &str, pane: &str) -> bool {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let Some(fs) = st.floats.get_mut(tab) else { return false };
        let before = fs.len();
        fs.retain(|f| f.pane_id != pane);
        fs.len() != before
    }

    pub fn mark_reflow(&self, tab: &str, client: &str) {
        self.st.lock().unwrap_or_else(|p| p.into_inner()).floated.insert(
            tab.to_string(),
            FloatMark { client: client.to_string(), at: Instant::now() },
        );
    }

    pub fn rebalance(&self, tab: &str, client: &str) -> bool {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let Some(m) = st.floated.remove(tab) else { return false };
        m.client == client && m.at.elapsed() <= REBALANCE_WINDOW
    }

    pub async fn view(&self, session_id: &str) -> Result<RexView, RexError> {
        let wid = self.herdr_id(session_id, "session")?;
        let s = self.current().await;
        let ws = workspace_of(&s, &wid)
            .ok_or_else(|| RexError::session_not_found(format!("unknown session {session_id}")))?;
        let rev = self.current_rev(&wid);
        let mut v = RexView {
            revision: rev,
            session_id: session_id.to_string(),
            label: ws.label.clone(),
            active_window_id: None,
            windows: Vec::new(),
        };
        let mut active = false;
        for t in &s.tabs {
            if t.workspace_id != wid {
                continue;
            }
            let Some(l) = self.tab_layout(&t.id) else {
                continue;
            };
            let Some((panes, root)) = agree(&t.id, &s.panes, &l) else {
                continue;
            };
            let floats = self.tab_floats(&t.id);
            v.windows.push(self.ids.window(t, &panes, &root, &floats));
            active = active || t.id == ws.active_tab_id;
        }
        self.set_owners(&mut v);
        if active {
            v.active_window_id = Some(self.ids.rex("window", &ws.active_tab_id));
        }
        Ok(v)
    }

    pub async fn attach(&self, c: &RexClient, ids: &[String]) -> Result<Vec<(RexView, Value)>, RexError> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for sid in ids {
            if !seen.insert(sid.as_str()) {
                continue;
            }
            let v = match self.view(sid).await {
                Ok(v) => v,
                Err(e) if e.code == CODE_SESSION_NOT_FOUND => continue,
                Err(e) => return Err(e),
            };
            self.srv.attach(c, sid);
            let val = json!({
                "session": {"session_id": sid, "label": v.label},
                "view": v,
            });
            out.push((v, val));
        }
        Ok(out)
    }

    pub async fn pane(&self, id: &str) -> Result<Pane, RexError> {
        if let Some(s) = self.snapshot()
            && let Some(p) = s.panes.into_iter().find(|p| p.id == id)
        {
            return Ok(p);
        }
        let rec = if let Some(t) = self.live_term(id) {
            t
        } else {
            let v = call_internal(&self.core, None, "terminal.get", json!({"terminal": id}))
                .await
                .map_err(|e| {
                    if e.kind == "not_found" {
                        RexError::not_found(format!("unknown pane {id}"))
                    } else {
                        RexError::from(e)
                    }
                })?;
            serde_json::from_value::<TerminalRec>(v)
                .map_err(|e| RexError::internal(format!("bad terminal record: {e}")))?
        };
        let mut p = Pane {
            id: rec.address.clone(),
            cwd: rec.cwd,
            pid: rec.pid,
            argv: rec.argv,
            terminal_title: rec.title,
            label: rec.name.filter(|n| !n.is_empty()).unwrap_or(rec.address),
            ..Pane::default()
        };
        if let Some(fg) = rec.foreground {
            p.foreground_name = fg.name;
            p.foreground_pid = fg.pid;
            p.foreground_argv = fg.argv;
            p.foreground_cwd = fg.cwd;
        }
        if let Some(st) = rec.status {
            p.agent_status = st.state;
            p.agent = st.app.clone();
            p.display_agent = st.app;
            p.status_title = st.title;
            p.status_msg = st.msg;
            p.status_kind = st.kind.unwrap_or_default();
            p.status_progress = st.progress.map(i64::from);
        }
        if let Some(ms) = rec.status_ms {
            p.status_updated_ms = ms as i64;
        }
        Ok(p)
    }

    pub async fn pane_of(&self, pane: &str) -> Result<Pane, RexError> {
        self.pane(pane).await.map_err(|e| {
            if e.code == CODE_NOT_FOUND {
                RexError::not_found("block is not in any window")
            } else {
                e
            }
        })
    }

    pub async fn block_or_focused(&self, p: &Value) -> Result<Pane, RexError> {
        let id = str_arg(p, "block_id");
        if !id.is_empty() {
            let h = self.herdr_id(id, "block")?;
            return self.pane_of(&h).await;
        }
        let ws = self.herdr_id(str_arg(p, "session_id"), "session")?;
        let s = self.current().await;
        let mut tab = workspace_of(&s, &ws)
            .map(|w| w.active_tab_id.clone())
            .unwrap_or_default();
        let wid = str_arg(p, "window_id");
        if !wid.is_empty() {
            tab = self.herdr_id(wid, "window")?;
        }
        let l = self
            .tab_layout(&tab)
            .ok_or_else(|| RexError::conflict("session has no focused block"))?;
        s.panes
            .into_iter()
            .find(|x| x.id == l.focused)
            .ok_or_else(|| RexError::conflict("session has no focused block"))
    }

    pub fn set_core_focus(&self, space: &str, tab: &str, addr: &str) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        if !space.is_empty() && !tab.is_empty() {
            st.active_tab.insert(space.to_string(), tab.to_string());
        }
        if !tab.is_empty() && !addr.is_empty() {
            st.active_pane.insert(tab.to_string(), addr.to_string());
        }
    }

    pub fn set_core_zoom(&self, tab: &str, zoomed: bool) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        if zoomed {
            st.zoomed.insert(tab.to_string(), true);
        } else {
            st.zoomed.remove(tab);
        }
    }

    pub fn session_machine(&self, sid: &str) -> String {
        if sid.is_empty() {
            return String::new();
        }
        self.herdr_id(sid, "session")
            .map(|space| self.on_of(&space))
            .unwrap_or_default()
    }

    pub async fn ack_rev(&self, session_id: &str) -> Value {
        let mut out = Map::new();
        if !session_id.is_empty()
            && let Ok(ws) = self.herdr_id(session_id, "session")
        {
            out.insert("revision".into(), json!(self.settle(&ws).await));
        }
        Value::Object(out)
    }

    pub async fn ack_close(&self, p: &Value, pane: &str) -> Value {
        let mut out = self
            .ack_rev(str_arg(p, "session_id"))
            .await
            .as_object()
            .cloned()
            .unwrap_or_default();
        if !pane.is_empty() {
            out.insert("block_id".into(), Value::String(self.ids.rex("block", pane)));
        } else {
            let id = str_arg(p, "block_id");
            if !id.is_empty() {
                out.insert("block_id".into(), Value::String(id.to_string()));
            }
        }
        Value::Object(out)
    }

    async fn core_where(&self, on: &str, space_id: &str, tab_id: &str) -> (String, String, String, String) {
        let home = self.machine_home(on);
        let mut folder = home.clone();
        let mut display = "~".to_string();
        let mut tab_lbl = "1".to_string();
        let raw = if let Some(pack) = self.pack(on) {
            pack.raw
        } else {
            let mut params = Map::new();
            params.insert("name".into(), Value::String(APP_DOC_NAME.into()));
            if !on.is_empty() {
                params.insert("on".into(), Value::String(on.to_string()));
            }
            match call_internal(&self.core, None, "doc.get", Value::Object(params)).await {
                Ok(d) => parse_doc(&d["value"]),
                Err(_) => return (folder, display.clone(), tab_lbl.clone(), where_label(&display, &tab_lbl)),
            }
        };
        if let Some(sp) = doc_space(&raw, space_id) {
            if let Some(f) = sp.get("folder").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                folder = f.to_string();
            }
            display = display_name(sp, &home);
            if let Some(tabs) = sp.get("tabs").and_then(Value::as_array) {
                for (i, t) in tabs.iter().enumerate() {
                    if let Some(m) = t.as_object()
                        && m.get("id").and_then(Value::as_str) == Some(tab_id)
                    {
                        tab_lbl = tab_name(m, i);
                        break;
                    }
                }
            }
        }
        let w = where_label(&display, &tab_lbl);
        (folder, display, tab_lbl, w)
    }

    async fn core_run(
        &self,
        on: &str,
        cwd: &str,
        space: &str,
        tab: &str,
        where_lbl: &str,
        argv: &[String],
    ) -> Result<String, RexError> {
        let mut params = Map::new();
        params.insert("keep".into(), json!(true));
        params.insert(
            "labels".into(),
            json!({
                "herdr.space": space,
                "herdr.tab": tab,
                "where": where_lbl,
            }),
        );
        if !cwd.is_empty() {
            params.insert("cwd".into(), Value::String(cwd.to_string()));
        }
        if !on.is_empty() {
            params.insert("on".into(), Value::String(on.to_string()));
        }
        if !argv.is_empty() {
            params.insert("argv".into(), json!(argv));
        }
        let res = call_internal(&self.core, None, "terminal.run", Value::Object(params)).await?;
        let addr = res["address"].as_str().unwrap_or_default().to_string();
        if !addr.is_empty() {
            let _ = call_internal(
                &self.core,
                None,
                "terminal.keep",
                json!({"terminal": addr, "keep": true}),
            )
            .await;
        }
        Ok(addr)
    }

    async fn core_kill(&self, on: &str, addrs: &[String]) {
        for a in addrs {
            let _ = call_internal(
                &self.core,
                None,
                "terminal.kill",
                json!({"terminal": qualify(a, on)}),
            )
            .await;
        }
    }

    async fn relabel_space(&self, on: &str, space_id: &str) {
        let home = self.machine_home(on);
        let raw = if let Some(p) = self.pack(on) {
            p.raw
        } else {
            let mut params = Map::new();
            params.insert("name".into(), Value::String(APP_DOC_NAME.into()));
            if !on.is_empty() {
                params.insert("on".into(), Value::String(on.to_string()));
            }
            match call_internal(&self.core, None, "doc.get", Value::Object(params)).await {
                Ok(d) => parse_doc(&d["value"]),
                Err(_) => return,
            }
        };
        let Some(sp) = doc_space(&raw, space_id) else { return };
        let display = display_name(sp, &home);
        for (i, t) in sp.get("tabs").and_then(Value::as_array).into_iter().flatten().enumerate() {
            let Some(tm) = t.as_object() else { continue };
            let tid = tm.get("id").and_then(Value::as_str).unwrap_or_default();
            let name = tab_name(tm, i);
            let w = where_label(&display, &name);
            let mut addrs = Vec::new();
            if let Some(root) = tm.get("root") {
                addresses_of(root, &mut addrs);
            }
            for addr in addrs {
                let _ = call_internal(
                    &self.core,
                    None,
                    "terminal.label",
                    json!({
                        "terminal": qualify(&addr, on),
                        "labels": {
                            "herdr.space": space_id,
                            "herdr.tab": tid,
                            "where": w,
                        }
                    }),
                )
                .await;
            }
        }
    }

    async fn core_window(&self, ws: &str, p: &Value) -> Result<String, RexError> {
        let wid = str_arg(p, "window_id");
        if !wid.is_empty() {
            return self.herdr_id(wid, "window");
        }
        let s = self.current().await;
        if let Some(w) = workspace_of(&s, ws)
            && !w.active_tab_id.is_empty()
        {
            return Ok(w.active_tab_id.clone());
        }
        Err(RexError::conflict("session has no windows"))
    }

    async fn active_tab(&self, sid: &str) -> Result<(String, String, Snapshot), RexError> {
        let ws = self.herdr_id(sid, "session")?;
        let s = self.current().await;
        let tab = workspace_of(&s, &ws)
            .map(|w| w.active_tab_id.clone())
            .unwrap_or_default();
        if tab.is_empty() {
            return Err(RexError::conflict("session has no windows"));
        }
        Ok((ws, tab, s))
    }

    async fn window_arg(&self, ws: &str, window_id: &str) -> Result<(String, Snapshot), RexError> {
        let s = self.current().await;
        if !window_id.is_empty() {
            let tab = self.herdr_id(window_id, "window")?;
            if !tab_in(&s, &tab, ws) {
                return Err(RexError::not_found("window is not in the session"));
            }
            return Ok((tab, s));
        }
        if let Some(w) = workspace_of(&s, ws)
            && !w.active_tab_id.is_empty()
        {
            return Ok((w.active_tab_id.clone(), s));
        }
        Err(RexError::conflict("session has no windows"))
    }

    #[allow(clippy::too_many_arguments)]
    async fn core_split_once(
        &self,
        on: &str,
        space: &str,
        tab: &str,
        folder: &str,
        anchor_addr: &str,
        direction: &str,
        side: &str,
        ratio: f64,
        layout: &Value,
    ) -> Result<String, RexError> {
        let mut cwd = leaf_cwd(layout);
        if cwd.is_empty() {
            cwd = folder.to_string();
        }
        let (_, _, _, where_lbl) = self.core_where(on, space, tab).await;
        let argv = leaf_command(layout);
        let q_addr = self.core_run(on, &cwd, space, tab, &where_lbl, &argv).await?;
        let addr = local_addr(&q_addr, on);
        let pane_id = fresh_id("p");
        let split_id = fresh_id("s");
        let target = local_addr(anchor_addr, on);
        let axis = rex_dir_axis(direction);
        let res = self
            .edit_doc(on, |doc| {
                if !doc_split_pane(doc, &target, axis, &pane_id, &addr, &split_id, side, ratio) {
                    return Err(RexError::not_found("anchor is not in the layout"));
                }
                Ok(())
            })
            .await;
        if let Err(e) = res {
            self.core_kill(on, &[addr]).await;
            return Err(e);
        }
        Ok(qualify(&addr, on))
    }

    fn core_fill<'a>(
        &'a self,
        on: &'a str,
        space: &'a str,
        tab: &'a str,
        folder: &'a str,
        pane: String,
        n: &'a Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>, RexError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(blk) = obj_arg(n, "block") {
                let l = str_arg(blk, "label").trim().to_string();
                if !l.is_empty() {
                    let local = local_addr(&pane, on);
                    let _: Result<_, RexError> = self
                        .edit_doc(on, |doc| {
                            doc_set_pane_title(doc, &local, &l);
                            Ok(())
                        })
                        .await;
                }
                return Ok(vec![self.ids.rex("block", &pane)]);
            }
            let Some(sp) = obj_arg(n, "split") else {
                return Ok(vec![self.ids.rex("block", &pane)]);
            };
            let ratio = num_arg(sp, "ratio").unwrap_or(0.5);
            let dir = str_arg(sp, "direction");
            let after = obj_arg(sp, "after").unwrap_or(&Value::Null);
            let before = obj_arg(sp, "before").unwrap_or(&Value::Null);
            let other = self
                .core_split_once(on, space, tab, folder, &pane, dir, "after", ratio, after)
                .await?;
            let mut first = self.core_fill(on, space, tab, folder, pane, before).await?;
            let second = self.core_fill(on, space, tab, folder, other, after).await?;
            first.extend(second);
            Ok(first)
        })
    }

    pub fn placement(&self, p: &Pane) -> Value {
        let blk = self.ids.block(p);
        let mut m = Map::new();
        m.insert("placement".into(), Value::String("placed".into()));
        m.insert("window_id".into(), Value::String(self.ids.rex("window", &p.tab_id)));
        m.insert("block_id".into(), Value::String(blk.block_id.clone()));
        m.insert("label".into(), Value::String(blk.label));
        m.insert("creator_name".into(), Value::String(blk.creator_name));
        m.insert("flavor".into(), Value::String(blk.flavor));
        m.insert("host_id".into(), Value::String(blk.host_id));
        let o = self.owner(&blk.block_id);
        if !o.is_empty() {
            m.insert("owner".into(), Value::String(o));
        }
        Value::Object(m)
    }

    fn layer_arg(&self, p: &Value, key: &str, op: &str) -> Result<(String, String), RexError> {
        let ws = self.herdr_id(str_arg(p, "session_id"), "session")?;
        let id = str_arg(p, key);
        let s = self.snapshot();
        if let Some(t) = self.ids.herdr(id)
            && let Some(snap) = &s
        {
            for x in &snap.tabs {
                if x.id == t && x.workspace_id == ws && self.ids.rex("layer", &t) == id {
                    return Err(RexError::bad_request(format!("cannot {op} tiled layer {id}")));
                }
            }
        }
        let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        for (t, fs) in &st.floats {
            for f in fs {
                if f.layer_id == id && s.as_ref().is_some_and(|sn| tab_in(sn, t, &ws)) {
                    return Ok((ws, t.clone()));
                }
            }
        }
        Err(RexError::not_found(format!("layer {id} not found")))
    }

    fn split_above(&self, tab: &str, pane: &str) -> String {
        let Some(l) = self.tab_layout(tab) else { return String::new() };
        let Some(pth) = path_to(&l, pane) else { return String::new() };
        if pth.is_empty() {
            return String::new();
        }
        self.ids.split_id(tab, &pth[..pth.len() - 1])
    }

    async fn bootstrap_tickets(
        &self,
        c: &Arc<RexClient>,
        out: &mut Map<String, Value>,
        attached: &[(RexView, Value)],
        requests: &[BootstrapRequest],
    ) {
        if requests.is_empty() {
            return;
        }
        let mut tickets = Vec::new();
        let mut seen = HashSet::new();
        for (view, _) in attached {
            for win in &view.windows {
                if view.active_window_id.as_deref() != Some(win.window_id.as_str()) {
                    continue;
                }
                for layer in &win.layers {
                    for blk in &layer.blocks {
                        if let Some(z) = &win.zoomed_block_id
                            && blk.block_id != *z
                        {
                            continue;
                        }
                        for req in requests {
                            if blk.creator_name != req.creator {
                                continue;
                            }
                            let key = (
                                view.session_id.clone(),
                                blk.block_id.clone(),
                                req.data_ref.clone(),
                                req.subprotocol.clone(),
                            );
                            if !seen.insert(key) {
                                continue;
                            }
                            let dr = DataRequest {
                                session_id: view.session_id.clone(),
                                block_id: blk.block_id.clone(),
                                data_ref_id: req.data_ref.clone(),
                                subprotocol: req.subprotocol.clone(),
                            };
                            if let Ok(tk) = self.srv.issue_data_ticket(c.clone(), dr.clone()).await {
                                let mut m = Map::new();
                                m.insert("ticket".into(), Value::String(tk.ticket));
                                m.insert("expires_in_ms".into(), json!(tk.expires_in_ms));
                                m.insert("session_id".into(), Value::String(dr.session_id));
                                m.insert("block_id".into(), Value::String(dr.block_id));
                                m.insert("data_ref_id".into(), Value::String(dr.data_ref_id));
                                if !dr.subprotocol.is_empty() {
                                    m.insert("subprotocol".into(), Value::String(dr.subprotocol));
                                }
                                tickets.push(Value::Object(m));
                            }
                        }
                    }
                }
            }
        }
        if !tickets.is_empty() {
            out.insert("data_tickets".into(), Value::Array(tickets));
        }
    }
}

struct BootstrapRequest {
    creator: String,
    data_ref: String,
    subprotocol: String,
}

fn bootstrap_requests(raw: Option<&Value>) -> Result<Vec<BootstrapRequest>, RexError> {
    let Some(raw) = raw.filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let Some(items) = raw.as_array() else {
        return Err(RexError::bad_request("data_tickets must be an array of at most 8 entries"));
    };
    if items.len() > 8 {
        return Err(RexError::bad_request("data_tickets must be an array of at most 8 entries"));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(obj) = item.as_object() else {
            return Err(RexError::bad_request("data_tickets entries must be objects"));
        };
        let creator = obj.get("creator_name").and_then(Value::as_str).unwrap_or_default();
        let data_ref = obj.get("data_ref_id").and_then(Value::as_str).unwrap_or_default();
        let subprotocol = match obj.get("subprotocol") {
            None => String::new(),
            Some(v) => v
                .as_str()
                .ok_or_else(|| {
                    RexError::bad_request(
                        "data_tickets entries need creator_name and data_ref_id strings, and an optional subprotocol string",
                    )
                })?
                .to_string(),
        };
        if creator.is_empty() || data_ref.is_empty() {
            return Err(RexError::bad_request(
                "data_tickets entries need creator_name and data_ref_id strings, and an optional subprotocol string",
            ));
        }
        out.push(BootstrapRequest {
            creator: creator.to_string(),
            data_ref: data_ref.to_string(),
            subprotocol,
        });
    }
    Ok(out)
}

// =========================================================================
// Control RPC Handlers
// =========================================================================

pub async fn h_status(b: &RexBridge) -> Result<Value, RexError> {
    Ok(b.status())
}

pub async fn h_version() -> Result<Value, RexError> {
    Ok(json!({
        "rex_version": REX_VERSION,
        "platform": format!("{}_{}", std::env::consts::OS, std::env::consts::ARCH),
        "dirty": false,
        "api_revision": API_REVISION,
        "api_min_revision": API_MIN_REVISION,
    }))
}

pub async fn h_list(b: &RexBridge) -> Result<Value, RexError> {
    Ok(json!({"sessions": b.sessions().await}))
}

pub async fn h_view(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let v = b.view(str_arg(p, "session_id")).await?;
    Ok(serde_json::to_value(v).unwrap_or_else(|_| json!({})))
}

pub async fn h_attach(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    b.herdr_id(sid, "session")?;
    let r = b.attach(c, &[sid.to_string()]).await?;
    let Some((v, _)) = r.into_iter().next() else {
        return Err(RexError::session_not_found(format!("unknown session {sid}")));
    };
    Ok(json!({"client_id": c.id, "view": v}))
}

pub async fn h_attach_all(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    b.srv.attach_all(c, str_arg(p, "event_scope"))?;
    Ok(json!({"sessions": b.sessions().await}))
}

pub async fn h_bootstrap(
    b: &Arc<RexBridge>,
    c: &Arc<RexClient>,
    p: &Value,
) -> Result<Value, RexError> {
    let requests = bootstrap_requests(p.get("data_tickets"))?;
    b.srv.attach_all(c, str_arg(p, "event_scope"))?;
    let ss = b.sessions().await;
    let mut out = Map::new();
    out.insert("client_id".into(), Value::String(c.id.clone()));
    out.insert("server_status".into(), b.status());
    out.insert("attach_all".into(), json!({"sessions": ss}));
    out.insert("selected_session".into(), Value::Null);

    if let Some(raw) = p.get("attach_session_ids").and_then(Value::as_array) {
        let ids: Vec<String> = raw.iter().filter_map(Value::as_str).map(String::from).collect();
        let attached = b.attach(c, &ids).await?;
        let vals: Vec<Value> = attached.iter().map(|(_, v)| v.clone()).collect();
        out.insert("attached_sessions".into(), Value::Array(vals));
        b.bootstrap_tickets(c, &mut out, &attached, &requests).await;
        return Ok(Value::Object(out));
    }

    let pref = str_arg(p, "preferred_session_id");
    let mut pick = String::new();
    if !pref.is_empty() && ss.iter().any(|s| s["session_id"].as_str() == Some(pref)) {
        pick = pref.to_string();
    } else if let Some(first) = ss.first().and_then(|s| s["session_id"].as_str()) {
        pick = first.to_string();
    }
    if !pick.is_empty() {
        let attached = b.attach(c, std::slice::from_ref(&pick)).await?;
        if attached.is_empty() {
            return Err(RexError::session_not_found(format!("unknown session {pick}")));
        }
        out.insert("selected_session".into(), attached[0].1.clone());
        b.bootstrap_tickets(c, &mut out, &attached, &requests).await;
    }
    Ok(Value::Object(out))
}

pub async fn h_creators(b: &RexBridge) -> Result<Value, RexError> {
    Ok(json!({"creators": [b.ids.creator_info()]}))
}

pub async fn h_session_help(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    b.herdr_id(str_arg(p, "session_id"), "session")?;
    Ok(b.srv.describe_help(false))
}

pub async fn h_list_clients(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    b.herdr_id(sid, "session")?;
    let out: Vec<Value> = b
        .srv
        .clients()
        .into_iter()
        .filter(|o| o.attached(sid))
        .map(|o| o.describe(sid))
        .collect();
    Ok(json!({"clients": out}))
}

pub async fn h_list_blocks(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let w = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let s = b.current().await;
    let out: Vec<Value> = s
        .panes
        .iter()
        .filter(|x| x.workspace_id == w)
        .map(|x| b.placement(x))
        .collect();
    Ok(json!({"blocks": out}))
}

pub async fn h_describe_block(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let pane = b.herdr_id(str_arg(p, "block_id"), "block")?;
    let x = b.pane(&pane).await.map_err(|e| {
        if e.code == CODE_NOT_FOUND {
            RexError::not_found("block not found")
        } else {
            e
        }
    })?;
    let info = b.ids.creator_info();
    Ok(json!({"block": b.placement(&x), "api": info["api"]}))
}

pub async fn h_create(b: &Arc<RexBridge>, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    struct InitWin {
        label: String,
        layout: Value,
    }
    let specs: Vec<InitWin> = if let Some(raw) = p.get("initial_windows").and_then(Value::as_array)
        && !raw.is_empty()
    {
        let mut v = Vec::with_capacity(raw.len());
        for item in raw {
            if !item.is_object() {
                return Err(RexError::bad_request("initial_windows item must be an object"));
            }
            let lay = obj_arg(item, "layout")
                .cloned()
                .unwrap_or_else(|| json!({"block": {"flavor": SHELL_FLAVOR}}));
            check_layout(&lay)?;
            v.push(InitWin {
                label: str_arg(item, "window_label").trim().to_string(),
                layout: lay,
            });
        }
        v
    } else {
        vec![InitWin {
            label: String::new(),
            layout: json!({"block": {"flavor": SHELL_FLAVOR}}),
        }]
    };

    let home = b.local_home();
    let label = str_arg(p, "label").trim().to_string();
    let mut last_on = b.session_machine(str_arg(p, "session_id"));
    if last_on.is_empty() {
        last_on = b.session_machine(&c.last_session());
    }
    let on_arg = if p.get("on").is_some() { str_arg(p, "on") } else { "" };
    let machines = b.connected_machines();
    let (on, mut name) = create_target(&label, on_arg, &last_on, &b.core.info.name, &machines);
    if name.is_empty() && !on.is_empty() {
        name = "new".into();
    }
    let where_name = if name.is_empty() {
        folder_name(&home, &home)
    } else {
        name.clone()
    };
    let space_id = fresh_id("sp");
    let (default_cwd, mut folder) = if on.is_empty() {
        (home.clone(), home.clone())
    } else {
        (String::new(), String::new())
    };
    let first_cwd = leaf_cwd(&specs[0].layout);
    if !first_cwd.is_empty() && folder.is_empty() {
        folder = first_cwd;
    }

    struct StartedWin {
        tab_id: String,
        q_addr: String,
        layout: Value,
    }
    let mut started = Vec::with_capacity(specs.len());
    let mut started_local = Vec::new();
    let mut tabs = Vec::with_capacity(specs.len());

    for (i, sp) in specs.into_iter().enumerate() {
        let tab_id = fresh_id("tb");
        let pane_id = fresh_id("p");
        let tab_shown = if sp.label.is_empty() {
            tab_name(&Map::new(), i)
        } else {
            sp.label.clone()
        };
        let mut cwd = leaf_cwd(&sp.layout);
        if cwd.is_empty() {
            cwd = default_cwd.clone();
        }
        let w_lbl = where_label(&where_name, &tab_shown);
        let argv = leaf_command(&sp.layout);
        let q_addr = match b.core_run(&on, &cwd, &space_id, &tab_id, &w_lbl, &argv).await {
            Ok(a) => a,
            Err(e) => {
                b.core_kill(&on, &started_local).await;
                return Err(e);
            }
        };
        let addr = local_addr(&q_addr, &on);
        started_local.push(addr.clone());
        tabs.push(make_tab(&tab_id, &sp.label, make_block(&pane_id, &addr)));
        started.push(StartedWin { tab_id, q_addr, layout: sp.layout });
    }

    let space = make_space(&space_id, &name, &folder, tabs);
    let res: Result<_, RexError> = b
        .edit_doc(&on, |doc| {
            doc_append_space(doc, space.clone());
            Ok(())
        })
        .await;
    if let Err(e) = res {
        b.core_kill(&on, &started_local).await;
        return Err(e);
    }

    let mut all_blocks = Vec::new();
    let mut win_blocks = Vec::with_capacity(started.len());
    for sw in &started {
        let blocks = b
            .core_fill(&on, &space_id, &sw.tab_id, &folder, sw.q_addr.clone(), &sw.layout)
            .await?;
        all_blocks.extend(blocks.iter().cloned());
        win_blocks.push(blocks);
    }
    if let Some(last) = started.last() {
        b.set_core_focus(&space_id, &last.tab_id, &last.q_addr);
    }
    b.claim(c, &space_id, &all_blocks).await;
    let rev = b.settle(&space_id).await;
    let out_wins: Vec<Value> = started
        .iter()
        .zip(win_blocks)
        .map(|(sw, blks)| {
            json!({
                "window_id": b.ids.rex("window", &sw.tab_id),
                "block_ids": blks,
                "revision": rev,
            })
        })
        .collect();
    Ok(json!({
        "session_id": b.ids.rex("session", &space_id),
        "initial_windows": out_wins,
    }))
}

pub async fn h_destroy(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let w = match b.herdr_id(str_arg(p, "session_id"), "session") {
        Ok(w) => w,
        Err(e) if gone(&e) => return Ok(json!({})),
        Err(e) => return Err(e),
    };
    let on = b.on_of(&w);
    let mut addrs = Vec::new();
    let res: Result<_, RexError> = b
        .edit_doc(&on, |doc| {
            let Some(a) = doc_close_space(doc, &w) else {
                return Err(RexError::session_not_found("unknown session"));
            };
            addrs = a;
            Ok(())
        })
        .await;
    match res {
        Ok(_) => {}
        Err(e) if gone(&e) => return Ok(json!({})),
        Err(e) => return Err(e),
    }
    b.core_kill(&on, &addrs).await;
    b.settle(&w).await;
    Ok(json!({}))
}

pub async fn h_set_label(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let w = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let on = b.on_of(&w);
    let label = str_arg(p, "label");
    b.edit_doc(&on, |doc| {
        if !doc_rename_space(doc, &w, label) {
            return Err(RexError::session_not_found("unknown session"));
        }
        Ok(())
    })
    .await?;
    b.relabel_space(&on, &w).await;
    Ok(json!({"revision": b.settle(&w).await}))
}

pub async fn h_new_window(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let w = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let layout = obj_arg(p, "layout")
        .cloned()
        .unwrap_or_else(|| json!({"block": {"flavor": SHELL_FLAVOR}}));
    check_layout(&layout)?;
    let on = b.on_of(&w);
    let tab_id = fresh_id("tb");
    let pane_id = fresh_id("p");
    let (folder, display, _, _) = b.core_where(&on, &w, "").await;
    let mut cwd = leaf_cwd(&layout);
    if cwd.is_empty() {
        cwd = folder.clone();
    }
    let tab_label = str_arg(p, "window_label").trim().to_string();
    let tab_shown = if tab_label.is_empty() { "1" } else { tab_label.as_str() };
    let w_lbl = where_label(&display, tab_shown);
    let argv = leaf_command(&layout);
    let q_addr = b.core_run(&on, &cwd, &w, &tab_id, &w_lbl, &argv).await?;
    let addr = local_addr(&q_addr, &on);
    let tab = make_tab(&tab_id, &tab_label, make_block(&pane_id, &addr));
    let res = b
        .edit_doc(&on, |doc| {
            if !doc_append_tab(doc, &w, tab.clone(), "") {
                return Err(RexError::session_not_found("unknown session"));
            }
            Ok(())
        })
        .await;
    if let Err(e) = res {
        b.core_kill(&on, &[addr]).await;
        return Err(e);
    }
    let q = qualify(&addr, &on);
    let focus = p.get("focus").and_then(Value::as_bool).unwrap_or(true);
    if focus {
        b.set_core_focus(&w, &tab_id, &q);
    }
    let blocks = b.core_fill(&on, &w, &tab_id, &folder, q, &layout).await?;
    b.claim(c, &w, &blocks).await;
    Ok(json!({
        "window_id": b.ids.rex("window", &tab_id),
        "block_ids": blocks,
        "revision": b.settle(&w).await,
    }))
}

pub async fn h_close_window(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let ws = match b.herdr_id(sid, "session") {
        Ok(ws) => ws,
        Err(e) if gone(&e) => return Ok(b.ack_rev(sid).await),
        Err(e) => return Err(e),
    };
    let tab = match b.core_window(&ws, p).await {
        Ok(t) => t,
        Err(e) if gone(&e) => return Ok(json!({"revision": b.settle(&ws).await})),
        Err(e) => return Err(e),
    };
    let on = b.on_of(&ws);
    let mut addrs = Vec::new();
    let res = b
        .edit_doc(&on, |doc| {
            let Some((a, _)) = doc_close_tab(doc, &tab) else {
                return Err(RexError::not_found("window is not in the session"));
            };
            addrs = a;
            Ok(())
        })
        .await;
    match res {
        Ok(_) => {}
        Err(e) if gone(&e) => return Ok(json!({"revision": b.settle(&ws).await})),
        Err(e) => return Err(e),
    }
    b.core_kill(&on, &addrs).await;
    Ok(json!({"revision": b.settle(&ws).await}))
}

pub async fn h_rename_window(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let ws = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let tab = b.core_window(&ws, p).await?;
    let on = b.on_of(&ws);
    let label = str_arg(p, "label");
    b.edit_doc(&on, |doc| {
        if !doc_rename_tab(doc, &tab, label) {
            return Err(RexError::not_found("window is not in the session"));
        }
        Ok(())
    })
    .await?;
    b.relabel_space(&on, &ws).await;
    Ok(json!({"revision": b.settle(&ws).await}))
}

pub async fn h_focus_window(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let ws = match b.herdr_id(sid, "session") {
        Ok(ws) => ws,
        Err(e) if idle(&e) => return Ok(b.ack_rev(sid).await),
        Err(e) => return Err(e),
    };
    let tab = match b.core_window(&ws, p).await {
        Ok(t) => t,
        Err(e) if idle(&e) => return Ok(json!({"revision": b.settle(&ws).await})),
        Err(e) => return Err(e),
    };
    let addr = b
        .st
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .active_pane
        .get(&tab)
        .cloned()
        .unwrap_or_default();
    b.set_core_focus(&ws, &tab, &addr);
    Ok(json!({"revision": b.settle(&ws).await}))
}

pub async fn h_new_split(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let anchor_id = str_arg(p, "anchor_id");
    let window_id = str_arg(p, "window_id");
    if !anchor_id.is_empty() && !window_id.is_empty() {
        return Err(RexError::bad_request("send anchor_id or window_id, not both"));
    }
    if anchor_id.starts_with("split:") {
        return Err(RexError::bad_request("can only split a block, not a split"));
    }
    let dir = str_arg(p, "direction");
    if dir != "horizontal" && dir != "vertical" {
        return Err(RexError::bad_request(r#"direction must be "horizontal" or "vertical""#));
    }
    let side = str_arg(p, "side");
    if side != "before" && side != "after" {
        return Err(RexError::bad_request(r#"side must be "before" or "after""#));
    }
    let layout = obj_arg(p, "layout").ok_or_else(|| RexError::bad_request("layout is required"))?;
    check_layout(layout)?;
    let ratio = match num_arg(p, "ratio") {
        Some(r) if r > 0.0 && r < 1.0 => r,
        Some(_) => return Err(RexError::bad_request("ratio must be between 0 and 1")),
        None => 0.5,
    };
    let anchor = b
        .block_or_focused(&json!({
            "block_id": anchor_id,
            "session_id": str_arg(p, "session_id"),
            "window_id": window_id,
        }))
        .await?;
    let on = b.on_of(&anchor.workspace_id);
    let (folder, _, _, _) = b.core_where(&on, &anchor.workspace_id, &anchor.tab_id).await;
    let new_addr = b
        .core_split_once(&on, &anchor.workspace_id, &anchor.tab_id, &folder, &anchor.id, dir, side, ratio, layout)
        .await?;
    let blocks = b
        .core_fill(&on, &anchor.workspace_id, &anchor.tab_id, &folder, new_addr, layout)
        .await?;
    if p.get("focus").and_then(Value::as_bool).unwrap_or(false)
        && let Some(first) = blocks.first()
        && let Some(h) = b.ids.herdr(first)
    {
        b.set_core_focus(&anchor.workspace_id, &anchor.tab_id, &h);
    }
    b.claim(c, &anchor.workspace_id, &blocks).await;
    Ok(json!({
        "anchor_id": b.ids.rex("block", &anchor.id),
        "block_ids": blocks,
        "split_ids": [],
        "revision": b.settle(&anchor.workspace_id).await,
    }))
}

pub async fn h_block_close(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let x = match b.block_or_focused(p).await {
        Ok(x) => x,
        Err(e) if gone(&e) => return Ok(b.ack_close(p, "").await),
        Err(e) => return Err(e),
    };
    let on = b.on_of(&x.workspace_id);
    let local = local_addr(&x.id, &on);
    let mut addrs = Vec::new();
    let res = b
        .edit_doc(&on, |doc| {
            let Some((a, _, _)) = doc_close_pane(doc, &local) else {
                return Err(RexError::not_found("block is not in any window"));
            };
            addrs = a;
            Ok(())
        })
        .await;
    match res {
        Ok(_) => {}
        Err(e) if gone(&e) => return Ok(b.ack_close(p, &x.id).await),
        Err(e) => return Err(e),
    }
    b.core_kill(&on, &addrs).await;
    Ok(json!({
        "block_id": b.ids.rex("block", &x.id),
        "revision": b.settle(&x.workspace_id).await,
    }))
}

pub async fn h_set_block_label(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    if str_arg(p, "block_id").is_empty() {
        return Err(RexError::bad_request("block_id is required"));
    }
    let x = b.block_or_focused(p).await?;
    let on = b.on_of(&x.workspace_id);
    let local = local_addr(&x.id, &on);
    let label = str_arg(p, "label");
    b.edit_doc(&on, |doc| {
        if !doc_set_pane_title(doc, &local, label) {
            return Err(RexError::not_found("block is not in any window"));
        }
        Ok(())
    })
    .await?;
    Ok(json!({"revision": b.settle(&x.workspace_id).await}))
}

pub async fn h_swap(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let a = b.herdr_id(str_arg(p, "block_id"), "block")?;
    let o = b.herdr_id(str_arg(p, "other_block_id"), "block")?;
    let x = b.pane_of(&a).await?;
    let on = b.on_of(&x.workspace_id);
    let la = local_addr(&a, &on);
    let lo = local_addr(&o, &on);
    b.edit_doc(&on, |doc| {
        if !doc_swap_panes(doc, &la, &lo) {
            return Err(RexError::bad_request("cannot swap these blocks"));
        }
        Ok(())
    })
    .await?;
    Ok(json!({"revision": b.settle(&x.workspace_id).await}))
}

pub async fn h_resize_pane(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let before = b.herdr_id(str_arg(p, "before_block_id"), "block")?;
    let after = b.herdr_id(str_arg(p, "after_block_id"), "block")?;
    let ratio = num_arg(p, "ratio").unwrap_or(0.0);
    if before == after || ratio <= 0.0 || ratio >= 1.0 {
        return Err(RexError::bad_request("need two different blocks and 0 < ratio < 1"));
    }
    let pn = b.pane_of(&before).await?;
    if b.rebalance(&pn.tab_id, &c.id) {
        return Ok(json!({"revision": b.current_rev(&pn.workspace_id)}));
    }
    let axis = if str_arg(p, "direction") == "horizontal" { "row" } else { "column" };
    let on = b.on_of(&pn.workspace_id);
    let lb = local_addr(&before, &on);
    let la = local_addr(&after, &on);
    b.edit_doc(&on, |doc| {
        if !doc_set_split_ratio(doc, &lb, &la, axis, ratio) {
            return Err(RexError::bad_request("no split between these blocks"));
        }
        Ok(())
    })
    .await?;
    Ok(json!({"revision": b.settle(&pn.workspace_id).await}))
}

pub async fn h_zoom(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let x = match b.block_or_focused(p).await {
        Ok(x) => x,
        Err(e) if gone(&e) => return Ok(b.ack_rev(str_arg(p, "session_id")).await),
        Err(e) => return Err(e),
    };
    let cur = {
        let st = b.st.lock().unwrap_or_else(|p| p.into_inner());
        let was = st.zoomed.get(&x.tab_id).copied().unwrap_or(false);
        match p.get("zoom").and_then(Value::as_bool) {
            Some(z) => z,
            None => !was,
        }
    };
    b.set_core_zoom(&x.tab_id, cur);
    b.set_core_focus(&x.workspace_id, &x.tab_id, &x.id);
    Ok(json!({
        "block_id": b.ids.rex("block", &x.id),
        "zoomed": cur,
        "revision": b.settle(&x.workspace_id).await,
    }))
}

pub async fn h_focus_block(b: &RexBridge, _c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let x = match b.block_or_focused(p).await {
        Ok(x) => x,
        Err(e) if gone(&e) => return Ok(b.ack_rev(str_arg(p, "session_id")).await),
        Err(e) => return Err(e),
    };
    b.set_core_focus(&x.workspace_id, &x.tab_id, &x.id);
    Ok(json!({"revision": b.settle(&x.workspace_id).await}))
}

pub async fn h_move(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let ws = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let before = {
        let id = str_arg(p, "before_session_id");
        if id.is_empty() { String::new() } else { b.herdr_id(id, "session")? }
    };
    let on = b.on_of(&ws);
    if !before.is_empty() && b.on_of(&before) != on {
        return Err(RexError::bad_request("cannot move a session onto another machine"));
    }
    b.edit_doc(&on, |doc| {
        if !doc_move_spaces(doc, std::slice::from_ref(&ws), &before) {
            return Err(RexError::session_not_found("unknown session"));
        }
        Ok(())
    })
    .await?;
    b.settle(&ws).await;
    Ok(json!({}))
}

pub async fn h_move_window(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let (ws, mut tab, s) = b.active_tab(str_arg(p, "session_id")).await?;
    let wid = str_arg(p, "window_id");
    if !wid.is_empty() {
        tab = b.herdr_id(wid, "window")?;
    }
    let before = {
        let id = str_arg(p, "before_window_id");
        if id.is_empty() { String::new() } else { b.herdr_id(id, "window")? }
    };
    let order: Vec<&str> = s.tabs.iter().filter(|t| t.workspace_id == ws).map(|t| t.id.as_str()).collect();
    let idx = if before.is_empty() {
        order.len()
    } else {
        order
            .iter()
            .position(|&x| x == before)
            .ok_or_else(|| RexError::not_found("window is not in the session"))?
    };
    let on = b.on_of(&ws);
    b.edit_doc(&on, |doc| {
        if !doc_move_tab(doc, &tab, idx) {
            return Err(RexError::not_found("window is not in the session"));
        }
        Ok(())
    })
    .await?;
    Ok(json!({"revision": b.settle(&ws).await}))
}

pub async fn h_focus_pane_step(b: &RexBridge, p: &Value, delta: isize) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let (ws, tab, _) = match b.active_tab(sid).await {
        Ok(x) => x,
        Err(e) if idle(&e) => return Ok(b.ack_rev(sid).await),
        Err(e) => return Err(e),
    };
    let Some(l) = b.tab_layout(&tab) else {
        return Ok(b.ack_rev(sid).await);
    };
    let wrap = p.get("wrap").and_then(Value::as_bool).unwrap_or(false);
    let mut order = Vec::new();
    collect_leaves(&l, &mut order);
    if !order.is_empty() {
        let i = order.iter().position(|id| id == &l.focused).unwrap_or(0);
        let j = step_idx(i, delta, order.len(), wrap);
        if j != i {
            b.set_core_focus(&ws, &tab, &order[j]);
        }
    }
    Ok(json!({"revision": b.settle(&ws).await}))
}

pub async fn h_focus_window_step(b: &RexBridge, p: &Value, delta: isize) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let (ws, tab, s) = match b.active_tab(sid).await {
        Ok(x) => x,
        Err(e) if idle(&e) => return Ok(b.ack_rev(sid).await),
        Err(e) => return Err(e),
    };
    let wrap = p.get("wrap").and_then(Value::as_bool).unwrap_or(false);
    let tabs: Vec<&str> = s.tabs.iter().filter(|t| t.workspace_id == ws).map(|t| t.id.as_str()).collect();
    if !tabs.is_empty() {
        let i = tabs.iter().position(|&id| id == tab).unwrap_or(0);
        let j = step_idx(i, delta, tabs.len(), wrap);
        if j != i {
            let addr = b
                .st
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .active_pane
                .get(tabs[j])
                .cloned()
                .unwrap_or_default();
            b.set_core_focus(&ws, tabs[j], &addr);
        }
    }
    Ok(json!({"revision": b.settle(&ws).await}))
}

pub async fn h_focus_direction(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let dir = str_arg(p, "direction");
    if !matches!(dir, "left" | "right" | "up" | "down") {
        return Err(RexError::bad_request(r#"direction must be "left", "right", "up" or "down""#));
    }
    let sid = str_arg(p, "session_id");
    let (ws, tab, s) = match b.active_tab(sid).await {
        Ok(x) => x,
        Err(e) if idle(&e) => return Ok(b.ack_rev(sid).await),
        Err(e) => return Err(e),
    };
    let Some(l) = b.tab_layout(&tab) else {
        return Ok(b.ack_rev(sid).await);
    };
    let mut t = nearest_pane(&s, &tab, &l.focused, dir);
    if t.is_empty() && p.get("wrap").and_then(Value::as_bool).unwrap_or(false) {
        t = wrap_target(&s, &tab, &l.focused, dir);
    }
    if !t.is_empty() {
        b.set_core_focus(&ws, &tab, &t);
    }
    Ok(json!({"revision": b.settle(&ws).await}))
}

// =========================================================================
// Ownership
// =========================================================================

pub async fn h_own_block(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let wid = b.herdr_id(sid, "session")?;
    let mode = str_arg(p, "mode");
    if mode != "take" && mode != "request" {
        return Err(RexError::bad_request(format!(
            r#"unknown mode "{mode}": expected "take" or "request""#
        )));
    }
    let mut ids = Vec::new();
    if let Some(raw) = p.get("block_ids").and_then(Value::as_array)
        && !raw.is_empty()
    {
        for x in raw {
            let id = x.as_str().unwrap_or_default();
            b.herdr_id(id, "block")?;
            ids.push(id.to_string());
        }
    } else {
        let snap = b.current().await;
        for x in &snap.panes {
            if x.workspace_id == wid {
                ids.push(b.ids.rex("block", &x.id));
            }
        }
    }
    let mut out = Vec::with_capacity(ids.len());
    let mut changed = false;
    for id in ids {
        let (set, prev, owner) = {
            let mut st = b.st.lock().unwrap_or_else(|p| p.into_inner());
            let prev = st.owners.get(&id).cloned().unwrap_or_default();
            let set = prev != c.id && (mode == "take" || prev.is_empty());
            if set {
                st.owners.insert(id.clone(), c.id.clone());
            }
            let owner = st.owners.get(&id).cloned().unwrap_or_default();
            (set, prev, owner)
        };
        if set {
            let mut ev = Map::new();
            ev.insert("block_id".into(), Value::String(id.clone()));
            ev.insert("owner".into(), Value::String(c.id.clone()));
            ev.insert("reason".into(), Value::String(mode.to_string()));
            if !prev.is_empty() {
                ev.insert("previous".into(), Value::String(prev));
            }
            b.srv.session_event(sid, "block_owner_changed", Value::Object(ev));
            changed = true;
            if let Ok(pane) = b.herdr_id(&id, "block") {
                b.apply_owner_size(sid, &id, &pane);
            }
        }
        out.push(json!({"block_id": id, "owner": owner}));
    }
    if changed {
        b.bump(&wid);
    }
    Ok(json!({"blocks": out}))
}

pub async fn h_disown_block(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let wid = b.herdr_id(sid, "session")?;
    if !c.attached(sid) {
        return Err(RexError::bad_request("connection is not attached to this session"));
    }
    let mut ids = Vec::new();
    if let Some(raw) = p.get("block_ids").and_then(Value::as_array)
        && !raw.is_empty()
    {
        for x in raw {
            let id = x.as_str().unwrap_or_default();
            b.herdr_id(id, "block")?;
            ids.push(id.to_string());
        }
    } else {
        let snap = b.current().await;
        for x in &snap.panes {
            if x.workspace_id == wid {
                ids.push(b.ids.rex("block", &x.id));
            }
        }
    }
    let mut out = Vec::with_capacity(ids.len());
    let mut changed = false;
    for id in ids {
        let (mine, owner) = {
            let mut st = b.st.lock().unwrap_or_else(|p| p.into_inner());
            let mine = st.owners.get(&id).is_some_and(|o| o == &c.id);
            if mine {
                st.owners.remove(&id);
            }
            let owner = st.owners.get(&id).cloned().unwrap_or_default();
            (mine, owner)
        };
        if mine {
            b.srv.session_event(
                sid,
                "block_owner_changed",
                json!({"block_id": id, "previous": c.id, "reason": "disown"}),
            );
            changed = true;
        }
        let mut item = Map::new();
        item.insert("block_id".into(), Value::String(id));
        if !owner.is_empty() {
            item.insert("owner".into(), Value::String(owner));
        }
        out.push(Value::Object(item));
    }
    if changed {
        b.bump(&wid);
    }
    Ok(json!({"blocks": out}))
}

// =========================================================================
// Floating layers
// =========================================================================

pub async fn h_float_block(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    b.herdr_id(str_arg(p, "session_id"), "session")?;
    let bounds = bounds_arg(p)?;
    let x = b.block_or_focused(p).await?;
    if let Some(f) = b.float_of(&x.tab_id, &x.id) {
        return Err(RexError::bad_request(format!(
            "block {} is already in floating layer {}",
            b.ids.rex("block", &x.id),
            f.layer_id
        )));
    }
    if let Some(l) = b.tab_layout(&x.tab_id)
        && l.zoomed
    {
        b.set_core_zoom(&x.tab_id, false);
    }
    let f = FloatLayer {
        layer_id: format!("layer:{}", Uuid::new_v4()),
        pane_id: x.id.clone(),
        bounds,
        minimized: false,
    };
    let lid = f.layer_id.clone();
    b.st
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .floats
        .entry(x.tab_id.clone())
        .or_default()
        .push(f);
    let rev = b.settle(&x.workspace_id).await;
    b.mark_reflow(&x.tab_id, &c.id);
    Ok(json!({"layer_id": lid, "revision": rev}))
}

pub async fn h_new_layer(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let ws = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let bounds = bounds_arg(p)?;
    let layout = layout_block(p)?;
    let (tab, s) = b.window_arg(&ws, str_arg(p, "window_id")).await?;
    let l = b
        .tab_layout(&tab)
        .ok_or_else(|| RexError::conflict("window has no blocks"))?;
    if l.zoomed {
        b.set_core_zoom(&tab, false);
    }
    let mut anchor = l.focused.clone();
    let mut tiled = String::new();
    let mut cwd = leaf_cwd(layout);
    for x in &s.panes {
        if x.tab_id != tab {
            continue;
        }
        if b.float_of(&tab, &x.id).is_none() && (tiled.is_empty() || x.id == l.focused) {
            tiled = x.id.clone();
        }
        if x.id == l.focused && cwd.is_empty() {
            cwd = pwd_of(x).to_string();
        }
    }
    if !tiled.is_empty() {
        anchor = tiled;
    }
    if anchor.is_empty() {
        return Err(RexError::conflict("window has no blocks"));
    }
    let on = b.on_of(&ws);
    let (mut folder, _, _, _) = b.core_where(&on, &ws, &tab).await;
    if !cwd.is_empty() {
        folder = cwd;
    }
    let pane = b
        .core_split_once(&on, &ws, &tab, &folder, &anchor, "horizontal", "after", 0.5, layout)
        .await?;
    let f = FloatLayer {
        layer_id: format!("layer:{}", Uuid::new_v4()),
        pane_id: pane.clone(),
        bounds,
        minimized: false,
    };
    let lid = f.layer_id.clone();
    {
        let _r = b.refresh_mu.lock().await;
        b.st
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .floats
            .entry(tab.clone())
            .or_default()
            .push(f);
    }
    let blocks = b.core_fill(&on, &ws, &tab, &folder, pane.clone(), layout).await?;
    b.claim(c, &ws, &blocks).await;
    if p.get("focus").and_then(Value::as_bool).unwrap_or(false) {
        b.set_core_focus(&ws, &tab, &pane);
    }
    Ok(json!({
        "layer_id": lid,
        "block_ids": blocks,
        "revision": b.settle(&ws).await,
    }))
}

pub async fn h_resize_layer(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let (ws, tab) = b.layer_arg(p, "layer_id", "resize")?;
    let bounds = bounds_arg(p)?;
    let lid = str_arg(p, "layer_id");
    let mut changed = false;
    {
        let mut st = b.st.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(fs) = st.floats.get_mut(&tab) {
            for f in fs {
                if f.layer_id == lid && f.bounds != bounds {
                    f.bounds = bounds;
                    changed = true;
                }
            }
        }
    }
    let rev = if changed { b.bump(&ws) } else { b.current_rev(&ws) };
    Ok(json!({"revision": rev}))
}

pub async fn h_restack_layer(b: &RexBridge, p: &Value, raise: bool) -> Result<Value, RexError> {
    let (ws, tab) = b.layer_arg(p, "layer_id", "raise or lower")?;
    let id = str_arg(p, "layer_id");
    let rel = str_arg(p, "relative_layer_id");
    if !rel.is_empty() {
        if rel == id {
            return Err(RexError::bad_request("relative_layer_id is the layer itself"));
        }
        let (_, rtab) = b.layer_arg(p, "relative_layer_id", "raise or lower")?;
        if rtab != tab {
            return Err(RexError::bad_request(format!("layer {rel} is in another window")));
        }
    }
    let same = {
        let mut st = b.st.lock().unwrap_or_else(|p| p.into_inner());
        let old = st.floats.get(&tab).cloned().unwrap_or_default();
        let mut moved = None;
        let mut rest = Vec::with_capacity(old.len());
        for f in &old {
            if f.layer_id == id {
                moved = Some(f.clone());
            } else {
                rest.push(f.clone());
            }
        }
        if let Some(mv) = moved {
            let mut at = if raise { rest.len() } else { 0 };
            for (i, f) in rest.iter().enumerate() {
                if f.layer_id == rel {
                    at = if raise { i + 1 } else { i };
                }
            }
            rest.insert(at, mv);
            let same = rest.len() == old.len()
                && rest.iter().zip(old.iter()).all(|(a, b)| a.layer_id == b.layer_id);
            st.floats.insert(tab, rest);
            same
        } else {
            true
        }
    };
    let rev = if same { b.current_rev(&ws) } else { b.bump(&ws) };
    Ok(json!({"revision": rev}))
}

pub async fn h_set_layer_state(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let state = str_arg(p, "state");
    if state != "normal" && state != "minimized" {
        return Err(RexError::bad_request("state must be normal or minimized"));
    }
    let focus = p.get("focus").and_then(Value::as_bool).unwrap_or(false);
    if focus && state == "minimized" {
        return Err(RexError::bad_request("focus requires state normal"));
    }
    let ws = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let id = str_arg(p, "layer_id");
    let s = b.snapshot();
    if let Some(tab) = b.ids.herdr(id)
        && let Some(snap) = &s
        && b.ids.rex("layer", &tab) == id
    {
        if !tab_in(snap, &tab, &ws) {
            return Err(RexError::not_found(format!("layer {id} not found")));
        }
        if state == "minimized" {
            return Err(RexError::bad_request(format!("cannot minimize tiled layer {id}")));
        }
        if focus
            && let Some(l) = b.tab_layout(&tab)
            && !l.focused.is_empty()
        {
            b.set_core_focus(&ws, &tab, &l.focused);
        }
        return Ok(json!({"revision": b.settle(&ws).await}));
    }

    let mut found = None;
    let mut changed = false;
    {
        let mut st = b.st.lock().unwrap_or_else(|p| p.into_inner());
        'outer: for (t, fs) in &mut st.floats {
            if let Some(snap) = &s
                && !tab_in(snap, t, &ws)
            {
                continue;
            }
            for i in 0..fs.len() {
                if fs[i].layer_id != id {
                    continue;
                }
                let want = state == "minimized";
                if fs[i].minimized != want {
                    fs[i].minimized = want;
                    changed = true;
                }
                let pane = fs[i].pane_id.clone();
                if focus {
                    let mv = fs.remove(i);
                    fs.push(mv);
                }
                found = Some((t.clone(), pane));
                break 'outer;
            }
        }
    }
    let Some((tab, pane)) = found else {
        return Err(RexError::not_found(format!("layer {id} not found")));
    };
    if focus {
        b.set_core_focus(&ws, &tab, &pane);
    }
    let rev = if changed || focus { b.bump(&ws) } else { b.current_rev(&ws) };
    Ok(json!({"revision": rev}))
}

pub async fn h_move_block(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let ws = b.herdr_id(str_arg(p, "session_id"), "session")?;
    let dir = match str_arg(p, "direction") {
        "" | "horizontal" => "right",
        "vertical" => "down",
        _ => return Err(RexError::bad_request(r#"direction must be "horizontal" or "vertical""#)),
    };
    let side = str_arg(p, "side");
    if !side.is_empty() && side != "before" && side != "after" {
        return Err(RexError::bad_request(r#"side must be "before" or "after""#));
    }
    let ratio = num_arg(p, "ratio").unwrap_or(0.5);
    if str_arg(p, "block_id") == str_arg(p, "anchor_block_id") || ratio <= 0.0 || ratio >= 1.0 {
        return Err(RexError::bad_request("need two different blocks and 0 < ratio < 1"));
    }
    let x = b
        .block_or_focused(&json!({
            "block_id": str_arg(p, "block_id"),
            "session_id": str_arg(p, "session_id"),
        }))
        .await?;
    let a = b
        .block_or_focused(&json!({
            "block_id": str_arg(p, "anchor_block_id"),
            "session_id": str_arg(p, "session_id"),
        }))
        .await?;
    if x.workspace_id != ws || a.workspace_id != ws {
        return Err(RexError::not_found("block is not in the session"));
    }
    if b.float_of(&a.tab_id, &a.id).is_some() {
        return Err(RexError::bad_request(
            "Herdr floats one block per layer: the anchor floats",
        ));
    }
    let floating = b.float_of(&x.tab_id, &x.id).is_some();
    if floating
        && x.tab_id == a.tab_id
        && let Some(l) = b.tab_layout(&x.tab_id)
        && at_spot(&l, &x.id, &a.id, dir, side == "before")
    {
        b.unfloat(&x.tab_id, &x.id);
        let out = json!({
            "created_split_id": b.split_above(&x.tab_id, &x.id),
            "revision": b.settle(&ws).await,
        });
        b.mark_reflow(&x.tab_id, &c.id);
        return Ok(out);
    }
    Err(RexError::not_supported(
        "session.move_block cannot rearrange herdr-core panes; docking a float back onto its original split still works",
    ))
}

pub async fn h_close_layer(b: &RexBridge, p: &Value) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let (ws, tab) = match b.layer_arg(p, "layer_id", "close") {
        Ok(x) => x,
        Err(e) if gone(&e) => return Ok(b.ack_rev(sid).await),
        Err(e) => return Err(e),
    };
    let lid = str_arg(p, "layer_id");
    for f in b.tab_floats(&tab) {
        if f.layer_id == lid {
            let _ = h_block_close(
                b,
                &json!({"session_id": sid, "block_id": b.ids.rex("block", &f.pane_id)}),
            )
            .await?;
        }
    }
    Ok(json!({"revision": b.settle(&ws).await}))
}

// =========================================================================
// Pure Helpers
// =========================================================================

pub fn agree(tab: &str, panes: &[Pane], l: &LayoutNode) -> Option<(Vec<Pane>, LayoutNode)> {
    let mut known = HashMap::new();
    for p in panes {
        known.insert(p.id.as_str(), p.tab_id == tab);
    }
    let mut root = prune(l, &known)?;
    let mut shown_vec = Vec::new();
    collect_leaves(&root, &mut shown_vec);
    let shown: HashSet<&str> = shown_vec.iter().map(String::as_str).collect();
    if shown.contains(l.focused.as_str()) {
        root.focused = l.focused.clone();
        root.zoomed = l.zoomed;
    } else {
        root.focused.clear();
        root.zoomed = false;
    }
    let out: Vec<Pane> = panes
        .iter()
        .filter(|p| p.tab_id == tab && shown.contains(p.id.as_str()))
        .cloned()
        .collect();
    Some((out, root))
}

fn prune(n: &LayoutNode, keep: &HashMap<&str, bool>) -> Option<LayoutNode> {
    if n.first.is_none() {
        return if keep.get(n.pane_id.as_str()).copied().unwrap_or(false) {
            Some(n.clone())
        } else {
            None
        };
    }
    let first = n.first.as_deref().and_then(|f| prune(f, keep));
    let second = n.second.as_deref().and_then(|s| prune(s, keep));
    match (first, second) {
        (None, s) => s,
        (f, None) => f,
        (Some(f), Some(s)) => {
            let mut c = n.clone();
            c.first = Some(Box::new(f));
            c.second = Some(Box::new(s));
            Some(c)
        }
    }
}

fn collect_leaves(n: &LayoutNode, out: &mut Vec<String>) {
    if n.first.is_none() {
        if !n.pane_id.is_empty() {
            out.push(n.pane_id.clone());
        }
        return;
    }
    if let Some(f) = n.first.as_deref() {
        collect_leaves(f, out);
    }
    if let Some(s) = n.second.as_deref() {
        collect_leaves(s, out);
    }
}

fn step_idx(i: usize, d: isize, n: usize, wrap: bool) -> usize {
    let j = i as isize + d;
    if j < 0 || j >= n as isize {
        if !wrap {
            return i;
        }
        j.rem_euclid(n as isize) as usize
    } else {
        j as usize
    }
}

fn nearest_pane(s: &Snapshot, tab: &str, pane: &str, dir: &str) -> String {
    let Some(panes) = s.layouts.iter().find(|l| l.tab_id == tab).map(|l| &l.panes) else {
        return String::new();
    };
    let Some(src) = panes.iter().find(|p| p.pane_id == pane).map(|p| p.rect) else {
        return String::new();
    };
    let overlap = |a0: i32, a1: i32, b0: i32, b1: i32| a0 < b1 && b0 < a1;
    let mut best = String::new();
    let mut best_key = 0i32;
    for x in panes {
        if x.pane_id == pane {
            continue;
        }
        let r = x.rect;
        let (ok, key) = match dir {
            "right" => (overlap(r.y, r.y + r.height, src.y, src.y + src.height) && r.x >= src.x + src.width, r.x),
            "left" => (overlap(r.y, r.y + r.height, src.y, src.y + src.height) && r.x + r.width <= src.x, -(r.x + r.width)),
            "down" => (overlap(r.x, r.x + r.width, src.x, src.x + src.width) && r.y >= src.y + src.height, r.y),
            "up" => (overlap(r.x, r.x + r.width, src.x, src.x + src.width) && r.y + r.height <= src.y, -(r.y + r.height)),
            _ => (false, 0),
        };
        if ok && (best.is_empty() || key < best_key) {
            best = x.pane_id.clone();
            best_key = key;
        }
    }
    best
}

fn wrap_target(s: &Snapshot, tab: &str, pane: &str, dir: &str) -> String {
    let Some(panes) = s.layouts.iter().find(|l| l.tab_id == tab).map(|l| &l.panes) else {
        return String::new();
    };
    let Some(src) = panes.iter().find(|p| p.pane_id == pane).map(|p| p.rect) else {
        return String::new();
    };
    let overlap = |a0: i32, a1: i32, b0: i32, b1: i32| a0 < b1 && b0 < a1;
    let mut best = String::new();
    let mut best_key = 0i32;
    for x in panes {
        let r = x.rect;
        let (ok, key) = match dir {
            "right" => (overlap(r.y, r.y + r.height, src.y, src.y + src.height), r.x),
            "left" => (overlap(r.y, r.y + r.height, src.y, src.y + src.height), -(r.x + r.width)),
            "down" => (overlap(r.x, r.x + r.width, src.x, src.x + src.width), r.y),
            "up" => (overlap(r.x, r.x + r.width, src.x, src.x + src.width), -(r.y + r.height)),
            _ => (false, 0),
        };
        if ok && (best.is_empty() || key < best_key) {
            best = x.pane_id.clone();
            best_key = key;
        }
    }
    if best == pane { String::new() } else { best }
}

fn rex_dir_axis(direction: &str) -> &'static str {
    if direction == "horizontal" { "row" } else { "column" }
}

pub fn check_layout(n: &Value) -> Result<(), RexError> {
    if let Some(blk) = obj_arg(n, "block") {
        let f = str_arg(blk, "flavor");
        if !f.is_empty() && f != SHELL_FLAVOR {
            return Err(RexError::not_found(format!("no creator provides flavor {f}")));
        }
        return Ok(());
    }
    let Some(sp) = obj_arg(n, "split") else {
        return Err(RexError::bad_request("layout node needs block or split"));
    };
    let d = str_arg(sp, "direction");
    if d != "horizontal" && d != "vertical" {
        return Err(RexError::bad_request(r#"split direction must be "horizontal" or "vertical""#));
    }
    if let Some(r) = num_arg(sp, "ratio")
        && (r <= 0.0 || r >= 1.0)
    {
        return Err(RexError::bad_request("ratio must be between 0 and 1"));
    }
    let (Some(before), Some(after)) = (obj_arg(sp, "before"), obj_arg(sp, "after")) else {
        return Err(RexError::bad_request("split needs before and after"));
    };
    check_layout(before)?;
    check_layout(after)
}

pub fn leaf_cwd(mut n: &Value) -> String {
    while let Some(sp) = obj_arg(n, "split") {
        match obj_arg(sp, "before") {
            Some(b) => n = b,
            None => break,
        }
    }
    let cwd = n
        .get("block")
        .and_then(|b| b.get("options"))
        .and_then(|o| o.get("cwd"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    decode_file_url(cwd)
}

pub fn leaf_command(mut n: &Value) -> Vec<String> {
    while let Some(sp) = obj_arg(n, "split") {
        match obj_arg(sp, "before") {
            Some(b) => n = b,
            None => break,
        }
    }
    let Some(raw) = n.get("block").and_then(|b| b.get("options")).and_then(|o| o.get("command")) else {
        return Vec::new();
    };
    if let Some(s) = raw.as_str() {
        if !s.is_empty() {
            return vec!["/bin/zsh".into(), "-lc".into(), s.to_string()];
        }
    } else if let Some(arr) = raw.as_array() {
        return arr
            .iter()
            .filter_map(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
    }
    Vec::new()
}

fn tab_in(s: &Snapshot, tab: &str, ws: &str) -> bool {
    s.tabs.iter().any(|t| t.id == tab && t.workspace_id == ws)
}

fn bounds_arg(p: &Value) -> Result<[f64; 4], RexError> {
    let mut r = [0.0f64; 4];
    let mut ok = false;
    match p.get("bounds") {
        Some(Value::Array(arr)) if arr.len() == 4 => {
            ok = true;
            for (i, x) in arr.iter().enumerate() {
                if let Some(f) = x.as_f64() {
                    r[i] = f;
                } else {
                    ok = false;
                }
            }
        }
        Some(Value::Object(obj)) => {
            ok = true;
            for (i, k) in ["x", "y", "w", "h"].iter().enumerate() {
                if let Some(f) = obj.get(*k).and_then(Value::as_f64) {
                    r[i] = f;
                } else {
                    ok = false;
                }
            }
        }
        _ => {}
    }
    const EPS: f64 = 1e-9;
    for x in r {
        ok = ok && x.is_finite();
    }
    if !ok
        || r[2] <= 0.0
        || r[3] <= 0.0
        || r[0] < -EPS
        || r[1] < -EPS
        || r[0] + r[2] > 1.0 + EPS
        || r[1] + r[3] > 1.0 + EPS
    {
        return Err(RexError::bad_request(
            "input: validating: bounds must be a finite normalized rectangle with positive size contained within the unit square",
        ));
    }
    Ok(r)
}

fn layout_block(p: &Value) -> Result<&Value, RexError> {
    let Some(raw) = p.get("layout") else {
        return Err(RexError::bad_request(
            r#"validating input: validating root: required: missing properties: ["layout"]"#,
        ));
    };
    if !raw.is_object() {
        return Err(RexError::bad_request("input: validating: layout is required"));
    }
    let blk = obj_arg(raw, "block");
    let has_split = raw.get("split").is_some();
    if blk.is_some() == has_split {
        return Err(RexError::bad_request(
            "input: validating: layout must contain exactly one of block or split",
        ));
    }
    if has_split {
        return Err(RexError::bad_request(
            "herdrex floats one block per layer: layout must be a single block",
        ));
    }
    if let Some(b) = blk {
        let f = str_arg(b, "flavor");
        if !f.is_empty() && f != SHELL_FLAVOR {
            return Err(RexError::not_found(format!(r#"block flavor not found: "{f}""#)));
        }
    }
    Ok(raw)
}

fn has_pane(n: &LayoutNode, pane: &str) -> bool {
    if n.kind == "pane" || n.first.is_none() {
        return n.pane_id == pane;
    }
    n.first.as_deref().is_some_and(|f| has_pane(f, pane))
        || n.second.as_deref().is_some_and(|s| has_pane(s, pane))
}

fn path_to(n: &LayoutNode, pane: &str) -> Option<Vec<bool>> {
    if n.kind == "pane" || n.first.is_none() {
        return (n.pane_id == pane).then(Vec::new);
    }
    if let Some(mut pth) = n.first.as_deref().and_then(|f| path_to(f, pane)) {
        pth.insert(0, false);
        return Some(pth);
    }
    if let Some(mut pth) = n.second.as_deref().and_then(|s| path_to(s, pane)) {
        pth.insert(0, true);
        return Some(pth);
    }
    None
}

fn at_spot(n: &LayoutNode, pane: &str, anchor: &str, dir: &str, before: bool) -> bool {
    if n.kind == "pane" || n.first.is_none() {
        return false;
    }
    let (Some(first), Some(second)) = (n.first.as_deref(), n.second.as_deref()) else {
        return false;
    };
    if first.kind == "pane" && first.pane_id == pane {
        return n.direction == dir && before && has_pane(second, anchor);
    }
    if second.kind == "pane" && second.pane_id == pane {
        return n.direction == dir && !before && has_pane(first, anchor);
    }
    at_spot(first, pane, anchor, dir, before) || at_spot(second, pane, anchor, dir, before)
}

pub fn create_target(
    label: &str,
    on_arg: &str,
    last_on: &str,
    local_name: &str,
    machines: &[String],
) -> (String, String) {
    let label = label.trim();
    let on_arg = on_arg.trim();
    if !on_arg.is_empty() {
        if let Some(m) = match_machine(on_arg, local_name, machines) {
            return (m, label.to_string());
        }
        return (on_arg.to_string(), label.to_string());
    }
    if let Some((on, rest)) = split_machine_label(label, local_name, machines) {
        return (on, rest);
    }
    (last_on.to_string(), label.to_string())
}

fn split_machine_label(label: &str, local_name: &str, machines: &[String]) -> Option<(String, String)> {
    let (prefix, name, found) = match label.split_once(" / ") {
        Some((p, n)) => (p.trim(), n.trim(), true),
        None => (label.trim(), "", false),
    };
    if prefix.is_empty() {
        return None;
    }
    let on = match_machine(prefix, local_name, machines)?;
    if !found {
        Some((on, String::new()))
    } else {
        Some((on, name.to_string()))
    }
}

fn match_machine(prefix: &str, local_name: &str, machines: &[String]) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    if (!local_name.is_empty() && prefix.eq_ignore_ascii_case(local_name))
        || prefix.eq_ignore_ascii_case("local")
    {
        return Some(String::new());
    }
    let mut suffix = Vec::new();
    let suf = format!("-{}", prefix.to_lowercase());
    for m in machines {
        if m.is_empty() {
            continue;
        }
        if m.eq_ignore_ascii_case(prefix) {
            return Some(m.clone());
        }
        if m.to_lowercase().ends_with(&suf) {
            suffix.push(m.clone());
        }
    }
    if suffix.len() == 1 {
        Some(suffix.remove(0))
    } else {
        None
    }
}
