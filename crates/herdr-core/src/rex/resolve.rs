//! Rex `target.resolve` and `target.complete` matching the official Rex server rules.

use super::appdoc::{Pane, Snapshot, Workspace};
use super::bridge::RexBridge;
use super::model::pane_label;
use super::proto::RexError;
use super::server::RexClient;
use serde_json::{Map, Value, json};
use std::sync::Arc;
use uuid::Uuid;

struct Resolver<'a> {
    b: &'a RexBridge,
    s: Snapshot,
    kinds: Vec<String>,
    searched: Vec<Workspace>,
    window: String,
    ctx_sid: String,
    ctx_block: String,
    ctx_cli: String,
    clients: Vec<Arc<RexClient>>,
}

pub async fn h_resolve(b: &RexBridge, _c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let kinds = target_kinds(p.get("kinds"))?;
    let raw = p
        .get("queries")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| RexError::bad_request("target resolution requires at least one query"))?;
    let mut queries = Vec::with_capacity(raw.len());
    for (i, q) in raw.iter().enumerate() {
        let s = q.as_str().unwrap_or_default().to_string();
        if has_control(&s) {
            return Err(RexError::bad_request(format!(
                "queries[{i}]: target {s:?} contains a control character"
            )));
        }
        queries.push(s);
    }
    match build_resolver(b, p, kinds).await? {
        ResolverInit::Failed { status, reason, cands } => {
            let mut out = Vec::with_capacity(queries.len());
            for q in queries {
                let mut m = Map::new();
                m.insert("query".into(), Value::String(q));
                m.insert("status".into(), Value::String(status.clone()));
                m.insert("reason".into(), Value::String(reason.clone()));
                if let Some(cs) = &cands {
                    m.insert("candidates".into(), Value::Array(cs.clone()));
                }
                out.push(Value::Object(m));
            }
            Ok(json!({"results": out}))
        }
        ResolverInit::Ready(r) => {
            let out: Vec<Value> = queries.iter().map(|q| r.resolve(q)).collect();
            Ok(json!({"results": out}))
        }
    }
}

pub async fn h_complete(b: &RexBridge, _c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let kinds = target_kinds(p.get("kinds"))?;
    let raw = p.get("prefix").and_then(Value::as_str).unwrap_or_default();
    if has_control(raw) {
        return Err(RexError::bad_request(format!("target {raw:?} contains a control character")));
    }
    let prefix = raw.trim().to_lowercase();
    let r = match build_resolver(b, p, kinds.clone()).await? {
        ResolverInit::Failed { .. } => return Ok(json!({"completions": []})),
        ResolverInit::Ready(r) => r,
    };
    let ids = prefix.is_empty() || is_hex(&prefix);
    let mut out = Vec::new();
    for k in &kinds {
        let mut labels: Vec<Value> = Vec::new();
        let mut ords: Vec<Value> = Vec::new();
        let mut shorts: Vec<Value> = Vec::new();
        let all = r.filter(k, |_, _| true);
        let id_key = format!("{k}_id");
        for t in all {
            if let Some(l) = t.get("label").and_then(Value::as_str)
                && !l.is_empty()
                && l.to_lowercase().starts_with(&prefix)
            {
                labels.push(json!({"value": l, "form": "label", "target": t}));
            }
            if let Some(n) = t.get("ordinal").and_then(Value::as_u64) {
                let ns = n.to_string();
                if ns.starts_with(&prefix) {
                    ords.push(json!({"value": ns, "form": "ordinal", "target": t}));
                }
            }
            if ids
                && let Some(id) = t.get(&id_key).and_then(Value::as_str)
            {
                let sh = short_id(id);
                if sh.starts_with(&prefix) {
                    shorts.push(json!({"value": sh, "form": "id", "target": t}));
                }
            }
        }
        labels.sort_by(|a, b| {
            let al = a["value"].as_str().unwrap_or_default().to_lowercase();
            let bl = b["value"].as_str().unwrap_or_default().to_lowercase();
            al.cmp(&bl)
        });
        ords.sort_by_key(|x| x["target"]["ordinal"].as_u64().unwrap_or(0));
        shorts.sort_by(|a, b| {
            let av = a["value"].as_str().unwrap_or_default();
            let bv = b["value"].as_str().unwrap_or_default();
            av.cmp(bv)
        });
        out.extend(labels);
        out.extend(ords);
        out.extend(shorts);
    }
    Ok(json!({"completions": out}))
}

#[allow(clippy::large_enum_variant)]
enum ResolverInit<'a> {
    Ready(Resolver<'a>),
    Failed {
        status: String,
        reason: String,
        cands: Option<Vec<Value>>,
    },
}

async fn build_resolver<'a>(
    b: &'a RexBridge,
    p: &Value,
    kinds: Vec<String>,
) -> Result<ResolverInit<'a>, RexError> {
    let has_scope = p.get("scope").is_some_and(|v| !v.is_null());
    let sc = p.get("scope").and_then(Value::as_object);
    let sc_str = |k: &str| sc.and_then(|m| m.get(k)).and_then(Value::as_str).unwrap_or_default();

    if has_scope && kinds.iter().any(|k| k == "session") {
        return Err(RexError::bad_request("session target requests do not accept a scope"));
    }
    if !sc_str("window").is_empty() && (kinds.len() != 1 || kinds[0] != "block") {
        let k = if kinds[0] == "block" { &kinds[1] } else { &kinds[0] };
        return Err(RexError::bad_request(format!(
            "{k} target requests do not accept a window scope"
        )));
    }
    for k in ["session", "window"] {
        let v = sc_str(k);
        if has_control(v) {
            return Err(RexError::bad_request(format!(
                "scope.{k}: target {v:?} contains a control character"
            )));
        }
    }

    let s = b.current().await;
    let cx = p.get("context").and_then(Value::as_object);
    let cx_str = |k: &str| cx.and_then(|m| m.get(k)).and_then(Value::as_str).unwrap_or_default();

    let mut r = Resolver {
        b,
        s,
        kinds,
        searched: Vec::new(),
        window: String::new(),
        ctx_sid: String::new(),
        ctx_block: String::new(),
        ctx_cli: cx_str("client_id").to_string(),
        clients: Vec::new(),
    };

    let pane_id = cx_str("block_id");
    if !pane_id.is_empty()
        && let Ok(pair) = r.block_by_id(pane_id).map(|p| (p.id.clone(), p.workspace_id.clone()))
    {
        r.ctx_block = pair.0;
        r.ctx_sid = pair.1;
    }
    if r.ctx_sid.is_empty()
        && let Some(ws) = b.ids.herdr(cx_str("session_id"))
        && r.workspace(&ws).is_some()
    {
        r.ctx_sid = ws;
    }
    if r.kinds[0] == "client" {
        r.clients = b.srv.clients();
    }

    let q_sess = sc_str("session");
    if !q_sess.is_empty() {
        let m = match r.session_matches(q_sess) {
            Ok(m) => m,
            Err(why) => {
                return Ok(ResolverInit::Failed {
                    status: "not_found".into(),
                    reason: format!("session scope: {why}"),
                    cands: None,
                });
            }
        };
        match m.len() {
            0 => {
                return Ok(ResolverInit::Failed {
                    status: "not_found".into(),
                    reason: format!("session scope: session {q_sess:?} not found"),
                    cands: None,
                });
            }
            1 => {
                if r.kinds[0] == "client" {
                    let sid = b.ids.rex("session", &m[0].id);
                    r.clients.retain(|o| o.attached(&sid));
                }
                r.searched = m;
            }
            _ => {
                let cands = r.session_items(&m);
                return Ok(ResolverInit::Failed {
                    status: "ambiguous".into(),
                    reason: format!("session scope: session {q_sess:?} is ambiguous"),
                    cands: Some(cands),
                });
            }
        }
    } else if !r.ctx_sid.is_empty() {
        if let Some(w) = r.workspace(&r.ctx_sid).cloned() {
            r.searched = vec![w];
        }
    } else {
        r.searched = r.s.workspaces.clone();
    }

    let q_win = sc_str("window");
    if !q_win.is_empty() {
        let m = r.find(q_win, &["window".to_string()]);
        match m.len() {
            0 => {
                return Ok(ResolverInit::Failed {
                    status: "not_found".into(),
                    reason: format!("window scope: window {q_win:?} not found"),
                    cands: None,
                });
            }
            1 => {
                if let Some(wid) = m[0]["window_id"].as_str()
                    && let Some(h) = b.ids.herdr(wid)
                {
                    r.window = h;
                }
            }
            _ => {
                return Ok(ResolverInit::Failed {
                    status: "ambiguous".into(),
                    reason: format!("window scope: window {q_win:?} is ambiguous"),
                    cands: Some(m),
                });
            }
        }
    }

    Ok(ResolverInit::Ready(r))
}

fn target_kinds(v: Option<&Value>) -> Result<Vec<String>, RexError> {
    let raw = v
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| RexError::bad_request("target requests require at least one kind"))?;
    let mut kinds = Vec::with_capacity(raw.len());
    for (i, k) in raw.iter().enumerate() {
        let s = k.as_str().unwrap_or_default();
        if !matches!(s, "session" | "window" | "block" | "client") {
            return Err(RexError::bad_request(
                "target requests support sessions, windows, blocks, and clients only",
            ));
        }
        if kinds.iter().any(|x| x == s) {
            return Err(RexError::bad_request(format!("kinds[{i}] duplicates {s:?}")));
        }
        kinds.push(s.to_string());
    }
    if kinds.iter().any(|k| k == "client") && kinds.len() > 1 {
        return Err(RexError::bad_request(
            "client targets cannot be resolved together with sessions, windows, or blocks",
        ));
    }
    Ok(kinds)
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
}

fn kind_list(kinds: &[String]) -> String {
    match kinds.len() {
        0 => String::new(),
        1 => kinds[0].clone(),
        2 => format!("{} or {}", kinds[0], kinds[1]),
        _ => format!("{}, or {}", kinds[..kinds.len() - 1].join(", "), kinds[kinds.len() - 1]),
    }
}

fn full_id(q: &str) -> Option<&'static str> {
    ["session", "window", "block", "client"]
        .into_iter()
        .find(|k| q.starts_with(&format!("{k}:")))
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn short_id(id: &str) -> String {
    let h: String = id.chars().filter(|c| *c != '-').collect();
    if h.len() < 6 {
        h
    } else {
        h[h.len() - 6..].to_string()
    }
}

fn client_item(c: &RexClient) -> Value {
    let info = c.info();
    let label = info.get("label").and_then(Value::as_str).unwrap_or_default();
    let name = info.get("name").and_then(Value::as_str).unwrap_or_default();
    let version = info.get("version").and_then(Value::as_str).unwrap_or_default();
    let where_str = format!("{name} {version}").trim().to_string();
    json!({
        "kind": "client",
        "client_id": c.id,
        "label": label,
        "where": where_str,
    })
}

impl<'a> Resolver<'a> {
    fn has_kind(&self, k: &str) -> bool {
        self.kinds.iter().any(|x| x == k)
    }

    fn resolve(&self, q: &str) -> Value {
        let mut res = Map::new();
        res.insert("query".into(), Value::String(q.to_string()));
        let t = q.trim();
        let (m, reason) = if t.is_empty() {
            self.empty()
        } else if full_id(t).is_some() {
            self.by_id(t)
        } else {
            let m = self.match_query(t, &self.kinds);
            let reason = if m.is_empty() && self.kinds.len() > 1 {
                format!("no {} matched", kind_list(&self.kinds))
            } else {
                String::new()
            };
            (m, reason)
        };
        if m.is_empty() {
            res.insert("status".into(), Value::String("not_found".into()));
        } else if m.len() == 1 && reason.is_empty() {
            res.insert("status".into(), Value::String("resolved".into()));
            res.insert("target".into(), m[0].clone());
            return Value::Object(res);
        } else {
            res.insert("status".into(), Value::String("ambiguous".into()));
            res.insert("candidates".into(), Value::Array(m));
        }
        if !reason.is_empty() {
            res.insert("reason".into(), Value::String(reason));
        }
        Value::Object(res)
    }

    fn empty(&self) -> (Vec<Value>, String) {
        if self.kinds[0] == "client" {
            return self.empty_client();
        }
        if self.has_kind("block") {
            if !self.window.is_empty() {
                return self.focused_in(&self.window);
            }
            if !self.ctx_block.is_empty()
                && let Some(p) = self.pane_of(&self.ctx_block)
                && self.in_search(&p.workspace_id)
            {
                return (vec![self.block_item(p)], String::new());
            }
            let (tab, m, why) = self.empty_window();
            if tab.is_empty() {
                return (m, why);
            }
            return self.focused_in(&tab);
        }
        if self.has_kind("window") {
            let (tab, m, why) = self.empty_window();
            if tab.is_empty() {
                return (m, why);
            }
            return (vec![self.window_item(&tab)], String::new());
        }
        if !self.ctx_sid.is_empty()
            && let Some(w) = self.workspace(&self.ctx_sid)
        {
            return (self.session_items(std::slice::from_ref(w)), String::new());
        }
        if self.s.workspaces.is_empty() {
            return (Vec::new(), "no sessions are available".into());
        }
        if self.s.workspaces.len() > 1 {
            return (
                self.session_items(&self.s.workspaces),
                "multiple sessions are available".into(),
            );
        }
        (self.session_items(&self.s.workspaces), String::new())
    }

    fn empty_window(&self) -> (String, Vec<Value>, String) {
        if !self.ctx_block.is_empty()
            && self.searched.len() == 1
            && let Some(p) = self.pane_of(&self.ctx_block)
            && p.workspace_id == self.searched[0].id
        {
            return (p.tab_id.clone(), Vec::new(), String::new());
        }
        match self.searched.len() {
            0 => (String::new(), Vec::new(), "no sessions are available".into()),
            1 => {
                if !self.searched[0].active_tab_id.is_empty() {
                    (self.searched[0].active_tab_id.clone(), Vec::new(), String::new())
                } else {
                    (String::new(), Vec::new(), "session has no windows".into())
                }
            }
            _ => (
                String::new(),
                self.session_items(&self.searched),
                "multiple sessions are available. Pass -s to select one".into(),
            ),
        }
    }

    fn focused_in(&self, tab: &str) -> (Vec<Value>, String) {
        for l in &self.s.layouts {
            if l.tab_id == tab
                && let Some(p) = self.pane_of(&l.focused_pane_id)
            {
                return (vec![self.block_item(p)], String::new());
            }
        }
        (Vec::new(), "window has no blocks".into())
    }

    fn empty_client(&self) -> (Vec<Value>, String) {
        let mut apps = Vec::new();
        for c in &self.clients {
            if c.id == self.ctx_cli {
                return (vec![client_item(c)], String::new());
            }
            if c.info().get("kind").and_then(Value::as_str) == Some("app") {
                apps.push(client_item(c));
            }
        }
        match apps.len() {
            0 => (Vec::new(), "no app client is connected".into()),
            1 => (apps, String::new()),
            _ => (apps, "multiple app clients are connected".into()),
        }
    }

    fn session_items(&self, ws: &[Workspace]) -> Vec<Value> {
        ws.iter()
            .map(|w| {
                json!({
                    "kind": "session",
                    "session_id": self.b.ids.rex("session", &w.id),
                    "label": w.label,
                })
            })
            .collect()
    }

    fn tab_workspace(&self, tab: &str) -> &str {
        self.s
            .tabs
            .iter()
            .find(|t| t.id == tab)
            .map(|t| t.workspace_id.as_str())
            .unwrap_or_default()
    }

    fn ordinal(&self, tab: &str) -> (String, usize) {
        let ws = self.tab_workspace(tab);
        let mut n = 0usize;
        for t in &self.s.tabs {
            if t.workspace_id == ws {
                n += 1;
                if t.id == tab {
                    return (t.workspace_id.clone(), n);
                }
            }
        }
        (String::new(), 0)
    }

    fn tab_at(&self, ws: &str, mut n: usize) -> Option<&str> {
        for t in &self.s.tabs {
            if t.workspace_id == ws {
                n -= 1;
                if n == 0 {
                    return Some(&t.id);
                }
            }
        }
        None
    }

    fn window_item(&self, tab: &str) -> Value {
        let (ws, n) = self.ordinal(tab);
        let label = self
            .s
            .tabs
            .iter()
            .find(|t| t.id == tab)
            .map(|t| t.label.as_str())
            .unwrap_or_default();
        let mut f = Map::new();
        f.insert("kind".into(), Value::String("window".into()));
        f.insert("session_id".into(), Value::String(self.b.ids.rex("session", &ws)));
        f.insert("window_id".into(), Value::String(self.b.ids.rex("window", tab)));
        f.insert("label".into(), Value::String(label.to_string()));
        f.insert("ordinal".into(), json!(n));
        if self.searched.len() > 1
            && let Some(w) = self.workspace(&ws)
        {
            f.insert("where".into(), Value::String(format!("in {}", w.label)));
        }
        Value::Object(f)
    }

    fn block_item(&self, p: &Pane) -> Value {
        let (_, n) = self.ordinal(&p.tab_id);
        let mut where_str = format!("window {n}");
        if self.searched.len() > 1
            && let Some(w) = self.workspace(&p.workspace_id)
        {
            where_str.push_str(&format!(" of {}", w.label));
        }
        json!({
            "kind": "block",
            "session_id": self.b.ids.rex("session", &p.workspace_id),
            "window_id": self.b.ids.rex("window", &p.tab_id),
            "block_id": self.b.ids.rex("block", &p.id),
            "label": pane_label(p),
            "where": where_str,
        })
    }

    fn block_by_id(&self, q: &str) -> Result<&Pane, String> {
        let Some(raw) = q.strip_prefix("block:") else {
            return Err(format!("{q:?} is not a valid block ID"));
        };
        let Ok(id) = Uuid::parse_str(raw) else {
            return Err(format!("{q:?} is not a valid block ID"));
        };
        if let Some(h) = self.b.ids.herdr(&format!("block:{id}"))
            && let Some(p) = self.pane_of(&h)
        {
            return Ok(p);
        }
        Err(format!("no open block has ID {q:?}"))
    }

    fn by_id(&self, q: &str) -> (Vec<Value>, String) {
        let Some(k) = full_id(q) else { return (Vec::new(), String::new()) };
        if k == "block" && self.has_kind("session") && !self.has_kind("block") {
            return match self.session_matches(q) {
                Ok(ws) => (self.session_items(&ws), String::new()),
                Err(why) => (Vec::new(), why),
            };
        }
        if !self.has_kind(k) {
            let reason = if self.kinds.len() == 1 {
                format!("{q:?} is a {k} ID, not a {}", self.kinds[0])
            } else {
                format!("{q:?} is a {k} ID; expected {}", kind_list(&self.kinds))
            };
            return (Vec::new(), reason);
        }
        let Ok(u) = Uuid::parse_str(&q[k.len() + 1..]) else {
            return (Vec::new(), format!("{q:?} is not a valid {k} ID"));
        };
        let canonical = format!("{k}:{u}");
        (self.filter(k, |id, _| id == canonical), String::new())
    }

    fn match_query(&self, q: &str, kinds: &[String]) -> Vec<Value> {
        let q_low = q.to_lowercase();
        let mut m = Vec::new();
        for k in kinds {
            m.extend(self.filter(k, |_, label| label.to_lowercase() == q_low));
        }
        if !m.is_empty() {
            return m;
        }
        if !q.starts_with('+')
            && let Ok(n) = q.parse::<usize>()
            && n > 0
            && kinds.iter().any(|k| k == "window")
        {
            for w in &self.searched {
                if let Some(t) = self.tab_at(&w.id, n) {
                    m.push(self.window_item(t));
                }
            }
            if !m.is_empty() {
                return m;
            }
        }
        let end: String = q.chars().filter(|c| *c != '-').collect::<String>().to_lowercase();
        if end.len() >= 4 && end.len() <= 32 && is_hex(&end) {
            for k in kinds {
                m.extend(self.filter(k, |id, _| {
                    let clean: String = id.chars().filter(|c| *c != '-').collect();
                    clean.ends_with(&end)
                }));
            }
        }
        m
    }

    fn filter<F>(&self, k: &str, mut ok: F) -> Vec<Value>
    where
        F: FnMut(&str, &str) -> bool,
    {
        let mut m = Vec::new();
        match k {
            "session" => {
                for w in &self.s.workspaces {
                    if ok(&self.b.ids.rex("session", &w.id), &w.label) {
                        m.extend(self.session_items(std::slice::from_ref(w)));
                    }
                }
            }
            "window" => {
                for t in &self.s.tabs {
                    if self.in_search(&t.workspace_id)
                        && ok(&self.b.ids.rex("window", &t.id), &t.label)
                    {
                        m.push(self.window_item(&t.id));
                    }
                }
            }
            "block" => {
                for p in &self.s.panes {
                    if self.in_search(&p.workspace_id)
                        && (self.window.is_empty() || p.tab_id == self.window)
                        && ok(&self.b.ids.rex("block", &p.id), &pane_label(p))
                    {
                        m.push(self.block_item(p));
                    }
                }
            }
            "client" => {
                for c in &self.clients {
                    let info = c.info();
                    let label = info.get("label").and_then(Value::as_str).unwrap_or_default();
                    if ok(&c.id, label) {
                        m.push(client_item(c));
                    }
                }
            }
            _ => {}
        }
        m
    }

    fn in_search(&self, ws: &str) -> bool {
        self.searched.iter().any(|w| w.id == ws)
    }

    fn workspace(&self, ws: &str) -> Option<&Workspace> {
        self.s.workspaces.iter().find(|w| w.id == ws)
    }

    fn pane_of(&self, id: &str) -> Option<&Pane> {
        self.s.panes.iter().find(|p| p.id == id)
    }

    fn find(&self, q: &str, kinds: &[String]) -> Vec<Value> {
        if let Some(k) = full_id(q) {
            if !kinds.iter().any(|x| x == k) {
                return Vec::new();
            }
            return self.filter(k, |id, _| id == q);
        }
        self.match_query(q, kinds)
    }

    fn session_matches(&self, q: &str) -> Result<Vec<Workspace>, String> {
        let mut q = q.trim().to_string();
        if full_id(&q) == Some("block") {
            let pane = self.block_by_id(&q)?;
            q = self.b.ids.rex("session", &pane.workspace_id);
        }
        let mut out = Vec::new();
        for f in self.find(&q, &["session".to_string()]) {
            if let Some(sid) = f["session_id"].as_str()
                && let Some(ws) = self.b.ids.herdr(sid)
                && let Some(w) = self.workspace(&ws)
            {
                out.push(w.clone());
            }
        }
        Ok(out)
    }
}
