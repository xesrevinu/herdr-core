//! Terminal block methods (`block.method` / `com.superlogical.terminal.*`),
//! terminal events (`block.event`, `client.key`), resize/size, key encoding,
//! local & remote `list_dir`, and `upload_begin` / `rex.data.bytes.v1`.

use super::appdoc::{Pane, TerminalRec, machine_of};
use super::bridge::{
    BLOB_KIND_CLIPBOARD, BLOB_KIND_RESULT, DesiredSize, MAX_CORE_PUT, MAX_UPLOAD_BATCHES,
    MAX_UPLOAD_BYTES, MAX_UPLOAD_COUNT, RexBridge, UPLOAD_IDLE, UploadBatch, UploadFile,
    process_owner, pwd_of,
};
use super::hub::{
    BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, DEFAULT_CELL_H, DEFAULT_CELL_W, MOD_ALT, MOD_CTRL,
    MOD_SHIFT, MOD_SUPER, MouseInput, MouseKind, TermFrame, TermGridSize, client_clear_frame,
};
use super::ops::{num_arg, obj_arg, str_arg};
use super::proto::*;
use super::server::{RexClient, UploadChunk, UploadServeFn, UploadStream};
use crate::server::call_internal;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};
use uuid::Uuid;

pub const TERMINAL_METHODS: &[&str] = &[
    "format",
    "write",
    "title",
    "pwd",
    "size",
    "resize",
    "set_theme",
    "process",
    "program_status",
    "clear",
    "reset",
    "upload_begin",
    "list_dir",
    "blob_read",
    "clipboard_read",
];

const PASTE_START: &str = "\x1b[200~";
const PASTE_END: &str = "\x1b[201~";
const LIST_DIR_LIMIT: usize = 2000;

const LIST_DIR_PY: &str = r#"
import os, json, sys
path, prefix, want_files, limit, cwd = sys.argv[1], sys.argv[2], sys.argv[3] == "1", int(sys.argv[4]), sys.argv[5]
home = os.path.expanduser("~")
def resolve(p):
    p = (p or "").strip()
    if not p:
        p = cwd or os.getcwd()
    if p == "~":
        p = home
    elif p.startswith("~/"):
        p = os.path.join(home, p[2:])
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.normpath(p)
abs_path = resolve(path)
out = {"path": abs_path, "home": home, "status": "ok", "entries": [], "truncated": False}
try:
    st = os.lstat(abs_path)
    if os.path.islink(abs_path):
        st = os.stat(abs_path)
except FileNotFoundError:
    out["status"] = "missing"
    print(json.dumps(out)); raise SystemExit
except NotADirectoryError:
    out["status"] = "not_dir"
    print(json.dumps(out)); raise SystemExit
except PermissionError:
    out["status"] = "denied"
    print(json.dumps(out)); raise SystemExit
except OSError as e:
    out["status"] = "not_dir" if getattr(e, "errno", None) == 20 else "denied"
    print(json.dumps(out)); raise SystemExit
if not os.path.isdir(abs_path):
    out["status"] = "not_dir"
    print(json.dumps(out)); raise SystemExit
try:
    names = os.listdir(abs_path)
except PermissionError:
    out["status"] = "denied"
    print(json.dumps(out)); raise SystemExit
pref = prefix.lower()
entries = []
truncated = False
for name in names:
    if pref and not name.lower().startswith(pref):
        continue
    full = os.path.join(abs_path, name)
    try:
        lst = os.lstat(full)
        symlink = os.path.islink(full)
        if symlink:
            os.stat(full)
        is_file = not os.path.isdir(full)
    except OSError:
        continue
    if is_file and not want_files:
        continue
    if len(entries) >= limit:
        truncated = True
        break
    ent = {"name": name}
    if symlink:
        ent["symlink"] = True
    if want_files and is_file:
        ent["file"] = True
    entries.append(ent)
out["entries"] = entries
out["truncated"] = truncated
print(json.dumps(out))
"#;

// =========================================================================
// block.method & com.superlogical.terminal.<m>
// =========================================================================

pub async fn h_block_method(
    b: &Arc<RexBridge>,
    c: &Arc<RexClient>,
    p: &Value,
) -> Result<Value, RexError> {
    let block_id = str_arg(p, "block_id");
    let pane = b.herdr_id(block_id, "block")?;
    let empty_obj = json!({});
    let args = obj_arg(p, "args").unwrap_or(&empty_obj);
    let raw_method = str_arg(p, "method");
    let method = raw_method
        .strip_prefix(&format!("{TERMINAL_CREATOR}."))
        .unwrap_or(raw_method);

    match method {
        "format" => {
            let v = call_internal(
                &b.core,
                None,
                "terminal.read",
                json!({"terminal": pane, "lines": 0}),
            )
            .await?;
            Ok(json!({
                "content": v["text"].as_str().unwrap_or_default(),
                "format": str_arg(args, "format"),
            }))
        }
        "write" => {
            let data = str_arg(args, "data");
            b.unscroll(&pane).await;
            if let Some(text) = pasted(data) {
                b.paste_input(&pane, text).await?;
            } else {
                b.inject_bytes(&pane, data.as_bytes()).await?;
            }
            Ok(json!({"bytes_written": data.len()}))
        }
        "title" => {
            let x = b.pane(&pane).await?;
            let mut out = Map::new();
            out.insert("title".into(), Value::String(x.terminal_title.clone()));
            if !x.terminal_title.is_empty()
                && let Some(o) = process_owner(&x)
            {
                out.insert("owner".into(), o);
            }
            Ok(Value::Object(out))
        }
        "pwd" => {
            let x = b.pane(&pane).await?;
            if !pwd_of(&x).is_empty() {
                let mut out = Map::new();
                out.insert("pwd".into(), Value::String(b.pwd_url_for(&x)));
                if let Some(o) = process_owner(&x) {
                    out.insert("owner".into(), o);
                }
                Ok(Value::Object(out))
            } else {
                Ok(json!({}))
            }
        }
        "size" => Ok(b.term_size(block_id, &pane)),
        "resize" => b.term_resize(c, str_arg(p, "session_id"), block_id, &pane, args).await,
        "clear" | "reset" => {
            b.unscroll(&pane).await;
            let cleared = call_internal(&b.core, None, "terminal.clear", json!({"terminal": pane}))
                .await
                .is_ok();
            if let Some(h) = b.hub(&pane) {
                let frame = if cleared {
                    b.screen_frame(&pane, h.current()).await
                } else {
                    client_clear_frame(h.current())
                };
                h.push_full(frame);
            }
            Ok(Value::Null)
        }
        "set_theme" => {
            let map = args.as_object().cloned().unwrap_or_default();
            b.st
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .themes
                .insert(block_id.to_string(), map.clone());
            if let Some(h) = b.hub(&pane) {
                h.send_theme(map);
            }
            Ok(json!({}))
        }
        "process" => b.term_process(&pane).await,
        "upload_begin" => b.upload_begin(c, p, &pane).await,
        "program_status" => {
            let x = b.pane(&pane).await?;
            Ok(json!({"records": b.status_records(&x)}))
        }
        "list_dir" => {
            let x = b.pane(&pane).await?;
            b.term_list_dir(&x, args).await
        }
        "blob_read" => b.term_blob_read(BLOB_KIND_RESULT, args),
        "clipboard_read" => b.term_blob_read(BLOB_KIND_CLIPBOARD, args),
        _ => Err(RexError::method_not_found(format!(
            "block method not supported: {raw_method}"
        ))),
    }
}

pub async fn h_terminal_method(
    b: &Arc<RexBridge>,
    c: &Arc<RexClient>,
    p: &Value,
    method: &str,
) -> Result<Value, RexError> {
    let args = if let Some(raw) = p.get("args") {
        if raw.is_null() {
            json!({})
        } else if raw.is_object() {
            raw.clone()
        } else {
            return Err(RexError::bad_request("args must be an object"));
        }
    } else {
        let mut m = Map::new();
        if let Some(obj) = p.as_object() {
            for (k, v) in obj {
                if k != "session_id" && k != "block_id" {
                    m.insert(k.clone(), v.clone());
                }
            }
        }
        Value::Object(m)
    };
    let req = json!({
        "session_id": str_arg(p, "session_id"),
        "block_id": str_arg(p, "block_id"),
        "method": method,
        "args": args,
    });
    h_block_method(b, c, &req).await
}

// =========================================================================
// block.event & client.key
// =========================================================================

pub async fn h_block_event(b: &RexBridge, c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let pane = b.herdr_id(str_arg(p, "block_id"), "block")?;
    let empty_obj = json!({});
    let ev = obj_arg(p, "event").unwrap_or(&empty_obj);
    let payload = obj_arg(ev, "payload").unwrap_or(&empty_obj);
    match str_arg(ev, "type") {
        "paste" => {
            b.unscroll(&pane).await;
            b.paste_input(&pane, str_arg(payload, "text")).await?;
        }
        "key" => {
            let k = obj_arg(payload, "key").unwrap_or(payload);
            b.send_key(&pane, k).await?;
        }
        "mouse" => {
            b.mouse_event(c, &pane, payload).await?;
        }
        "wheel" => {
            b.wheel_event(&pane, payload).await?;
        }
        "focus" => {
            b.focus_event(&pane, payload)?;
        }
        other => {
            eprintln!("rex block.event {other} (not mapped)");
        }
    }
    Ok(Value::Null)
}

pub async fn h_client_key(b: &RexBridge, _c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let pane = {
        let bid = str_arg(p, "block_id");
        if !bid.is_empty() {
            b.herdr_id(bid, "block")?
        } else {
            b.focused_pane(str_arg(p, "session_id")).await?
        }
    };
    if pane.is_empty() {
        return Ok(json!({"handled": false}));
    }
    let empty_obj = json!({});
    let k = obj_arg(p, "key").unwrap_or(&empty_obj);
    b.send_key(&pane, k).await?;
    Ok(json!({"handled": false}))
}

// =========================================================================
// RexBridge terminal helpers
// =========================================================================

impl RexBridge {
    fn terminal_wants_paste(&self, pane: &str) -> bool {
        if let Some(h) = self.hub(pane) {
            return h.wants_paste();
        }
        if machine_of(pane).is_empty()
            && let Some(id) = crate::terminals::parse_id(pane)
        {
            let st = self.core.lock();
            if let Some(screen) = st.screens.get(&id) {
                return screen.dec_mode(2004);
            }
        }
        false
    }

    pub async fn paste_input(&self, pane: &str, text: &str) -> Result<(), RexError> {
        let bytes = crate::input::paste(self.terminal_wants_paste(pane), text);
        if let Some(h) = self.hub(pane)
            && h.control
        {
            h.write_input(&bytes);
            return Ok(());
        }
        self.inject_bytes(pane, &bytes).await
    }

    pub fn focus_event(&self, pane: &str, p: &Value) -> Result<(), RexError> {
        let focused = match str_arg(p, "action") {
            "in" | "" => true,
            "out" => false,
            other => return Err(event_err("focus", &format!("unknown focus action {other:?}"))),
        };
        if let Some(h) = self.hub(pane)
            && h.control
        {
            h.send_focus(focused);
        }
        Ok(())
    }

    pub async fn focused_pane(&self, session_id: &str) -> Result<String, RexError> {
        let wid = self.herdr_id(session_id, "session")?;
        let s = self.current().await;
        for w in &s.workspaces {
            if w.id == wid
                && !w.active_tab_id.is_empty()
                && let Some(l) = self.tab_layout(&w.active_tab_id)
            {
                return Ok(l.focused);
            }
        }
        Ok(String::new())
    }

    fn encode_terminal_key(&self, pane: &str, ev: &RexKeyEvent) -> Option<Vec<u8>> {
        if let Some(h) = self.hub(pane)
            && let Some(bytes) = h.encode_key_event(ev)
        {
            return Some(bytes);
        }
        if machine_of(pane).is_empty()
            && let Some(id) = crate::terminals::parse_id(pane)
        {
            let st = self.core.lock();
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

    pub async fn send_key(&self, pane: &str, k: &Value) -> Result<(), RexError> {
        if let Some(ev) = parse_rex_key_event(k)
            && let Some(raw) = self.encode_terminal_key(pane, &ev)
        {
            if raw.is_empty() {
                return Ok(());
            }
            self.unscroll(pane).await;
            if let Some(h) = self.hub(pane)
                && h.control
            {
                h.write_input(&raw);
                return Ok(());
            }
            return self.inject_bytes(pane, &raw).await;
        }
        if k.get("composing").and_then(Value::as_bool).unwrap_or(false)
            || str_arg(k, "action") == "release"
        {
            return Ok(());
        }
        self.unscroll(pane).await;
        let (raw, named) = encode_rex_key(k);
        if let Some(h) = self.hub(pane)
            && h.control
        {
            if !raw.is_empty() {
                h.write_input(&raw);
            }
            return Ok(());
        }
        if !raw.is_empty() {
            return self.inject_bytes(pane, &raw).await;
        }
        if !named.is_empty() {
            call_internal(
                &self.core,
                None,
                "terminal.keys",
                json!({"terminal": pane, "keys": named}),
            )
            .await?;
        }
        Ok(())
    }

    fn record_desired(&self, block: &str, client: &str, size: TermGridSize) {
        let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        let mut list = vec![DesiredSize {
            client: client.to_string(),
            size,
            updated: SystemTime::now(),
        }];
        if let Some(prev) = st.desired.get(block) {
            for d in prev {
                if d.client != client {
                    list.push(d.clone());
                }
            }
        }
        st.desired.insert(block.to_string(), list);
    }

    fn client_desired(&self, block: &str, client: &str) -> Option<TermGridSize> {
        let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
        st.desired
            .get(block)?
            .iter()
            .find(|d| d.client == client)
            .map(|d| d.size)
    }

    pub fn apply_owner_size(&self, sid: &str, block: &str, pane: &str) -> bool {
        let Some(h) = self.hub(pane) else { return false };
        let Some(s) = self.owner_desired(block) else { return false };
        if !h.control || h.current() == s {
            return false;
        }
        h.apply_size(s);
        let owner = self.owner(block);
        let owner_val = if owner.is_empty() { Value::Null } else { json!({}) };
        self.emit_block_event(
            sid,
            block,
            "size_changed",
            json!({
                "columns": s.cols,
                "rows": s.rows,
                "cell_width_px": s.cell_width_px,
                "cell_height_px": s.cell_height_px,
                "owner": owner_val,
            }),
        );
        true
    }

    pub async fn term_resize(
        &self,
        c: &RexClient,
        sid: &str,
        block: &str,
        pane: &str,
        args: &Value,
    ) -> Result<Value, RexError> {
        let (Some(cols), Some(rows)) = (num_arg(args, "columns"), num_arg(args, "rows")) else {
            return Err(RexError::bad_request("resize needs columns and rows between 1 and 65535"));
        };
        if !(1.0..=65535.0).contains(&cols) || !(1.0..=65535.0).contains(&rows) {
            return Err(RexError::bad_request("resize needs columns and rows between 1 and 65535"));
        }
        let mut s = TermGridSize {
            cols: cols as u16,
            rows: rows as u16,
            cell_width_px: DEFAULT_CELL_W,
            cell_height_px: DEFAULT_CELL_H,
        };
        if let Some(prev) = self.client_desired(block, &c.id) {
            s.cell_width_px = prev.cell_width_px;
            s.cell_height_px = prev.cell_height_px;
        }
        if let Some(w) = num_arg(args, "cell_width_px")
            && w > 0.0
        {
            s.cell_width_px = w as u32;
        }
        if let Some(h) = num_arg(args, "cell_height_px")
            && h > 0.0
        {
            s.cell_height_px = h as u32;
        }
        self.record_desired(block, &c.id, s);
        let h = self.hub(pane);
        let same_grid = h
            .as_ref()
            .is_some_and(|h| h.current().cols == s.cols && h.current().rows == s.rows);
        let owner = self.owner(block);
        let resized = if owner.is_empty() || owner == c.id {
            self.apply_owner_size(sid, block, pane)
        } else {
            false
        };
        if let Some(h) = h {
            if resized && !same_grid {
                self.unscroll(pane).await;
                let cur = h.current();
                h.fanout(TermFrame {
                    width: cur.cols,
                    height: cur.rows,
                    full: false,
                    bytes: Vec::new(),
                });
            } else {
                self.align_host_viewport(pane).await;
                let frame = self.screen_frame(pane, h.current()).await;
                h.push_full(frame);
            }
        }
        Ok(json!({}))
    }

    pub fn term_size(&self, block: &str, pane: &str) -> Value {
        let s = self
            .hub(pane)
            .map(|h| h.current())
            .unwrap_or_else(|| self.layout_size(pane));
        let owner = self.owner(block);
        let owner_val = if owner.is_empty() { Value::Null } else { Value::String(owner) };
        let list: Vec<Value> = {
            let st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            st.desired
                .get(block)
                .into_iter()
                .flatten()
                .map(|d| {
                    json!({
                        "client_id": d.client,
                        "columns": d.size.cols,
                        "rows": d.size.rows,
                        "updated_at": stamp_rfc3339(d.updated),
                    })
                })
                .collect()
        };
        json!({
            "columns": s.cols,
            "rows": s.rows,
            "cell_width_px": s.cell_width_px,
            "cell_height_px": s.cell_height_px,
            "owner": owner_val,
            "desired": list,
        })
    }

    pub async fn term_process(&self, pane: &str) -> Result<Value, RexError> {
        let t = if let Some(rec) = self.live_term(pane) {
            rec
        } else {
            let v = call_internal(&self.core, None, "terminal.get", json!({"terminal": pane})).await?;
            serde_json::from_value::<TerminalRec>(v)
                .map_err(|e| RexError::internal(format!("bad terminal record: {e}")))?
        };
        let home = self.machine_home(machine_of(pane));
        let mut child = Map::new();
        child.insert("pid".into(), json!(t.pid));
        if let Some(a0) = t.argv.first() {
            child.insert("argv0".into(), Value::String(a0.clone()));
        }
        if !t.cwd.is_empty() {
            child.insert("cwd".into(), Value::String(t.cwd.clone()));
        }
        let fg = if let Some(f) = t.foreground {
            let mut m = Map::new();
            m.insert("pid".into(), json!(f.pid));
            m.insert("name".into(), Value::String(f.name));
            if let Some(a0) = f.argv.first() {
                m.insert("argv0".into(), Value::String(a0.clone()));
            }
            if !f.cwd.is_empty() {
                m.insert("cwd".into(), Value::String(f.cwd));
            }
            Value::Object(m)
        } else {
            Value::Object(child.clone())
        };
        Ok(json!({
            "last_exit": Value::Null,
            "child": Value::Object(child),
            "foreground": fg,
            "ancestors": Value::Null,
            "home": home,
        }))
    }

    pub fn term_blob_read(&self, kind: &str, args: &Value) -> Result<Value, RexError> {
        let id = num_arg(args, "id").unwrap_or(0.0) as i64;
        let offset = num_arg(args, "offset").unwrap_or(0.0) as i64;
        let max_bytes = num_arg(args, "max_bytes").unwrap_or(0.0) as i64;
        let (id, data, total, eof) = self.read_blob(kind, id, offset, max_bytes)?;
        Ok(json!({"id": id, "data": data, "total": total, "eof": eof}))
    }

    pub async fn mouse_event(&self, c: &RexClient, pane: &str, p: &Value) -> Result<(), RexError> {
        let x = num_field(p, "mouse", "MouseEvent", "x")?;
        let y = num_field(p, "mouse", "MouseEvent", "y")?;
        let mods = mouse_mods(str_arg(p, "mods"));
        let btn_name = str_arg(p, "button");
        let (button, mut known) = match btn_name {
            "left" => (BTN_LEFT, true),
            "right" => (BTN_RIGHT, true),
            "middle" => (BTN_MIDDLE, true),
            _ => (BTN_LEFT, false),
        };
        let mut m = MouseInput {
            kind: MouseKind::Down,
            button,
            column: cell_coord(x),
            row: cell_coord(y),
            mods,
        };
        match str_arg(p, "action") {
            "press" => {
                m.kind = MouseKind::Down;
                match btn_name {
                    "four" => {
                        m.kind = MouseKind::ScrollUp;
                        known = true;
                    }
                    "five" => {
                        m.kind = MouseKind::ScrollDown;
                        known = true;
                    }
                    "six" => {
                        m.kind = MouseKind::ScrollLeft;
                        known = true;
                    }
                    "seven" => {
                        m.kind = MouseKind::ScrollRight;
                        known = true;
                    }
                    _ => {}
                }
            }
            "release" => {
                m.kind = MouseKind::Up;
            }
            "motion" => {
                m.kind = MouseKind::Moved;
                known = true;
                if let Some(btns) = obj_arg(p, "buttons") {
                    for (name, b) in [("left", BTN_LEFT), ("middle", BTN_MIDDLE), ("right", BTN_RIGHT)] {
                        if btns.get(name).and_then(Value::as_bool).unwrap_or(false) {
                            m.kind = MouseKind::Drag;
                            m.button = b;
                            break;
                        }
                    }
                }
            }
            other => {
                return Err(event_err("mouse", &format!("unknown mouse action {other:?}")));
            }
        }
        if !known {
            return Ok(());
        }
        if let Some(h) = self.hub(pane)
            && h.control
            && h.reports_mouse()
        {
            if m.mods & MOD_SHIFT != 0 && m.kind <= MouseKind::Drag && m.button == BTN_LEFT {
                return self.select_drag(c, pane, m).await;
            }
            h.send_mouse(m);
            return Ok(());
        }
        if m.kind <= MouseKind::Drag && m.button == BTN_LEFT {
            return self.select_drag(c, pane, m).await;
        }
        Ok(())
    }

    pub async fn wheel_event(&self, pane: &str, p: &Value) -> Result<(), RexError> {
        let dx = num_field(p, "wheel", "WheelEvent", "delta_x")?;
        let dy = num_field(p, "wheel", "WheelEvent", "delta_y")?;
        let x = num_field(p, "wheel", "WheelEvent", "x")?;
        let y = num_field(p, "wheel", "WheelEvent", "y")?;
        let h = self.hub(pane).filter(|h| h.control);
        let unit = match str_arg(p, "delta_mode") {
            "line" => 1.0,
            "" | "pixel" => {
                let ch = h.as_ref().map_or(0, |h| h.current().cell_height_px);
                if ch > 0 { ch as f64 } else { 16.0 }
            }
            "page" => {
                let rows = h.as_ref().map_or(24, |h| h.current().rows.max(1));
                1.0 / (rows as f64)
            }
            other => return Err(event_err("wheel", &format!("unknown wheel delta mode {other:?}"))),
        };
        let reports_mouse = h.as_ref().is_some_and(|h| h.reports_mouse());
        let lines = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            let mut acc = st.wheel.get(pane).copied().unwrap_or(0.0) + dy / unit;
            let mut lines = acc.trunc();
            if reports_mouse && dy != 0.0 {
                lines = 1.0_f64.copysign(dy);
                acc = lines;
            }
            st.wheel.insert(pane.to_string(), acc - lines);
            lines as i32
        };
        let mut m = MouseInput {
            kind: MouseKind::ScrollDown,
            button: 0,
            column: cell_coord(x),
            row: cell_coord(y),
            mods: mouse_mods(str_arg(p, "mods")),
        };
        if !reports_mouse {
            if lines == 0 {
                return Ok(());
            }
            if let Some(h) = &h
                && h.on_alt_screen()
            {
                h.send_arrows(lines);
                return Ok(());
            }
            return self.scroll_by(pane, lines).await;
        }
        let Some(h) = h else { return Ok(()) };
        if lines != 0 {
            m.kind = if lines < 0 { MouseKind::ScrollUp } else { MouseKind::ScrollDown };
            h.send_mouse(m);
        }
        if dx != 0.0 {
            m.kind = if dx < 0.0 { MouseKind::ScrollLeft } else { MouseKind::ScrollRight };
            h.send_mouse(m);
        }
        Ok(())
    }

    pub async fn term_list_dir(&self, pane: &Pane, args: &Value) -> Result<Value, RexError> {
        let cwd = pwd_of(pane).to_string();
        let path = str_arg(args, "path").to_string();
        let prefix = str_arg(args, "prefix").to_string();
        let files = args.get("files").and_then(Value::as_bool).unwrap_or(false);
        let limit = num_arg(args, "limit")
            .filter(|n| *n > 0.0)
            .map_or(LIST_DIR_LIMIT, |n| n as usize);
        let on = machine_of(&pane.id).to_string();
        if !on.is_empty() {
            return self.list_dir_remote(&on, &cwd, &path, &prefix, files, limit).await;
        }
        let home = self.local_home();
        Ok(list_directory(&path, &cwd, &home, &prefix, files, limit))
    }

    async fn list_dir_remote(
        &self,
        on: &str,
        cwd: &str,
        path: &str,
        prefix: &str,
        files: bool,
        limit: usize,
    ) -> Result<Value, RexError> {
        let flag = if files { "1" } else { "0" };
        let lim = if limit == 0 { LIST_DIR_LIMIT } else { limit }.to_string();
        for py in ["python3", "python"] {
            let mut params = Map::new();
            params.insert(
                "argv".into(),
                json!([py, "-c", LIST_DIR_PY, path, prefix, flag, lim, cwd]),
            );
            params.insert("on".into(), Value::String(on.to_string()));
            if !cwd.is_empty() {
                params.insert("cwd".into(), Value::String(cwd.to_string()));
            }
            params.insert("timeout".into(), json!(8.0));
            if let Ok(res) = call_internal(&self.core, None, "machine.exec", Value::Object(params)).await
                && res["code"].as_i64() == Some(0)
                && let Some(b64) = res["stdout"].as_str()
                && let Ok(raw) = B64.decode(b64)
                && let Ok(mut v) = serde_json::from_slice::<Value>(&raw)
                && let Some(m) = v.as_object_mut()
            {
                m.entry("entries").or_insert_with(|| json!([]));
                return Ok(v);
            }
        }
        let abs = resolve_list_path(path, cwd, "");
        Ok(json!({
            "path": abs,
            "home": "",
            "status": "denied",
            "entries": [],
            "truncated": false,
        }))
    }

    pub async fn upload_begin(
        self: &Arc<Self>,
        c: &Arc<RexClient>,
        p: &Value,
        pane: &str,
    ) -> Result<Value, RexError> {
        let sid = str_arg(p, "session_id");
        if !c.attached(sid) {
            return Err(RexError::conflict("connection is not attached to this session"));
        }
        let empty = json!({});
        let args = obj_arg(p, "args").unwrap_or(&empty);
        let spec = parse_upload(args)?;
        let key = if spec.batch.is_empty() { spec.r#ref.clone() } else { spec.batch.clone() };

        let batch = {
            let mut ups = self.uploads.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            ups.retain(|_, u| {
                let seen = *u.seen.lock().unwrap_or_else(|p| p.into_inner());
                if now.duration_since(seen) > UPLOAD_IDLE {
                    let _ = u.cancel_tx.send(true);
                    false
                } else {
                    true
                }
            });
            upload_room_locked(&ups, &key, spec.size)?;
            let u = ups
                .entry(key.clone())
                .or_insert_with(|| {
                    let (cancel_tx, _) = tokio::sync::watch::channel(false);
                    let mut slots = Vec::with_capacity(spec.count);
                    slots.resize_with(spec.count, || None);
                    Arc::new(UploadBatch {
                        key: key.clone(),
                        client_id: c.id.clone(),
                        pane: pane.to_string(),
                        files: Mutex::new(slots),
                        seen: Mutex::new(now),
                        cancel_tx,
                    })
                })
                .clone();
            let mut files = u.files.lock().unwrap_or_else(|p| p.into_inner());
            if u.pane != pane || u.client_id != c.id || files.len() != spec.count {
                return Err(RexError::conflict(
                    "the batch is already reserved by another connection or pane",
                ));
            }
            if files[spec.index].is_some() {
                return Err(RexError::conflict(format!(
                    "file {} of the batch is already reserved",
                    spec.index
                )));
            }
            files[spec.index] = Some(UploadFile {
                name: spec.name.clone(),
                size: spec.size,
                got: Vec::new(),
                path: String::new(),
                done: false,
            });
            *u.seen.lock().unwrap_or_else(|p| p.into_inner()) = now;
            drop(files);
            u
        };

        let b = self.clone();
        let idx = spec.index;
        let expected_size = spec.size;
        let fname = spec.name;
        let serve: UploadServeFn = Box::new(move |st| {
            Box::pin(async move {
                b.receive_upload(batch, idx, fname, expected_size, st).await;
            })
        });
        let tk = self.srv.issue_upload_ticket(c.clone(), DATA_BYTES_PROTOCOL, serve);
        Ok(json!({"ticket": tk.ticket, "expires_in_ms": tk.expires_in_ms}))
    }

    async fn receive_upload(
        self: Arc<Self>,
        u: Arc<UploadBatch>,
        index: usize,
        name: String,
        expected_size: usize,
        mut st: UploadStream,
    ) {
        let mut cancel_rx = u.cancel_tx.subscribe();
        let mut got = Vec::with_capacity(expected_size.min(64 << 10));

        loop {
            let chunk = tokio::select! {
                _ = cancel_rx.changed() => {
                    st.close(CLOSE_PROVIDER_CANCELED, "the upload was dropped").await;
                    return;
                }
                msg = st.recv() => msg,
            };
            match chunk {
                UploadChunk::Data(msg) => {
                    if got.len() + msg.len() > expected_size {
                        st.close(CLOSE_PROTOCOL_VIOLATION, "data stream broke a rule").await;
                        self.abort_upload(&u, &name, &format!("more than {expected_size} bytes"));
                        return;
                    }
                    if !self.touch_upload(&u) {
                        st.close(CLOSE_PROVIDER_CANCELED, "the upload expired").await;
                        self.abort_upload(&u, &name, "no bytes for upload idle timeout");
                        return;
                    }
                    got.extend_from_slice(&msg);
                }
                UploadChunk::HalfClose => {
                    if got.len() != expected_size {
                        st.close(CLOSE_PROTOCOL_VIOLATION, "data stream broke a rule").await;
                        self.abort_upload(
                            &u,
                            &name,
                            &format!("the stream ended with {} of {expected_size} bytes", got.len()),
                        );
                        return;
                    }
                    break;
                }
                UploadChunk::Dropped => {
                    self.abort_upload(
                        &u,
                        &name,
                        &format!("the stream ended with {} of {expected_size} bytes", got.len()),
                    );
                    return;
                }
            }
        }

        if *u.cancel_tx.borrow() {
            st.close(CLOSE_PROVIDER_CANCELED, "the upload was dropped").await;
            return;
        }
        if got.len() > MAX_CORE_PUT {
            st.close(CLOSE_PROVIDER_FAILED, "could not store the file").await;
            self.abort_upload(&u, &name, "exceeds terminal.put limit");
            return;
        }

        let put_res = call_internal(
            &self.core,
            None,
            "terminal.put",
            json!({
                "terminal": u.pane,
                "name": name,
                "data": B64.encode(&got),
            }),
        )
        .await;
        let path = match put_res {
            Ok(v) => v["path"].as_str().unwrap_or_default().to_string(),
            Err(e) => {
                st.close(1011, "could not store the file").await;
                self.abort_upload(&u, &name, &format!("could not store the file: {}", e.message));
                return;
            }
        };

        let all_paths: Result<Option<Vec<String>>, ()> = {
            let mut ups = self.uploads.lock().unwrap_or_else(|p| p.into_inner());
            if !ups.get(&u.key).is_some_and(|cur| Arc::ptr_eq(cur, &u)) {
                Err(())
            } else {
                let mut files = u.files.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(slot) = files.get_mut(index).and_then(Option::as_mut) {
                    slot.path = path;
                    slot.done = true;
                    slot.got.clear();
                }
                *u.seen.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
                if files.iter().all(|f| f.as_ref().is_some_and(|x| x.done)) {
                    let paths: Vec<String> = files
                        .iter()
                        .filter_map(|f| f.as_ref().map(|x| shell_word(&x.path)))
                        .collect();
                    ups.remove(&u.key);
                    Ok(Some(paths))
                } else {
                    Ok(None)
                }
            }
        };
        let Ok(all_paths) = all_paths else {
            st.close(1001, "the upload was dropped").await;
            return;
        };

        if let Some(paths) = all_paths {
            let text = format!("{} ", paths.join(" "));
            self.unscroll(&u.pane).await;
            if let Err(e) = self.paste_input(&u.pane, &text).await {
                eprintln!("rex upload: typing the paths: {e}");
                st.close(CLOSE_PROVIDER_FAILED, "could not type the paths").await;
                return;
            }
        }
        st.close(CLOSE_NORMAL, "").await;
    }

    fn touch_upload(&self, u: &Arc<UploadBatch>) -> bool {
        let mut ups = self.uploads.lock().unwrap_or_else(|p| p.into_inner());
        let mut seen = u.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.elapsed() > UPLOAD_IDLE {
            if ups.get(&u.key).is_some_and(|cur| Arc::ptr_eq(cur, u)) {
                ups.remove(&u.key);
            }
            let _ = u.cancel_tx.send(true);
            return false;
        }
        *seen = Instant::now();
        true
    }

    fn abort_upload(&self, u: &Arc<UploadBatch>, name: &str, msg: &str) {
        eprintln!("rex upload {name}: {msg}");
        let mut ups = self.uploads.lock().unwrap_or_else(|p| p.into_inner());
        if ups.get(&u.key).is_some_and(|cur| Arc::ptr_eq(cur, u)) {
            ups.remove(&u.key);
        }
        let _ = u.cancel_tx.send(true);
    }
}

// =========================================================================
// Pure helpers: paste, keys, mouse, list_dir, upload
// =========================================================================

pub fn pasted(data: &str) -> Option<&str> {
    let rest = data.strip_prefix(PASTE_START)?;
    let (text, after) = rest.split_once(PASTE_END)?;
    after.is_empty().then_some(text)
}

pub struct RexKeyEvent {
    pub action: i32,
    pub key: i32,
    pub mods: u16,
    pub consumed_mods: u16,
    pub composing: bool,
    pub text: String,
    pub unshifted: u32,
    pub option_as_alt: bool,
}

pub fn parse_rex_key_event(k: &Value) -> Option<RexKeyEvent> {
    let action = match str_arg(k, "action") {
        "" | "press" => 1,
        "release" => 0,
        "repeat" => 2,
        _ => return None,
    };
    let name = str_arg(k, "key");
    let key = rex_ghostty_key(name);
    let mods = rex_ghostty_mods(str_arg(k, "mods"));
    let consumed_mods = rex_ghostty_mods(str_arg(k, "consumed_mods"));
    let composing = k.get("composing").and_then(Value::as_bool).unwrap_or(false);
    let raw_text = str_arg(k, "text");
    // Some synthetic callers pass raw C0 control bytes in `text` for Ctrl+key.
    // Ghostty's key encoder expects printable UTF-8 text or empty string for Ctrl chords.
    let text = if (mods & (1 << 1)) != 0
        && raw_text.len() == 1
        && raw_text.as_bytes()[0] < 0x20
    {
        String::new()
    } else {
        raw_text.to_string()
    };
    let unshifted = k
        .get("unshifted_codepoint")
        .and_then(Value::as_u64)
        .filter(|&cp| cp > 0 && cp <= u32::MAX as u64)
        .map(|cp| cp as u32)
        .unwrap_or_else(|| default_unshifted_codepoint(name));
    let option_as_alt = (consumed_mods & (1 << 2)) == 0;
    Some(RexKeyEvent {
        action,
        key,
        mods,
        consumed_mods,
        composing,
        text,
        unshifted,
        option_as_alt,
    })
}

pub fn encode_rex_key_with_screen(screen: &ghostty_vt::Terminal, k: &Value) -> Vec<u8> {
    let Some(ev) = parse_rex_key_event(k) else {
        return Vec::new();
    };
    screen.encode_key_event(
        ev.action,
        ev.key,
        ev.mods,
        ev.consumed_mods,
        ev.composing,
        &ev.text,
        ev.unshifted,
        ev.option_as_alt,
    )
}

fn rex_ghostty_mods(s: &str) -> u16 {
    let mut m = 0u16;
    for part in s.split('+') {
        match part {
            "shift" => m |= 1 << 0,
            "ctrl" => m |= 1 << 1,
            "alt" => m |= 1 << 2,
            "super" => m |= 1 << 3,
            "caps_lock" => m |= 1 << 4,
            "num_lock" => m |= 1 << 5,
            "shift_side" => m |= 1 << 6,
            "ctrl_side" => m |= 1 << 7,
            "alt_side" => m |= 1 << 8,
            "super_side" => m |= 1 << 9,
            _ => {}
        }
    }
    m
}

fn default_unshifted_codepoint(name: &str) -> u32 {
    if let Some(ch) = name.strip_prefix("key_").filter(|s| s.len() == 1) {
        return ch.as_bytes()[0].to_ascii_lowercase() as u32;
    }
    if let Some(ch) = name.strip_prefix("digit_").filter(|s| s.len() == 1) {
        return ch.as_bytes()[0] as u32;
    }
    match name {
        "backquote" => '`' as u32,
        "backslash" => '\\' as u32,
        "bracket_left" => '[' as u32,
        "bracket_right" => ']' as u32,
        "comma" => ',' as u32,
        "equal" => '=' as u32,
        "minus" => '-' as u32,
        "period" => '.' as u32,
        "quote" => '\'' as u32,
        "semicolon" => ';' as u32,
        "slash" => '/' as u32,
        "space" => ' ' as u32,
        _ => 0,
    }
}

/// Maps W3C/Rex snake_case key names to `GhosttyKey` (`vendor/ghostty/include/ghostty/vt/key/event.h`).
fn rex_ghostty_key(name: &str) -> i32 {
    match name {
        "unidentified" | "" => 0,
        "backquote" => 1,
        "backslash" => 2,
        "bracket_left" => 3,
        "bracket_right" => 4,
        "comma" => 5,
        "digit_0" => 6,
        "digit_1" => 7,
        "digit_2" => 8,
        "digit_3" => 9,
        "digit_4" => 10,
        "digit_5" => 11,
        "digit_6" => 12,
        "digit_7" => 13,
        "digit_8" => 14,
        "digit_9" => 15,
        "equal" => 16,
        "intl_backslash" => 17,
        "intl_ro" => 18,
        "intl_yen" => 19,
        "key_a" => 20,
        "key_b" => 21,
        "key_c" => 22,
        "key_d" => 23,
        "key_e" => 24,
        "key_f" => 25,
        "key_g" => 26,
        "key_h" => 27,
        "key_i" => 28,
        "key_j" => 29,
        "key_k" => 30,
        "key_l" => 31,
        "key_m" => 32,
        "key_n" => 33,
        "key_o" => 34,
        "key_p" => 35,
        "key_q" => 36,
        "key_r" => 37,
        "key_s" => 38,
        "key_t" => 39,
        "key_u" => 40,
        "key_v" => 41,
        "key_w" => 42,
        "key_x" => 43,
        "key_y" => 44,
        "key_z" => 45,
        "minus" => 46,
        "period" => 47,
        "quote" => 48,
        "semicolon" => 49,
        "slash" => 50,
        "alt_left" => 51,
        "alt_right" => 52,
        "backspace" => 53,
        "caps_lock" => 54,
        "context_menu" => 55,
        "control_left" => 56,
        "control_right" => 57,
        "enter" => 58,
        "meta_left" => 59,
        "meta_right" => 60,
        "shift_left" => 61,
        "shift_right" => 62,
        "space" => 63,
        "tab" => 64,
        "convert" => 65,
        "kana_mode" => 66,
        "non_convert" => 67,
        "delete" => 68,
        "end" => 69,
        "help" => 70,
        "home" => 71,
        "insert" => 72,
        "page_down" => 73,
        "page_up" => 74,
        "arrow_down" => 75,
        "arrow_left" => 76,
        "arrow_right" => 77,
        "arrow_up" => 78,
        "num_lock" => 79,
        "numpad_0" => 80,
        "numpad_1" => 81,
        "numpad_2" => 82,
        "numpad_3" => 83,
        "numpad_4" => 84,
        "numpad_5" => 85,
        "numpad_6" => 86,
        "numpad_7" => 87,
        "numpad_8" => 88,
        "numpad_9" => 89,
        "numpad_add" => 90,
        "numpad_backspace" => 91,
        "numpad_clear" => 92,
        "numpad_clear_entry" => 93,
        "numpad_comma" => 94,
        "numpad_decimal" => 95,
        "numpad_divide" => 96,
        "numpad_enter" => 97,
        "numpad_equal" => 98,
        "numpad_memory_add" => 99,
        "numpad_memory_clear" => 100,
        "numpad_memory_recall" => 101,
        "numpad_memory_store" => 102,
        "numpad_memory_subtract" => 103,
        "numpad_multiply" => 104,
        "numpad_paren_left" => 105,
        "numpad_paren_right" => 106,
        "numpad_subtract" => 107,
        "numpad_separator" => 108,
        "numpad_up" => 109,
        "numpad_down" => 110,
        "numpad_right" => 111,
        "numpad_left" => 112,
        "numpad_begin" => 113,
        "numpad_home" => 114,
        "numpad_end" => 115,
        "numpad_insert" => 116,
        "numpad_delete" => 117,
        "numpad_page_up" => 118,
        "numpad_page_down" => 119,
        "escape" => 120,
        "f1" => 121,
        "f2" => 122,
        "f3" => 123,
        "f4" => 124,
        "f5" => 125,
        "f6" => 126,
        "f7" => 127,
        "f8" => 128,
        "f9" => 129,
        "f10" => 130,
        "f11" => 131,
        "f12" => 132,
        "f13" => 133,
        "f14" => 134,
        "f15" => 135,
        "f16" => 136,
        "f17" => 137,
        "f18" => 138,
        "f19" => 139,
        "f20" => 140,
        "f21" => 141,
        "f22" => 142,
        "f23" => 143,
        "f24" => 144,
        "f25" => 145,
        "fn" => 146,
        "fn_lock" => 147,
        "print_screen" => 148,
        "scroll_lock" => 149,
        "pause" => 150,
        "browser_back" => 151,
        "browser_favorites" => 152,
        "browser_forward" => 153,
        "browser_home" => 154,
        "browser_refresh" => 155,
        "browser_search" => 156,
        "browser_stop" => 157,
        "eject" => 158,
        "launch_app_1" => 159,
        "launch_app_2" => 160,
        "launch_mail" => 161,
        "media_play_pause" => 162,
        "media_select" => 163,
        "media_stop" => 164,
        "media_track_next" => 165,
        "media_track_previous" => 166,
        "power" => 167,
        "sleep" => 168,
        "audio_volume_down" => 169,
        "audio_volume_mute" => 170,
        "audio_volume_up" => 171,
        "wake_up" => 172,
        "copy" => 173,
        "cut" => 174,
        "paste" => 175,
        _ => 0,
    }
}

pub fn encode_rex_key(k: &Value) -> (Vec<u8>, Vec<String>) {
    let mut mods: HashSet<&str> = str_arg(k, "mods").split('+').filter(|s| !s.is_empty()).collect();
    if mods.contains("super") {
        return (Vec::new(), Vec::new());
    }
    for m in str_arg(k, "consumed_mods").split('+') {
        if m == "ctrl" || m == "alt" {
            mods.remove(m);
        }
    }
    let name = str_arg(k, "key");
    let text = str_arg(k, "text");
    let chord = mods.contains("ctrl") || mods.contains("alt");
    if !text.is_empty() && !chord {
        return (text.as_bytes().to_vec(), vec![text.to_string()]);
    }
    if !chord {
        let raw = match name {
            "delete" => Some("\x1b[3~"),
            "home" => Some("\x1b[H"),
            "end" => Some("\x1b[F"),
            "page_up" => Some("\x1b[5~"),
            "page_down" => Some("\x1b[6~"),
            "insert" => Some("\x1b[2~"),
            _ => None,
        };
        if let Some(seq) = raw {
            return (seq.as_bytes().to_vec(), Vec::new());
        }
    }
    match name {
        "enter" | "numpad_enter" => return (b"\r".to_vec(), vec!["enter".into()]),
        "tab" => return (b"\t".to_vec(), vec!["tab".into()]),
        "backspace" => return (vec![0x7f], vec!["backspace".into()]),
        "escape" => return (vec![0x1b], vec!["esc".into()]),
        "space" => return (b" ".to_vec(), vec!["space".into()]),
        "arrow_up" => return (b"\x1b[A".to_vec(), vec!["up".into()]),
        "arrow_down" => return (b"\x1b[B".to_vec(), vec!["down".into()]),
        "arrow_right" => return (b"\x1b[C".to_vec(), vec!["right".into()]),
        "arrow_left" => return (b"\x1b[D".to_vec(), vec!["left".into()]),
        _ => {}
    }
    if chord && mods.contains("ctrl") && text.len() == 1 {
        let b = text.as_bytes()[0];
        return (vec![b & 0x1f], vec![format!("ctrl+{}", text.to_lowercase())]);
    }
    if chord && mods.contains("ctrl") {
        let base = name
            .strip_prefix("key_")
            .or_else(|| name.strip_prefix("digit_"))
            .unwrap_or(name);
        if base.len() == 1 {
            let mut c = base.as_bytes()[0];
            if c.is_ascii_uppercase() {
                c = c.to_ascii_lowercase();
            }
            return (vec![c & 0x1f], vec![format!("ctrl+{}", c as char)]);
        }
    }
    if is_fn_key(name) {
        return (Vec::new(), vec![name.to_string()]);
    }
    if !text.is_empty() {
        return (text.as_bytes().to_vec(), vec![text.to_string()]);
    }
    (Vec::new(), Vec::new())
}

fn is_fn_key(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('f') else { return false };
    (1..=2).contains(&rest.len()) && rest.bytes().all(|b| b.is_ascii_digit())
}

fn event_err(kind: &str, msg: &str) -> RexError {
    RexError::bad_request(format!(
        r#"netapi: decoding args for "block.event": decoding {kind} event payload: {msg}"#
    ))
}

fn num_field(p: &Value, kind: &str, typ: &str, k: &str) -> Result<f64, RexError> {
    let Some(v) = p.get(k) else { return Ok(0.0) };
    if v.is_null() {
        return Ok(0.0);
    }
    v.as_f64().ok_or_else(|| {
        let jk = match v {
            Value::String(_) => "string",
            Value::Bool(_) => "bool",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
            _ => "number",
        };
        event_err(
            kind,
            &format!("json: cannot unmarshal {jk} into Go struct field {typ}.{k} of type float64"),
        )
    })
}

fn mouse_mods(s: &str) -> u8 {
    let mut m = 0u8;
    for x in s.split('+') {
        match x {
            "shift" => m |= MOD_SHIFT,
            "ctrl" => m |= MOD_CTRL,
            "alt" => m |= MOD_ALT,
            "super" => m |= MOD_SUPER,
            _ => {}
        }
    }
    m
}

fn cell_coord(f: f64) -> u16 {
    f.clamp(0.0, u16::MAX as f64) as u16
}

fn list_directory(path: &str, cwd: &str, home: &str, prefix: &str, files: bool, limit: usize) -> Value {
    let limit = if limit == 0 { LIST_DIR_LIMIT } else { limit };
    let abs = resolve_list_path(path, cwd, home);
    let mut out = Map::new();
    out.insert("path".into(), Value::String(abs.clone()));
    out.insert("home".into(), Value::String(home.to_string()));
    out.insert("status".into(), Value::String("ok".into()));
    out.insert("entries".into(), Value::Array(Vec::new()));
    out.insert("truncated".into(), Value::Bool(false));

    let meta = match std::fs::symlink_metadata(&abs) {
        Ok(m) => m,
        Err(e) => {
            out.insert("status".into(), Value::String(list_dir_status(&e).into()));
            return Value::Object(out);
        }
    };
    let target = if meta.file_type().is_symlink() {
        match std::fs::metadata(&abs) {
            Ok(m) => m,
            Err(e) => {
                out.insert("status".into(), Value::String(list_dir_status(&e).into()));
                return Value::Object(out);
            }
        }
    } else {
        meta
    };
    if !target.is_dir() {
        out.insert("status".into(), Value::String("not_dir".into()));
        return Value::Object(out);
    }
    let rd = match std::fs::read_dir(&abs) {
        Ok(r) => r,
        Err(e) => {
            out.insert("status".into(), Value::String(list_dir_status(&e).into()));
            return Value::Object(out);
        }
    };
    let pref_low = prefix.to_lowercase();
    let mut entries = Vec::new();
    let mut truncated = false;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !pref_low.is_empty() && !name.to_lowercase().starts_with(&pref_low) {
            continue;
        }
        let full = ent.path();
        let Ok(linfo) = std::fs::symlink_metadata(&full) else { continue };
        let symlink = linfo.file_type().is_symlink();
        let target = if symlink {
            match std::fs::metadata(&full) {
                Ok(m) => m,
                Err(_) => continue,
            }
        } else {
            linfo
        };
        let is_file = !target.is_dir();
        if is_file && !files {
            continue;
        }
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        let mut item = Map::new();
        item.insert("name".into(), Value::String(name));
        if symlink {
            item.insert("symlink".into(), Value::Bool(true));
        }
        if files && is_file {
            item.insert("file".into(), Value::Bool(true));
        }
        entries.push(Value::Object(item));
    }
    out.insert("entries".into(), Value::Array(entries));
    out.insert("truncated".into(), Value::Bool(truncated));
    Value::Object(out)
}

fn resolve_list_path(path: &str, cwd: &str, home: &str) -> String {
    let mut p = path.trim().to_string();
    if p.is_empty() {
        p = cwd.to_string();
    }
    if p == "~" {
        p = home.to_string();
    } else if let Some(rest) = p.strip_prefix("~/") {
        p = PathBuf::from(home).join(rest).to_string_lossy().into_owned();
    }
    if p.is_empty() {
        p = std::env::current_dir()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".into());
    }
    let pb = PathBuf::from(&p);
    let abs = if pb.is_absolute() {
        pb
    } else {
        let base = if !cwd.is_empty() {
            PathBuf::from(cwd)
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
        };
        base.join(pb)
    };
    clean_path(&abs)
}

fn clean_path(p: &Path) -> String {
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    let mut has_root = false;
    for comp in p.components() {
        match comp {
            Component::RootDir => {
                has_root = true;
                stack.clear();
            }
            Component::Prefix(pre) => {
                stack.push(pre.as_os_str().to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !stack.is_empty() {
                    stack.pop();
                } else if !has_root {
                    stack.push("..".into());
                }
            }
            Component::Normal(seg) => stack.push(seg.to_os_string()),
        }
    }
    let mut out = PathBuf::new();
    if has_root {
        out.push("/");
    }
    for s in stack {
        out.push(s);
    }
    if out.as_os_str().is_empty() {
        ".".into()
    } else {
        out.to_string_lossy().into_owned()
    }
}

fn list_dir_status(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::NotFound => "missing",
        std::io::ErrorKind::PermissionDenied => "denied",
        std::io::ErrorKind::NotADirectory => "not_dir",
        _ => {
            if e.raw_os_error() == Some(20) {
                "not_dir"
            } else {
                "denied"
            }
        }
    }
}

pub struct UploadSpec {
    pub r#ref: String,
    pub name: String,
    pub batch: String,
    pub size: usize,
    pub index: usize,
    pub count: usize,
}

pub fn parse_upload(args: &Value) -> Result<UploadSpec, RexError> {
    let r#ref = str_arg(args, "ref").to_string();
    let name = str_arg(args, "name").to_string();
    let batch = str_arg(args, "batch").to_string();
    let size_i = num_arg(args, "size").unwrap_or(0.0) as i64;
    let index_i = num_arg(args, "index").unwrap_or(0.0) as i64;
    let mut count_i = num_arg(args, "count").unwrap_or(0.0) as i64;

    let Some(raw_uuid) = r#ref.strip_prefix("upload:") else {
        return Err(RexError::bad_request("ref must start with upload:"));
    };
    if let Err(e) = Uuid::parse_str(raw_uuid) {
        return Err(RexError::bad_request(format!("ref must hold a UUID: {e}")));
    }
    if !is_safe_file_name(&name) {
        return Err(RexError::bad_request(format!("upload name {name:?} is not a file name")));
    }
    if size_i < 0 || size_i as usize > MAX_CORE_PUT {
        return Err(RexError::bad_request(format!(
            "upload size {size_i} is outside 0 to {MAX_CORE_PUT}"
        )));
    }
    if batch.is_empty() {
        if index_i != 0 || count_i > 1 {
            return Err(RexError::bad_request("index and count need a batch"));
        }
        count_i = 1;
    } else if count_i < 1
        || count_i as usize > MAX_UPLOAD_COUNT
        || index_i < 0
        || index_i >= count_i
    {
        return Err(RexError::bad_request(format!(
            "a batch needs count from 1 to {MAX_UPLOAD_COUNT}, and index below it"
        )));
    }
    Ok(UploadSpec {
        r#ref,
        name,
        batch,
        size: size_i as usize,
        index: index_i as usize,
        count: count_i as usize,
    })
}

fn upload_room_locked(
    ups: &std::collections::HashMap<String, Arc<UploadBatch>>,
    key: &str,
    size: usize,
) -> Result<(), RexError> {
    if !ups.contains_key(key) && ups.len() >= MAX_UPLOAD_BATCHES {
        return Err(RexError::too_large(format!(
            "{MAX_UPLOAD_BATCHES} uploads are already in progress"
        )));
    }
    let mut reserved = 0usize;
    for u in ups.values() {
        let files = u.files.lock().unwrap_or_else(|p| p.into_inner());
        for f in files.iter().flatten() {
            if !f.done {
                reserved += f.size;
            }
        }
    }
    if reserved + size > MAX_UPLOAD_BYTES {
        return Err(RexError::too_large(format!(
            "uploads in progress hold {reserved} bytes; {size} more would pass {MAX_UPLOAD_BYTES}"
        )));
    }
    Ok(())
}

pub fn is_safe_file_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
        return false;
    }
    if name.contains('/') || name.contains('\\') {
        return false;
    }
    !name.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
}

pub fn shell_word(s: &str) -> String {
    if !s.is_empty()
        && s.chars().all(|r| {
            r.is_ascii_alphanumeric() || matches!(r, '/' | '.' | '_' | '-' | '+' | '@' | '%' | ',' | '=' | ':')
        })
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}
