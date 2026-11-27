//! Keymap watcher (`keymap.json`), layer merge (`client.keymap`), `server.config_reload`,
//! `hosts.list`, and `client.action` (popup layers, session jump, agent cycling).

use super::bridge::{RexBridge, pwd_of};
use super::ops::{h_focus_block, h_list_blocks, h_new_layer, str_arg};
use super::proto::{RexError, SHELL_FLAVOR};
use super::server::RexClient;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default, Deserialize)]
struct KeymapFile {
    #[serde(default)]
    bindings: Vec<Map<String, Value>>,
    #[serde(default)]
    modes: Vec<Value>,
    #[serde(default)]
    actions: Vec<Value>,
}

struct KeymapLayer {
    name: String,
    bindings: Vec<Map<String, Value>>,
    removals: Vec<Map<String, Value>>,
}

struct LuaPopup {
    title: &'static str,
    command: &'static str,
}

fn lua_popup(name: &str) -> Option<LuaPopup> {
    Some(match name {
        "popup_lazygit" => LuaPopup { title: "lazygit", command: "lazygit" },
        "popup_lazyjj" => LuaPopup { title: "lazyjj", command: "lazyjj" },
        "popup_lumen" => LuaPopup { title: "lumen", command: "lumen diff --watch --wrap" },
        "popup_sem" => LuaPopup {
            title: "sem",
            command: "sem diff -v --format markdown --no-cosmetics | mdcat --ansi --paginate --columns 120 --margin -",
        },
        "popup_yazi" => LuaPopup { title: "yazi", command: "yazi" },
        "popup_lazydocker" => LuaPopup { title: "lazydocker", command: "lazydocker" },
        "popup_k9s" => LuaPopup { title: "k9s", command: "k9s" },
        _ => return None,
    })
}

pub fn default_rex_dir() -> PathBuf {
    if let Ok(p) = std::env::var("REX_CONFIG")
        && !p.is_empty()
    {
        let pb = PathBuf::from(&p);
        if pb.is_file()
            && let Some(parent) = pb.parent()
        {
            return parent.to_path_buf();
        }
        return pb;
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("rex");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home).join(".config").join("rex");
    }
    PathBuf::new()
}

impl RexBridge {
    pub fn rex_dir(&self) -> PathBuf {
        if !self.rex_config.is_empty() {
            PathBuf::from(&self.rex_config)
        } else {
            default_rex_dir()
        }
    }

    pub fn keymap_path(&self) -> PathBuf {
        self.rex_dir().join("keymap.json")
    }

    pub fn init_lua_path(&self) -> PathBuf {
        self.rex_dir().join("init.lua")
    }

    pub async fn watch_keymap(self: &Arc<Self>) {
        self.publish_keymap(false);
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.tick().await;
        loop {
            tick.tick().await;
            self.publish_keymap(false);
        }
    }

    /// Reloads `keymap.json` hash. `emit` forces `keymap_changed` even when unchanged.
    pub fn publish_keymap(&self, emit: bool) -> (String, i64) {
        let hash = keymap_hash(&self.keymap_path());
        let (should_emit, generation) = {
            let mut st = self.st.lock().unwrap_or_else(|p| p.into_inner());
            if st.keymap_gen == 0 {
                st.keymap_gen = 1;
                st.keymap_hash = hash.clone();
                (emit, st.keymap_gen)
            } else {
                let changed = hash != st.keymap_hash;
                if changed {
                    st.keymap_hash = hash.clone();
                    st.keymap_gen += 1;
                } else if emit {
                    st.keymap_gen += 1;
                }
                (changed || emit, st.keymap_gen)
            }
        };
        if should_emit {
            self.srv.emit("keymap_changed", json!({"hash": hash}));
        }
        (hash, generation)
    }

    async fn agent_block_ids(&self, sid: &str) -> Result<Vec<String>, RexError> {
        let raw = h_list_blocks(self, &json!({"session_id": sid})).await?;
        let Some(list) = raw["blocks"].as_array() else {
            return Ok(Vec::new());
        };
        let mut placed = Vec::new();
        let mut agents = Vec::new();
        for item in list {
            if item["placement"].as_str() != Some("placed") {
                continue;
            }
            let id = item["block_id"].as_str().unwrap_or_default();
            if id.is_empty() {
                continue;
            }
            placed.push(id.to_string());
            if self.block_is_agent(id).await {
                agents.push(id.to_string());
            }
        }
        if !agents.is_empty() {
            Ok(agents)
        } else {
            Ok(placed)
        }
    }

    async fn block_is_agent(&self, block_id: &str) -> bool {
        let Ok(pane) = self.herdr_id(block_id, "block") else {
            return false;
        };
        let Ok(x) = self.pane(&pane).await else {
            return false;
        };
        for rec in self.status_records(&x) {
            if matches!(
                rec["state"].as_str(),
                Some("working" | "blocked" | "error")
            ) {
                return true;
            }
        }
        false
    }
}

fn keymap_hash(path: &PathBuf) -> String {
    let Ok(data) = std::fs::read(path) else {
        return String::new();
    };
    let sum = Sha256::digest(&data);
    let mut out = String::with_capacity(64);
    for b in sum {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn read_keymap_file(path: &PathBuf) -> KeymapFile {
    std::fs::read(path)
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default()
}

pub async fn h_keymap(b: &RexBridge, _c: &RexClient, p: &Value) -> Result<Value, RexError> {
    let file = read_keymap_file(&b.keymap_path());
    let (hash, generation) = b.publish_keymap(false);
    let lua = KeymapLayer {
        name: "init.lua".into(),
        bindings: file.bindings,
        removals: Vec::new(),
    };
    let bindings = merge_keymap(
        as_layers(p.get("defaults")),
        vec![lua],
        as_layers(p.get("overrides")),
    );
    let actions = if str_arg(p, "server_actions") != "none" {
        file.actions
    } else {
        Vec::new()
    };
    let init_lua = b.init_lua_path();
    let exists = init_lua.exists();
    Ok(json!({
        "bindings": bindings,
        "diagnostics": [],
        "actions": actions,
        "modes": file.modes,
        "config": {
            "path": init_lua.to_string_lossy(),
            "exists": exists,
            "generation": generation,
            "instance_id": b.instance,
            "hash": hash,
        },
    }))
}

pub async fn h_config_reload(b: &RexBridge, _c: &RexClient, _p: &Value) -> Result<Value, RexError> {
    let (_, generation) = b.publish_keymap(true);
    Ok(json!({"generation": generation, "diagnostics": []}))
}

pub async fn h_hosts_list(_b: &RexBridge, _c: &RexClient, _p: &Value) -> Result<Value, RexError> {
    Ok(json!({"hosts": [], "hash": "", "diagnostics": []}))
}

pub async fn h_client_action(
    b: &Arc<RexBridge>,
    c: &Arc<RexClient>,
    p: &Value,
) -> Result<Value, RexError> {
    if str_arg(p, "origin") == "script" {
        return Err(RexError::bad_request(r#"origin "script" is only valid from rex.invoke"#));
    }
    let name = str_arg(p, "action");
    if name.is_empty() {
        return Err(RexError::bad_request("action is required"));
    }
    let sid = str_arg(p, "session_id");
    if !sid.is_empty() && !c.attached(sid) {
        return Err(RexError::bad_request("connection is not attached to this session"));
    }
    if let Some(pop) = lua_popup(name) {
        return lua_popup_layer(b, c, p, pop).await;
    }
    let args = p.get("args").and_then(Value::as_object);
    let arg_int = |k: &str, fallback: i64| -> i64 {
        args.and_then(|m| m.get(k))
            .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
            .unwrap_or(fallback)
    };
    match name {
        "hide_rex" => Ok(queued("client.visibility.toggle", None)),
        "session_goto_n" => lua_session_goto(b, arg_int("index", 0)).await,
        "agent_cycle" => lua_agent_cycle(b, c, p, arg_int("delta", 1)).await,
        "agent_goto_n" => lua_agent_goto(b, c, p, arg_int("index", 0)).await,
        _ => Err(RexError::not_found(format!("unknown action {name}"))),
    }
}

fn queued(action: &str, args: Option<Value>) -> Value {
    let mut item = Map::new();
    item.insert("action".into(), Value::String(action.to_string()));
    if let Some(a) = args {
        item.insert("args".into(), a);
    }
    json!({"client_actions": [Value::Object(item)]})
}

async fn lua_popup_layer(
    b: &Arc<RexBridge>,
    c: &Arc<RexClient>,
    p: &Value,
    pop: LuaPopup,
) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    if sid.is_empty() {
        return Err(RexError::bad_request("session_id is required"));
    }
    let mut opts = Map::new();
    opts.insert("command".into(), json!(["/bin/zsh", "-lc", pop.command]));
    opts.insert("shell".into(), Value::String("none".into()));
    if let Ok(pane) = b.block_or_focused(p).await {
        let cwd = pwd_of(&pane);
        if !cwd.is_empty() {
            opts.insert("cwd".into(), Value::String(cwd.to_string()));
        }
    }
    let req = json!({
        "session_id": sid,
        "bounds": [0.04, 0.04, 0.92, 0.92],
        "focus": true,
        "layout": {
            "block": {
                "flavor": SHELL_FLAVOR,
                "label": pop.title,
                "options": Value::Object(opts),
            }
        }
    });
    let result = h_new_layer(b, c, &req).await?;
    Ok(json!({"result": result, "client_actions": []}))
}

async fn lua_session_goto(b: &RexBridge, idx: i64) -> Result<Value, RexError> {
    if idx < 1 {
        return Ok(json!({"client_actions": []}));
    }
    let ss = b.sessions().await;
    let i = (idx - 1) as usize;
    if i >= ss.len() {
        return Ok(json!({"client_actions": []}));
    }
    let sid = ss[i]["session_id"].as_str().unwrap_or_default();
    Ok(queued("session.select", Some(json!({"session_id": sid}))))
}

async fn lua_agent_cycle(
    b: &Arc<RexBridge>,
    c: &Arc<RexClient>,
    p: &Value,
    mut delta: i64,
) -> Result<Value, RexError> {
    if delta == 0 {
        delta = 1;
    }
    let sid = str_arg(p, "session_id");
    let ids = b.agent_block_ids(sid).await?;
    let n = ids.len() as i64;
    if n == 0 {
        return Ok(json!({"client_actions": []}));
    }
    let cur = str_arg(p, "block_id");
    let idx = ids.iter().position(|id| id == cur).unwrap_or(0) as i64;
    let next_idx = ((idx + delta).rem_euclid(n)) as usize;
    let result = h_focus_block(b, c, &json!({"session_id": sid, "block_id": ids[next_idx]})).await?;
    Ok(json!({"result": result, "client_actions": []}))
}

async fn lua_agent_goto(
    b: &Arc<RexBridge>,
    c: &Arc<RexClient>,
    p: &Value,
    index: i64,
) -> Result<Value, RexError> {
    let sid = str_arg(p, "session_id");
    let ids = b.agent_block_ids(sid).await?;
    if index < 1 || index as usize > ids.len() {
        return Ok(json!({"client_actions": []}));
    }
    let result = h_focus_block(b, c, &json!({"session_id": sid, "block_id": ids[(index - 1) as usize]})).await?;
    Ok(json!({"result": result, "client_actions": []}))
}

fn as_layers(v: Option<&Value>) -> Vec<KeymapLayer> {
    let Some(arr) = v.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for x in arr {
        let Some(m) = x.as_object() else { continue };
        let name = m.get("name").and_then(Value::as_str).unwrap_or_default();
        if name.is_empty() || name.contains(':') {
            continue;
        }
        out.push(KeymapLayer {
            name: name.to_string(),
            bindings: as_maps(m.get("bindings")),
            removals: as_maps(m.get("removals")),
        });
    }
    out
}

fn as_maps(v: Option<&Value>) -> Vec<Map<String, Value>> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_object().cloned())
        .collect()
}

fn merge_keymap(
    defaults: Vec<KeymapLayer>,
    lua: Vec<KeymapLayer>,
    overrides: Vec<KeymapLayer>,
) -> Vec<Value> {
    let mut stack: Vec<Map<String, Value>> = Vec::new();
    let mut apply = |layers: Vec<KeymapLayer>| {
        for l in layers {
            apply_removals(&mut stack, &l.removals);
            for mut item in l.bindings {
                if !item.contains_key("source") && !l.name.is_empty() {
                    item.insert("source".into(), Value::String(l.name.clone()));
                }
                stack.push(item);
            }
        }
    };
    apply(defaults);
    apply(lua);
    apply(overrides);
    stack.into_iter().rev().map(Value::Object).collect()
}

fn apply_removals(stack: &mut Vec<Map<String, Value>>, removals: &[Map<String, Value>]) {
    if removals.is_empty() {
        return;
    }
    stack.retain(|b| !removals.iter().any(|r| matches_removal(b, r)));
}

fn matches_removal(b: &Map<String, Value>, r: &Map<String, Value>) -> bool {
    if keys_sig(b.get("keys")) != keys_sig(r.get("keys")) {
        return false;
    }
    if val_str(b.get("mode")) != val_str(r.get("mode")) {
        return false;
    }
    let act = val_str(r.get("action"));
    if !act.is_empty() && val_str(b.get("action")) != act {
        return false;
    }
    true
}

fn keys_sig(v: Option<&Value>) -> String {
    let Some(arr) = v.and_then(Value::as_array) else {
        return String::new();
    };
    let parts: Vec<&str> = arr.iter().map(|e| e.as_str().unwrap_or_default()).collect();
    parts.join("\x1e")
}

fn val_str(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or_default()
}
