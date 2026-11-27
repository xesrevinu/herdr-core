//! `herdr-app` layout document model, CAS editor, and Rex snapshot builder.

use crate::rpc::RpcError;
use crate::runtime::Core;
use crate::server::call_internal;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub const APP_DOC_NAME: &str = "herdr-app";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub label: String,
    pub active_tab_id: String,
    pub focused: bool,
    pub agent_status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tab {
    pub id: String,
    pub workspace_id: String,
    pub label: String,
    pub focused: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusRec {
    pub id: String,
    pub state: String,
    pub app: String,
    pub title: String,
    pub msg: String,
    pub kind: String,
    pub progress: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pane {
    pub id: String,
    pub tab_id: String,
    pub workspace_id: String,
    pub focused: bool,
    pub agent_status: String,
    pub agent: String,
    pub display_agent: String,
    pub cwd: String,
    pub pid: i64,
    pub argv: Vec<String>,
    pub foreground_cwd: String,
    pub foreground_name: String,
    pub foreground_pid: i64,
    pub foreground_argv: Vec<String>,
    pub label: String,
    pub terminal_title: String,
    pub status_title: String,
    pub status_msg: String,
    pub status_kind: String,
    pub status_progress: Option<i64>,
    pub status_updated_ms: i64,
    pub status_records: Vec<StatusRec>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayoutPane {
    pub pane_id: String,
    pub rect: Rect,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TabLayout {
    pub tab_id: String,
    pub workspace_id: String,
    pub focused_pane_id: String,
    pub zoomed: bool,
    pub panes: Vec<LayoutPane>,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub workspaces: Vec<Workspace>,
    pub tabs: Vec<Tab>,
    pub panes: Vec<Pane>,
    pub layouts: Vec<TabLayout>,
    pub focused_pane_id: String,
}

#[derive(Debug, Clone)]
pub struct LayoutNode {
    pub kind: String,      // "pane" | "split"
    pub pane_id: String,   // when kind == "pane"
    pub direction: String, // "right" | "down"
    pub ratio: f64,
    pub first: Option<Box<LayoutNode>>,
    pub second: Option<Box<LayoutNode>>,
    pub focused: String,
    pub zoomed: bool,
}

impl LayoutNode {
    pub fn pane(pane_id: String) -> Self {
        Self {
            kind: "pane".into(),
            pane_id,
            direction: String::new(),
            ratio: 0.0,
            first: None,
            second: None,
            focused: String::new(),
            zoomed: false,
        }
    }

    pub fn leaves(&self, out: &mut Vec<String>) {
        if self.first.is_none() {
            if !self.pane_id.is_empty() {
                out.push(self.pane_id.clone());
            }
            return;
        }
        if let Some(f) = &self.first {
            f.leaves(out);
        }
        if let Some(s) = &self.second {
            s.leaves(out);
        }
    }

    pub fn has_pane(&self, pane: &str) -> bool {
        if self.kind == "pane" || self.first.is_none() {
            return self.pane_id == pane;
        }
        self.first.as_deref().is_some_and(|n| n.has_pane(pane))
            || self.second.as_deref().is_some_and(|n| n.has_pane(pane))
    }
}

#[derive(Debug, Clone, Default)]
pub struct DocMeta {
    pub layouts: HashMap<String, LayoutNode>,
    pub space_on: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct DocPack {
    pub on: String,
    pub label: String,
    pub home: String,
    pub version: u64,
    pub raw: Map<String, Value>,
}

#[derive(Debug, Clone, Default)]
pub struct FocusMaps {
    pub tab: HashMap<String, String>,
    pub pane: HashMap<String, String>,
    pub zoom: HashMap<String, bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TermStatus {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub msg: String,
    pub kind: Option<String>,
    pub progress: Option<u8>,
}

fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TermForeground {
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub cwd: String,
    #[serde(default, deserialize_with = "null_default")]
    pub pid: i64,
    #[serde(default, deserialize_with = "null_default")]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TerminalRec {
    #[serde(default, deserialize_with = "null_default")]
    pub address: String,
    pub name: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub title: String,
    #[serde(default, deserialize_with = "null_default")]
    pub cwd: String,
    #[serde(default, deserialize_with = "null_default")]
    pub cols: i32,
    #[serde(default, deserialize_with = "null_default")]
    pub rows: i32,
    #[serde(default, deserialize_with = "null_default")]
    pub state: String,
    pub status: Option<TermStatus>,
    #[serde(default, deserialize_with = "null_default")]
    pub records: HashMap<String, TermStatus>,
    pub status_ms: Option<u64>,
    #[serde(default, deserialize_with = "null_default")]
    pub pid: i64,
    #[serde(default, deserialize_with = "null_default")]
    pub argv: Vec<String>,
    pub foreground: Option<TermForeground>,
}

pub fn machine_of(addr: &str) -> &str {
    match addr.find('/') {
        Some(i) if i > 0 => &addr[..i],
        _ => "",
    }
}

pub fn qualify(addr: &str, machine: &str) -> String {
    if machine.is_empty() || addr.is_empty() || addr.contains('/') {
        addr.to_string()
    } else {
        format!("{machine}/{addr}")
    }
}

pub fn local_addr(addr: &str, machine: &str) -> String {
    if machine.is_empty() || addr.is_empty() {
        return addr.to_string();
    }
    addr.strip_prefix(&format!("{machine}/")).unwrap_or(addr).to_string()
}

pub fn fresh_id(prefix: &str) -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    let mut s = String::with_capacity(prefix.len() + 32);
    s.push_str(prefix);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

pub fn parse_doc(raw: &Value) -> Map<String, Value> {
    let mut m = raw.as_object().cloned().unwrap_or_default();
    if !m.get("spaces").is_some_and(Value::is_array) {
        m.insert("spaces".into(), Value::Array(Vec::new()));
    }
    m
}

pub fn folder_name(folder: &str, home: &str) -> String {
    let trimmed = folder.trim_end_matches(['/', '\\']);
    let home_t = home.trim_end_matches(['/', '\\']);
    if folder.is_empty() || (!home_t.is_empty() && trimmed == home_t) {
        return "~".into();
    }
    if trimmed.is_empty() {
        return folder.chars().next().map(|c| c.to_string()).unwrap_or_else(|| "/".into());
    }
    let norm = trimmed.replace('\\', "/");
    let base = norm.rsplit('/').next().unwrap_or(&norm);
    if base.is_empty() || base == "." {
        trimmed.to_string()
    } else {
        base.to_string()
    }
}

pub fn display_name(space: &Map<String, Value>, home: &str) -> String {
    let name = space.get("name").and_then(Value::as_str).unwrap_or_default().trim();
    if !name.is_empty() {
        return name.to_string();
    }
    let folder = space.get("folder").and_then(Value::as_str).unwrap_or_default();
    folder_name(folder, home)
}

pub fn session_label(machine: &str, display: &str) -> String {
    if machine.is_empty() {
        return display.to_string();
    }
    if display.is_empty() || display == "~" || display == machine {
        return machine.to_string();
    }
    format!("{machine} / {display}")
}

pub fn tab_name(tab: &Map<String, Value>, index: usize) -> String {
    let name = tab.get("name").and_then(Value::as_str).unwrap_or_default().trim();
    if !name.is_empty() {
        name.to_string()
    } else {
        format!("{}", index + 1)
    }
}

pub fn where_label(space: &str, tab: &str) -> String {
    format!("{space} / {tab}")
}

pub fn make_block(id: &str, addr: &str) -> Value {
    json!({"id": id, "type": "block", "content": {"terminal": addr}})
}

pub fn make_container(id: &str, axis: &str, children: Vec<Value>) -> Value {
    let t = if axis == "column" { "column" } else { "row" };
    json!({"id": id, "type": t, "children": children})
}

pub fn make_tab(id: &str, name: &str, pane: Value) -> Value {
    json!({"id": id, "name": name, "root": make_container(id, "row", vec![pane])})
}

pub fn make_space(id: &str, name: &str, folder: &str, tabs: Vec<Value>) -> Value {
    json!({"id": id, "name": name, "folder": folder, "tabs": tabs})
}

fn str_field<'a>(m: &'a Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn terminal_of(n: &Value) -> &str {
    n.get("content").and_then(|c| c.get("terminal")).and_then(Value::as_str).unwrap_or_default()
}

fn node_type(n: &Value) -> &str {
    n.get("type").and_then(Value::as_str).unwrap_or_default()
}

fn is_hidden(n: &Value) -> bool {
    n.get("hidden").and_then(Value::as_bool).unwrap_or(false)
}

fn axis_of(n: &Value) -> &str {
    match node_type(n) {
        "row" => "row",
        "column" => "column",
        _ => "",
    }
}

fn flex_weight(n: &Value) -> f64 {
    let Some(sz) = n.get("size").and_then(Value::as_object) else {
        return 1.0;
    };
    if sz.contains_key("px") {
        return 0.0;
    }
    sz.get("weight").and_then(Value::as_f64).filter(|w| *w > 0.0).unwrap_or(1.0)
}

fn set_weight(n: &mut Value, w: f64) {
    if let Some(m) = n.as_object_mut() {
        m.insert("size".into(), json!({"weight": w}));
    }
}

pub fn addresses_of(n: &Value, out: &mut Vec<String>) {
    let a = terminal_of(n);
    if !a.is_empty() {
        out.push(a.to_string());
    }
    if let Some(ch) = n.get("children").and_then(Value::as_array) {
        for c in ch {
            addresses_of(c, out);
        }
    }
}

fn find_by_addr<'a>(n: &'a Value, addr: &str) -> Option<&'a Value> {
    if addr.is_empty() {
        return None;
    }
    if terminal_of(n) == addr {
        return Some(n);
    }
    for c in n.get("children").and_then(Value::as_array).into_iter().flatten() {
        if let Some(found) = find_by_addr(c, addr) {
            return Some(found);
        }
    }
    None
}

fn has_addr(n: &Value, addr: &str) -> bool {
    find_by_addr(n, addr).is_some()
}

fn path_to_id_or_addr(n: &Value, id_or_addr: &str) -> Option<Vec<usize>> {
    if n.get("id").and_then(Value::as_str) == Some(id_or_addr) || terminal_of(n) == id_or_addr {
        return Some(Vec::new());
    }
    let ch = n.get("children").and_then(Value::as_array)?;
    for (i, c) in ch.iter().enumerate() {
        if let Some(mut rest) = path_to_id_or_addr(c, id_or_addr) {
            let mut p = Vec::with_capacity(rest.len() + 1);
            p.push(i);
            p.append(&mut rest);
            return Some(p);
        }
    }
    None
}

fn at_mut<'a>(root: &'a mut Value, path: &[usize]) -> Option<&'a mut Value> {
    let mut cur = root;
    for &i in path {
        cur = cur.get_mut("children")?.as_array_mut()?.get_mut(i)?;
    }
    Some(cur)
}

fn prefix_path(a: &[usize], b: &[usize]) -> bool {
    a.len() < b.len() && a == &b[..a.len()]
}

pub fn doc_space<'a>(doc: &'a Map<String, Value>, id: &str) -> Option<&'a Map<String, Value>> {
    doc.get("spaces")?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .find(|sp| str_field(sp, "id") == id)
}

pub fn doc_append_space(doc: &mut Map<String, Value>, space: Value) {
    let spaces = doc.entry("spaces").or_insert_with(|| Value::Array(Vec::new()));
    if let Some(arr) = spaces.as_array_mut() {
        arr.push(space);
    }
}

pub fn doc_close_space(doc: &mut Map<String, Value>, id: &str) -> Option<Vec<String>> {
    let spaces = doc.get_mut("spaces")?.as_array_mut()?;
    let idx = spaces.iter().position(|s| s.get("id").and_then(Value::as_str) == Some(id))?;
    let removed = spaces.remove(idx);
    let mut addrs = Vec::new();
    for t in removed.get("tabs").and_then(Value::as_array).into_iter().flatten() {
        if let Some(root) = t.get("root") {
            addresses_of(root, &mut addrs);
        }
    }
    Some(addrs)
}

pub fn doc_rename_space(doc: &mut Map<String, Value>, id: &str, name: &str) -> bool {
    let Some(spaces) = doc.get_mut("spaces").and_then(Value::as_array_mut) else {
        return false;
    };
    for s in spaces {
        if let Some(m) = s.as_object_mut()
            && str_field(m, "id") == id
        {
            m.insert("name".into(), Value::String(name.trim().to_string()));
            return true;
        }
    }
    false
}

pub fn doc_append_tab(doc: &mut Map<String, Value>, space_id: &str, tab: Value, after: &str) -> bool {
    let Some(spaces) = doc.get_mut("spaces").and_then(Value::as_array_mut) else {
        return false;
    };
    for s in spaces {
        let Some(sp) = s.as_object_mut() else { continue };
        if str_field(sp, "id") != space_id {
            continue;
        }
        let tabs = sp.entry("tabs").or_insert_with(|| Value::Array(Vec::new()));
        let Some(arr) = tabs.as_array_mut() else { return false };
        let at = if !after.is_empty() {
            arr.iter()
                .position(|t| t.get("id").and_then(Value::as_str) == Some(after))
                .map_or(arr.len(), |i| i + 1)
        } else {
            arr.len()
        };
        arr.insert(at, tab);
        return true;
    }
    false
}

pub fn doc_close_tab(doc: &mut Map<String, Value>, tab_id: &str) -> Option<(Vec<String>, String)> {
    let mut loc = None;
    if let Some(spaces) = doc.get("spaces").and_then(Value::as_array) {
        'outer: for (si, s) in spaces.iter().enumerate() {
            if let Some(tabs) = s.get("tabs").and_then(Value::as_array) {
                for (ti, t) in tabs.iter().enumerate() {
                    if t.get("id").and_then(Value::as_str) == Some(tab_id) {
                        loc = Some((si, ti, tabs.len(), s.get("id").and_then(Value::as_str).unwrap_or_default().to_string()));
                        break 'outer;
                    }
                }
            }
        }
    }
    let (si, ti, tab_count, sid) = loc?;
    if tab_count == 1 {
        let addrs = doc_close_space(doc, &sid)?;
        return Some((addrs, sid));
    }
    let spaces = doc.get_mut("spaces")?.as_array_mut()?;
    let tabs = spaces[si].get_mut("tabs")?.as_array_mut()?;
    let removed = tabs.remove(ti);
    let mut addrs = Vec::new();
    if let Some(root) = removed.get("root") {
        addresses_of(root, &mut addrs);
    }
    Some((addrs, String::new()))
}

pub fn doc_rename_tab(doc: &mut Map<String, Value>, tab_id: &str, name: &str) -> bool {
    for s in doc.get_mut("spaces").and_then(Value::as_array_mut).into_iter().flatten() {
        for t in s.get_mut("tabs").and_then(Value::as_array_mut).into_iter().flatten() {
            if let Some(tm) = t.as_object_mut()
                && str_field(tm, "id") == tab_id
            {
                tm.insert("name".into(), Value::String(name.trim().to_string()));
                return true;
            }
        }
    }
    false
}

pub fn doc_move_tab(doc: &mut Map<String, Value>, tab_id: &str, to: usize) -> bool {
    for s in doc.get_mut("spaces").and_then(Value::as_array_mut).into_iter().flatten() {
        let Some(tabs) = s.get_mut("tabs").and_then(Value::as_array_mut) else { continue };
        if let Some(from) = tabs.iter().position(|t| t.get("id").and_then(Value::as_str) == Some(tab_id)) {
            let item = tabs.remove(from);
            let idx = to.min(tabs.len());
            tabs.insert(idx, item);
            return true;
        }
    }
    false
}

pub fn doc_move_spaces(doc: &mut Map<String, Value>, ids: &[String], before: &str) -> bool {
    let Some(spaces) = doc.get_mut("spaces").and_then(Value::as_array_mut) else {
        return false;
    };
    let mut seen = std::collections::HashSet::new();
    let mut moved = Vec::new();
    let mut work = spaces.clone();
    for id in ids {
        if !seen.insert(id.as_str()) {
            return false;
        }
        let Some(i) = work.iter().position(|s| s.get("id").and_then(Value::as_str) == Some(id.as_str())) else {
            return false;
        };
        moved.push(work.remove(i));
    }
    if !before.is_empty() && seen.contains(before) {
        return false;
    }
    let at = if before.is_empty() {
        work.len()
    } else {
        let Some(i) = work.iter().position(|s| s.get("id").and_then(Value::as_str) == Some(before)) else {
            return false;
        };
        i
    };
    let mut out = Vec::with_capacity(work.len() + moved.len());
    out.extend(work.drain(..at));
    out.extend(moved);
    out.extend(work);
    *spaces = out;
    true
}

#[allow(clippy::too_many_arguments)]
pub fn doc_split_pane(
    doc: &mut Map<String, Value>,
    target: &str,
    axis: &str,
    new_id: &str,
    addr: &str,
    container_id: &str,
    side: &str,
    ratio: f64,
) -> bool {
    let ratio = if ratio > 0.0 && ratio < 1.0 { ratio } else { 0.5 };
    for s in doc.get_mut("spaces").and_then(Value::as_array_mut).into_iter().flatten() {
        for t in s.get_mut("tabs").and_then(Value::as_array_mut).into_iter().flatten() {
            let Some(root) = t.get_mut("root") else { continue };
            let Some(path) = path_to_id_or_addr(root, target) else { continue };
            let mut new_pane = make_block(new_id, addr);
            if let Some((&idx, parent_path)) = path.split_last()
                && let Some(parent) = at_mut(root, parent_path)
                && axis_of(parent) == axis
                && let Some(ch) = parent.get_mut("children").and_then(Value::as_array_mut)
                && idx < ch.len()
            {
                let share = flex_weight(&ch[idx]);
                let share = if share > 0.0 { share } else { 1.0 };
                let (first, second) = (share * ratio, share * (1.0 - ratio));
                if side == "before" {
                    set_weight(&mut new_pane, first);
                    set_weight(&mut ch[idx], second);
                    ch.insert(idx, new_pane);
                } else {
                    set_weight(&mut ch[idx], first);
                    set_weight(&mut new_pane, second);
                    ch.insert(idx + 1, new_pane);
                }
                return true;
            }
            let Some(slot) = at_mut(root, &path) else { return false };
            let mut old = slot.clone();
            let size = old.as_object_mut().and_then(|m| m.remove("size"));
            let children = if side == "before" {
                set_weight(&mut new_pane, ratio);
                set_weight(&mut old, 1.0 - ratio);
                vec![new_pane, old]
            } else {
                set_weight(&mut old, ratio);
                set_weight(&mut new_pane, 1.0 - ratio);
                vec![old, new_pane]
            };
            let mut wrap = make_container(container_id, axis, children);
            if let Some(sz) = size
                && let Some(m) = wrap.as_object_mut()
            {
                m.insert("size".into(), sz);
            }
            *slot = wrap;
            return true;
        }
    }
    false
}

pub fn doc_close_pane(doc: &mut Map<String, Value>, id_or_addr: &str) -> Option<(Vec<String>, String, String)> {
    let mut found_tab_id = None;
    let mut removed_addrs = Vec::new();
    let mut empty_tab = false;

    'outer: for s in doc.get_mut("spaces").and_then(Value::as_array_mut).into_iter().flatten() {
        for t in s.get_mut("tabs").and_then(Value::as_array_mut).into_iter().flatten() {
            let tid = t.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
            let Some(root) = t.get_mut("root") else { continue };
            let Some(path) = path_to_id_or_addr(root, id_or_addr) else { continue };
            let Some(pid) = at_mut(root, &path).and_then(|n| n.get("id")).and_then(Value::as_str).map(String::from) else {
                continue;
            };
            if let Some(removed) = take_node(root, &pid) {
                collapse(root);
                addresses_of(&removed, &mut removed_addrs);
                empty_tab = visible_pane_count(root) == 0;
                found_tab_id = Some(tid);
                break 'outer;
            }
        }
    }
    let tid = found_tab_id?;
    if empty_tab {
        let (more, closed_space) = doc_close_tab(doc, &tid)?;
        removed_addrs.extend(more);
        return Some((removed_addrs, tid, closed_space));
    }
    Some((removed_addrs, String::new(), String::new()))
}

fn take_node(n: &mut Value, id: &str) -> Option<Value> {
    let is_axis = !axis_of(n).is_empty();
    let ch = n.get_mut("children")?.as_array_mut()?;
    if let Some(i) = ch.iter().position(|c| c.get("id").and_then(Value::as_str) == Some(id)) {
        let child = ch.remove(i);
        let gone = flex_weight(&child);
        if gone > 0.0 && is_axis && !ch.is_empty() {
            let heir = i.min(ch.len() - 1);
            let hw = flex_weight(&ch[heir]);
            if hw > 0.0 || ch[heir].get("size").is_none() {
                set_weight(&mut ch[heir], hw + gone);
            }
        }
        return Some(child);
    }
    for c in ch.iter_mut() {
        if let Some(removed) = take_node(c, id) {
            return Some(removed);
        }
    }
    None
}

fn collapse(n: &mut Value) {
    let stack = node_type(n) == "stack";
    let is_axis = !axis_of(n).is_empty();
    if let Some(ch) = n.get_mut("children").and_then(Value::as_array_mut) {
        for c in ch.iter_mut() {
            collapse(c);
        }
    }
    if stack || !is_axis {
        return;
    }
    let Some(ch) = n.get_mut("children").and_then(Value::as_array_mut) else { return };
    let mut out = Vec::with_capacity(ch.len());
    for mut child in ch.drain(..) {
        if !axis_of(&child).is_empty() {
            let len = child.get("children").and_then(Value::as_array).map_or(0, Vec::len);
            if len == 0 {
                continue;
            }
            if len == 1 {
                let sz = child.as_object_mut().and_then(|m| m.remove("size"));
                let mut only = child["children"][0].clone();
                if let Some(sz) = sz
                    && let Some(m) = only.as_object_mut()
                {
                    m.insert("size".into(), sz);
                }
                out.push(only);
                continue;
            }
        }
        out.push(child);
    }
    *ch = out;
}

fn visible_pane_count(n: &Value) -> usize {
    if is_hidden(n) {
        return 0;
    }
    match node_type(n) {
        "block" => usize::from(!terminal_of(n).is_empty()),
        "stack" => {
            let ch = n.get("children").and_then(Value::as_array);
            let active = n.get("active").and_then(Value::as_str).unwrap_or_default();
            for c in ch.into_iter().flatten() {
                if !is_hidden(c) && (active.is_empty() || c.get("id").and_then(Value::as_str) == Some(active)) {
                    return visible_pane_count(c);
                }
            }
            for c in ch.into_iter().flatten() {
                let cnt = visible_pane_count(c);
                if cnt > 0 {
                    return cnt;
                }
            }
            0
        }
        _ => n
            .get("children")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(visible_pane_count)
            .sum(),
    }
}

pub fn doc_swap_panes(doc: &mut Map<String, Value>, a: &str, b: &str) -> bool {
    for s in doc.get_mut("spaces").and_then(Value::as_array_mut).into_iter().flatten() {
        for t in s.get_mut("tabs").and_then(Value::as_array_mut).into_iter().flatten() {
            let Some(root) = t.get_mut("root") else { continue };
            let (Some(pa), Some(pb)) = (path_to_id_or_addr(root, a), path_to_id_or_addr(root, b)) else {
                continue;
            };
            if pa == pb || prefix_path(&pa, &pb) || prefix_path(&pb, &pa) {
                return false;
            }
            let Some(mut na) = at_mut(root, &pa).cloned() else { return false };
            let Some(mut nb) = at_mut(root, &pb).cloned() else { return false };
            let sa = na.as_object_mut().and_then(|m| m.remove("size"));
            let sb = nb.as_object_mut().and_then(|m| m.remove("size"));
            if let Some(sb) = sb
                && let Some(m) = na.as_object_mut()
            {
                m.insert("size".into(), sb);
            }
            if let Some(sa) = sa
                && let Some(m) = nb.as_object_mut()
            {
                m.insert("size".into(), sa);
            }
            if let Some(slot) = at_mut(root, &pa) {
                *slot = nb;
            }
            if let Some(slot) = at_mut(root, &pb) {
                *slot = na;
            }
            return true;
        }
    }
    false
}

pub fn doc_set_pane_title(doc: &mut Map<String, Value>, id_or_addr: &str, title: &str) -> bool {
    for s in doc.get_mut("spaces").and_then(Value::as_array_mut).into_iter().flatten() {
        for t in s.get_mut("tabs").and_then(Value::as_array_mut).into_iter().flatten() {
            let Some(root) = t.get_mut("root") else { continue };
            let Some(path) = path_to_id_or_addr(root, id_or_addr) else { continue };
            let Some(pane) = at_mut(root, &path).and_then(Value::as_object_mut) else { return false };
            let trimmed = title.trim();
            if trimmed.is_empty() {
                pane.remove("title");
            } else {
                pane.insert("title".into(), Value::String(trimmed.to_string()));
            }
            return true;
        }
    }
    false
}

pub fn doc_set_split_ratio(doc: &mut Map<String, Value>, before: &str, after: &str, axis: &str, ratio: f64) -> bool {
    if !(ratio > 0.0 && ratio < 1.0) {
        return false;
    }
    for s in doc.get_mut("spaces").and_then(Value::as_array_mut).into_iter().flatten() {
        for t in s.get_mut("tabs").and_then(Value::as_array_mut).into_iter().flatten() {
            if let Some(root) = t.get_mut("root")
                && set_ratio_node(root, before, after, axis, ratio)
            {
                return true;
            }
        }
    }
    false
}

fn set_ratio_node(n: &mut Value, before: &str, after: &str, axis: &str, ratio: f64) -> bool {
    let want = if axis == "column" || axis == "down" { "column" } else { "row" };
    if axis_of(n) == want
        && let Some(ch) = n.get_mut("children").and_then(Value::as_array_mut)
    {
        for i in 0..ch.len().saturating_sub(1) {
            if has_addr(&ch[i], before) && has_addr(&ch[i + 1], after) {
                let pair = flex_weight(&ch[i]) + flex_weight(&ch[i + 1]);
                let pair = if pair > 0.0 { pair } else { 1.0 };
                set_weight(&mut ch[i], pair * ratio);
                set_weight(&mut ch[i + 1], pair * (1.0 - ratio));
                return true;
            }
        }
    }
    if let Some(ch) = n.get_mut("children").and_then(Value::as_array_mut) {
        for c in ch.iter_mut() {
            if set_ratio_node(c, before, after, axis, ratio) {
                return true;
            }
        }
    }
    false
}

pub fn infer_home(on: &str, terms: &HashMap<String, TerminalRec>) -> String {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for t in terms.values() {
        if t.cwd.is_empty() {
            continue;
        }
        if on.is_empty() {
            if t.address.contains('/') {
                continue;
            }
        } else if !t.address.starts_with(&format!("{on}/")) {
            continue;
        }
        let cwd = t.cwd.trim_end_matches('/');
        let parts: Vec<&str> = cwd.split('/').collect();
        if parts.len() >= 3 && (parts[1] == "Users" || parts[1] == "home") {
            let h = format!("/{}/{}", parts[1], parts[2]);
            *counts.entry(h).or_default() += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(h, _)| h).unwrap_or_default()
}

pub fn pane_from_term(t: &TerminalRec, tab_id: &str, ws_id: &str) -> Pane {
    let label = t
        .name
        .as_deref()
        .filter(|n| !n.is_empty())
        .unwrap_or(&t.address)
        .to_string();
    let cwd = t.cwd.clone();
    let mut fg_cwd = cwd.clone();
    let mut fg_name = String::new();
    let mut fg_pid = 0;
    let mut fg_argv = Vec::new();
    if let Some(fg) = &t.foreground {
        if !fg.cwd.is_empty() {
            fg_cwd = fg.cwd.clone();
        }
        fg_name = fg.name.clone();
        fg_pid = fg.pid;
        fg_argv = fg.argv.clone();
    }
    let (mut agent, mut app, mut title, mut msg, mut kind) =
        (String::new(), String::new(), String::new(), String::new(), String::new());
    let mut progress = None;
    let mut recs = Vec::new();
    if let Some(st) = &t.status {
        agent = st.state.clone();
        app = st.app.clone();
        title = st.title.clone();
        msg = st.msg.clone();
        if let Some(k) = &st.kind {
            kind = k.clone();
        }
        if let Some(p) = st.progress {
            progress = Some(p as i64);
        }
        recs.push(status_rec("", st));
    }
    let mut ids: Vec<&String> = t.records.keys().collect();
    ids.sort();
    for id in ids {
        recs.push(status_rec(id, &t.records[id]));
    }
    Pane {
        id: t.address.clone(),
        tab_id: tab_id.to_string(),
        workspace_id: ws_id.to_string(),
        focused: false,
        agent_status: agent,
        agent: app.clone(),
        display_agent: app,
        cwd,
        pid: t.pid,
        argv: t.argv.clone(),
        foreground_cwd: fg_cwd,
        foreground_name: fg_name,
        foreground_pid: fg_pid,
        foreground_argv: fg_argv,
        label,
        terminal_title: t.title.clone(),
        status_title: title,
        status_msg: msg,
        status_kind: kind,
        status_progress: progress,
        status_updated_ms: t.status_ms.unwrap_or(0) as i64,
        status_records: recs,
    }
}

fn status_rec(id: &str, s: &TermStatus) -> StatusRec {
    StatusRec {
        id: id.to_string(),
        state: s.state.clone(),
        app: s.app.clone(),
        title: s.title.clone(),
        msg: s.msg.clone(),
        kind: s.kind.clone().unwrap_or_default(),
        progress: s.progress.map(|p| p as i64),
    }
}

pub fn build_from_docs(
    packs: &[DocPack],
    terms: &HashMap<String, TerminalRec>,
    local_home: &str,
    focus: &FocusMaps,
) -> (Snapshot, DocMeta) {
    let mut snap = Snapshot::default();
    let mut meta = DocMeta::default();
    for pack in packs {
        let home = if pack.home.is_empty() { local_home } else { &pack.home };
        if let Some(spaces) = pack.raw.get("spaces").and_then(Value::as_array) {
            for s in spaces {
                if let Some(sp) = s.as_object() {
                    append_space(&mut snap, &mut meta, sp, &pack.on, &pack.label, terms, home, focus);
                }
            }
        }
    }
    if let Some(first) = snap.panes.first() {
        snap.focused_pane_id = first.id.clone();
        for p in &snap.panes {
            if p.focused {
                snap.focused_pane_id = p.id.clone();
                break;
            }
        }
    }
    (snap, meta)
}

#[allow(clippy::too_many_arguments)]
fn append_space(
    snap: &mut Snapshot,
    meta: &mut DocMeta,
    space: &Map<String, Value>,
    on: &str,
    machine: &str,
    terms: &HashMap<String, TerminalRec>,
    home: &str,
    focus: &FocusMaps,
) {
    let sid = str_field(space, "id");
    if sid.is_empty() {
        return;
    }
    let tabs = space.get("tabs").and_then(Value::as_array);
    struct Built {
        tab: Tab,
        panes: Vec<Pane>,
        layout: LayoutNode,
        cells: Vec<LayoutPane>,
        focus: String,
    }
    let mut built_tabs = Vec::new();
    let mut tab_ids = Vec::new();
    for (i, t) in tabs.into_iter().flatten().enumerate() {
        let Some(tab) = t.as_object() else { continue };
        let tid = str_field(tab, "id");
        if tid.is_empty() {
            continue;
        }
        let Some(root) = tab.get("root") else { continue };
        let Some(mut lay) = node_layout(root, on) else { continue };
        let mut ids = Vec::new();
        lay.leaves(&mut ids);
        if ids.is_empty() {
            continue;
        }
        tab_ids.push(tid.to_string());
        let want = focus
            .pane
            .get(tid)
            .filter(|p| ids.iter().any(|x| x == *p))
            .cloned()
            .unwrap_or_else(|| ids[0].clone());
        lay.focused = want.clone();
        lay.zoomed = focus.zoom.get(tid).copied().unwrap_or(false);
        let label = tab_name(tab, i);
        let cells = layout_cells(&lay, terms);
        let mut panes = Vec::with_capacity(ids.len());
        for (j, addr) in ids.iter().enumerate() {
            let mut rec = terms.get(addr).cloned().unwrap_or_default();
            if rec.address.is_empty() {
                rec.address = addr.clone();
            }
            let mut p = pane_from_term(&rec, tid, sid);
            let local = local_addr(addr, on);
            if let Some(title) = find_by_addr(root, &local).and_then(|n| n.get("title")).and_then(Value::as_str)
                && !title.is_empty()
            {
                p.label = title.to_string();
            }
            p.focused = addr == &want;
            if j == 0 && p.cwd.is_empty() {
                p.cwd = str_field(space, "folder").to_string();
            }
            panes.push(p);
        }
        built_tabs.push(Built {
            tab: Tab {
                id: tid.to_string(),
                workspace_id: sid.to_string(),
                label,
                focused: false,
            },
            panes,
            layout: lay,
            cells,
            focus: want,
        });
    }
    if built_tabs.is_empty() {
        return;
    }
    let active = focus
        .tab
        .get(sid)
        .filter(|t| tab_ids.iter().any(|x| x == *t))
        .cloned()
        .unwrap_or_else(|| tab_ids[0].clone());
    meta.space_on.insert(sid.to_string(), on.to_string());
    snap.workspaces.push(Workspace {
        id: sid.to_string(),
        label: session_label(machine, &display_name(space, home)),
        active_tab_id: active.clone(),
        focused: snap.workspaces.is_empty(),
        agent_status: String::new(),
    });
    for mut bt in built_tabs {
        bt.tab.focused = bt.tab.id == active;
        let tid = bt.tab.id.clone();
        let zoomed = bt.layout.zoomed;
        snap.tabs.push(bt.tab);
        snap.panes.extend(bt.panes);
        meta.layouts.insert(tid.clone(), bt.layout);
        snap.layouts.push(TabLayout {
            tab_id: tid,
            workspace_id: sid.to_string(),
            focused_pane_id: bt.focus,
            zoomed,
            panes: bt.cells,
        });
    }
}

fn node_layout(n: &Value, on: &str) -> Option<LayoutNode> {
    if is_hidden(n) {
        return None;
    }
    match node_type(n) {
        "block" => {
            let addr = terminal_of(n);
            if addr.is_empty() {
                return None;
            }
            Some(LayoutNode::pane(qualify(addr, on)))
        }
        "stack" => {
            let ch = n.get("children").and_then(Value::as_array)?;
            let active = n.get("active").and_then(Value::as_str).unwrap_or_default();
            for c in ch {
                if !active.is_empty() && c.get("id").and_then(Value::as_str) != Some(active) {
                    continue;
                }
                if let Some(l) = node_layout(c, on) {
                    return Some(l);
                }
            }
            for c in ch {
                if let Some(l) = node_layout(c, on) {
                    return Some(l);
                }
            }
            None
        }
        "row" | "column" => {
            let dir = if node_type(n) == "column" { "down" } else { "right" };
            let mut nodes = Vec::new();
            for c in n.get("children").and_then(Value::as_array).into_iter().flatten() {
                if let Some(l) = node_layout(c, on) {
                    let w = flex_weight(c);
                    nodes.push((l, if w > 0.0 { w } else { 1.0 }));
                }
            }
            pack_nodes(&nodes, dir)
        }
        _ => None,
    }
}

fn pack_nodes(nodes: &[(LayoutNode, f64)], dir: &str) -> Option<LayoutNode> {
    match nodes.len() {
        0 => None,
        1 => Some(nodes[0].0.clone()),
        _ => {
            let total: f64 = nodes.iter().map(|(_, w)| *w).sum();
            let total = if total > 0.0 { total } else { nodes.len() as f64 };
            Some(LayoutNode {
                kind: "split".into(),
                pane_id: String::new(),
                direction: dir.to_string(),
                ratio: nodes[0].1 / total,
                first: Some(Box::new(nodes[0].0.clone())),
                second: pack_nodes(&nodes[1..], dir).map(Box::new),
                focused: String::new(),
                zoomed: false,
            })
        }
    }
}

fn layout_cells(n: &LayoutNode, terms: &HashMap<String, TerminalRec>) -> Vec<LayoutPane> {
    let (w, h) = measure(n, terms);
    let mut out = Vec::new();
    assign_cells(n, 0, 0, w.max(1), h.max(1), &mut out);
    out
}

fn measure(n: &LayoutNode, terms: &HashMap<String, TerminalRec>) -> (i32, i32) {
    if n.first.is_none() {
        let t = terms.get(&n.pane_id);
        let w = t.map_or(80, |x| if x.cols > 0 { x.cols } else { 80 });
        let h = t.map_or(24, |x| if x.rows > 0 { x.rows } else { 24 });
        return (w, h);
    }
    let (aw, ah) = n.first.as_deref().map_or((0, 0), |c| measure(c, terms));
    let (bw, bh) = n.second.as_deref().map_or((0, 0), |c| measure(c, terms));
    if n.direction == "down" {
        (aw.max(bw), ah + bh)
    } else {
        (aw + bw, ah.max(bh))
    }
}

fn assign_cells(n: &LayoutNode, x: i32, y: i32, w: i32, h: i32, out: &mut Vec<LayoutPane>) {
    if n.first.is_none() {
        out.push(LayoutPane { pane_id: n.pane_id.clone(), rect: Rect { x, y, width: w, height: h } });
        return;
    }
    let r = if n.ratio > 0.0 && n.ratio < 1.0 { n.ratio } else { 0.5 };
    if n.direction == "down" {
        let top = ((h as f64) * r) as i32;
        let top = top.clamp(1, (h - 1).max(1));
        if let Some(f) = &n.first {
            assign_cells(f, x, y, w, top, out);
        }
        if let Some(s) = &n.second {
            assign_cells(s, x, y + top, w, (h - top).max(1), out);
        }
    } else {
        let left = ((w as f64) * r) as i32;
        let left = left.clamp(1, (w - 1).max(1));
        if let Some(f) = &n.first {
            assign_cells(f, x, y, left, h, out);
        }
        if let Some(s) = &n.second {
            assign_cells(s, x + left, y, (w - left).max(1), h, out);
        }
    }
}

/// CAS-edits `herdr-app` on local (`on == ""`) or a remote machine via `call_internal`.
pub async fn edit_app_doc<E, F>(
    core: &Arc<Core>,
    on: &str,
    mut edit: F,
) -> Result<(Map<String, Value>, u64), E>
where
    E: From<RpcError>,
    F: FnMut(&mut Map<String, Value>) -> Result<(), E>,
{
    let mut backoff = Duration::from_millis(25);
    let mut last_err: Option<RpcError> = None;
    for _ in 0..8 {
        let mut get_params = json!({"name": APP_DOC_NAME});
        if !on.is_empty() {
            get_params["on"] = Value::String(on.to_string());
        }
        let d = match call_internal(core, None, "doc.get", get_params).await {
            Ok(v) => v,
            Err(e) if e.kind == "unavailable" => {
                last_err = Some(e);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_millis(250));
                continue;
            }
            Err(e) => return Err(E::from(e)),
        };
        let version = d["version"].as_u64().unwrap_or(0);
        let mut doc = parse_doc(&d["value"]);
        edit(&mut doc)?;
        let mut set_params = json!({
            "name": APP_DOC_NAME,
            "value": Value::Object(doc.clone()),
            "version": version,
        });
        if !on.is_empty() {
            set_params["on"] = Value::String(on.to_string());
        }
        match call_internal(core, None, "doc.set", set_params).await {
            Ok(r) => {
                let new_ver = r["version"].as_u64().unwrap_or(version + 1);
                return Ok((doc, new_ver));
            }
            Err(e) if e.kind == "conflict" || e.kind == "unavailable" => {
                let wait = if e.kind == "conflict" {
                    backoff.min(Duration::from_millis(80))
                } else {
                    backoff
                };
                last_err = Some(e);
                tokio::time::sleep(wait).await;
                backoff = (backoff * 2).min(Duration::from_millis(250));
            }
            Err(e) => return Err(E::from(e)),
        }
    }
    Err(E::from(
        last_err.unwrap_or_else(|| RpcError::new("conflict", "herdr-app: too many doc.set conflicts", "")),
    ))
}
