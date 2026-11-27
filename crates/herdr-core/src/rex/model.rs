//! Stable UUIDv5 Rex IDs (bit-for-bit identical to Go Herdrex) and Rex View builder.

use super::appdoc::{LayoutNode, Pane, Tab};
use super::proto::{SHELL_FLAVOR, TERMINAL_CREATOR};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use uuid::Uuid;

const TERMINAL_CREATOR_JSON: &str = include_str!("assets/terminal_creator.json");
const NS_STR: &str = "6f1c2f58-8f0e-4c0e-9d57-2d3f1b7a0001";

#[derive(Debug, Clone, Serialize)]
pub struct RexView {
    pub revision: i64,
    pub session_id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_window_id: Option<String>,
    pub windows: Vec<RexWindow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RexWindow {
    pub window_id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focused_block_id: Option<String>,
    pub layers: Vec<RexLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoomed_block_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RexLayer {
    pub layer_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub state: String,
    pub bounds: [f64; 4],
    pub layout: Option<RexNode>,
    pub blocks: Vec<RexBlock>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RexNode {
    pub rect: [f64; 4],
    #[serde(skip_serializing_if = "String::is_empty")]
    pub block_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<Box<RexSplit>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RexSplit {
    pub split_id: String,
    pub direction: String,
    pub ratio: f64,
    pub before: Option<RexNode>,
    pub after: Option<RexNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RexBlock {
    pub block_id: String,
    pub label: String,
    pub creator_name: String,
    pub flavor: String,
    pub host_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub owner: String,
}

#[derive(Debug, Clone)]
pub struct FloatLayer {
    pub layer_id: String,
    pub pane_id: String,
    pub bounds: [f64; 4],
    pub minimized: bool,
}

pub struct Ids {
    pub host_id: String,
    host: Uuid,
    rev: RwLock<HashMap<String, String>>,
}

impl Ids {
    pub fn new(host_path: &str) -> Self {
        let ns = Uuid::parse_str(NS_STR).expect("valid static uuid");
        let host = Uuid::new_v5(&ns, format!("host/{host_path}").as_bytes());
        Self {
            host_id: host.to_string(),
            host,
            rev: RwLock::new(HashMap::new()),
        }
    }

    pub fn rex(&self, kind: &str, herdr_id: &str) -> String {
        let id = format!("{kind}:{}", Uuid::new_v5(&self.host, format!("{kind}/{herdr_id}").as_bytes()));
        self.rev.write().unwrap_or_else(|p| p.into_inner()).insert(id.clone(), herdr_id.to_string());
        id
    }

    pub fn herdr(&self, rex_id: &str) -> Option<String> {
        self.rev.read().unwrap_or_else(|p| p.into_inner()).get(rex_id).cloned()
    }

    pub fn split_id(&self, tab: &str, path: &[bool]) -> String {
        let mut s = format!("{tab}/");
        for &second in path {
            s.push(if second { '1' } else { '0' });
        }
        self.rex("split", &s)
    }

    pub fn creator_info(&self) -> Value {
        let mut v: Value = serde_json::from_str(TERMINAL_CREATOR_JSON).expect("valid terminal_creator.json");
        if let Some(m) = v.as_object_mut() {
            m.insert("host_id".into(), Value::String(self.host_id.clone()));
        }
        v
    }

    pub fn block(&self, p: &Pane) -> RexBlock {
        RexBlock {
            block_id: self.rex("block", &p.id),
            label: pane_label(p),
            creator_name: TERMINAL_CREATOR.into(),
            flavor: SHELL_FLAVOR.into(),
            host_id: self.host_id.clone(),
            owner: String::new(),
        }
    }

    pub fn window(&self, t: &Tab, panes: &[Pane], l: &LayoutNode, floats: &[FloatLayer]) -> RexWindow {
        let floating: HashSet<&str> = floats.iter().map(|f| f.pane_id.as_str()).collect();
        let mut blocks = Vec::new();
        let mut by_pane = HashMap::new();
        for p in panes {
            if p.tab_id != t.id {
                continue;
            }
            let blk = self.block(p);
            by_pane.insert(p.id.as_str(), blk.clone());
            if !floating.contains(p.id.as_str()) {
                blocks.push(blk);
            }
        }
        let mut layers = vec![RexLayer {
            layer_id: self.rex("layer", &t.id),
            kind: "tiled".into(),
            state: String::new(),
            bounds: [0.0, 0.0, 1.0, 1.0],
            layout: self.build_node(l, [0.0, 0.0, 1.0, 1.0], &format!("{}/", t.id), &floating),
            blocks,
        }];
        for f in floats {
            let Some(blk) = by_pane.get(f.pane_id.as_str()).cloned() else {
                continue;
            };
            layers.push(RexLayer {
                layer_id: f.layer_id.clone(),
                kind: "floating".into(),
                state: if f.minimized { "minimized".into() } else { String::new() },
                bounds: f.bounds,
                layout: Some(RexNode { rect: f.bounds, block_id: blk.block_id.clone(), split: None }),
                blocks: vec![blk],
            });
        }
        let (focused_block_id, zoomed_block_id) = if !l.focused.is_empty() {
            let f = self.rex("block", &l.focused);
            let z = if l.zoomed { Some(f.clone()) } else { None };
            (Some(f), z)
        } else {
            (None, None)
        };
        RexWindow {
            window_id: self.rex("window", &t.id),
            label: t.label.clone(),
            focused_block_id,
            layers,
            zoomed_block_id,
        }
    }

    fn build_node(&self, n: &LayoutNode, r: [f64; 4], path: &str, floating: &HashSet<&str>) -> Option<RexNode> {
        if node_hidden(n, floating) {
            return None;
        }
        if n.kind == "pane" || n.first.is_none() {
            return Some(RexNode { rect: r, block_id: self.rex("block", &n.pane_id), split: None });
        }
        let first = n.first.as_deref()?;
        let second = n.second.as_deref()?;
        if node_hidden(first, floating) {
            return self.build_node(second, r, &format!("{path}1"), floating);
        }
        if node_hidden(second, floating) {
            return self.build_node(first, r, &format!("{path}0"), floating);
        }
        let [x, y, w, h] = r;
        let (dir, r1, r2) = if n.direction == "right" {
            (
                "horizontal",
                [x, y, w * n.ratio, h],
                [x + w * n.ratio, y, w * (1.0 - n.ratio), h],
            )
        } else {
            (
                "vertical",
                [x, y, w, h * n.ratio],
                [x, y + h * n.ratio, w, h * (1.0 - n.ratio)],
            )
        };
        Some(RexNode {
            rect: r,
            block_id: String::new(),
            split: Some(Box::new(RexSplit {
                split_id: self.rex("split", path),
                direction: dir.into(),
                ratio: n.ratio,
                before: self.build_node(first, r1, &format!("{path}0"), floating),
                after: self.build_node(second, r2, &format!("{path}1"), floating),
            })),
        })
    }
}

fn node_hidden(n: &LayoutNode, floating: &HashSet<&str>) -> bool {
    if n.kind == "pane" || n.first.is_none() {
        return floating.contains(n.pane_id.as_str());
    }
    n.first.as_deref().is_none_or(|f| node_hidden(f, floating))
        && n.second.as_deref().is_none_or(|s| node_hidden(s, floating))
}

pub fn pane_label(p: &Pane) -> String {
    if !p.label.is_empty() {
        return p.label.clone();
    }
    if !p.terminal_title.is_empty() {
        return p.terminal_title.clone();
    }
    p.id.clone()
}
