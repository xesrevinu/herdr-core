//! Embedded Rex host server inside `herdr-core`.
//!
//! When configured via `rex_listen` in `config.toml` or `HERDR_REX_LISTEN`,
//! `herdr-core` directly serves Rex clients (`/api/control`, `/api/data`, `/api/help`)
//! over TCP or Unix socket in the same process with zero IPC hop and bit-for-bit
//! identical UUIDv5 Rex IDs to Go `Herdrex`.

pub mod appdoc;
pub mod bridge;
pub mod hub;
pub mod keymap;
pub mod model;
pub mod ops;
pub mod proto;
pub mod resolve;
pub mod server;
pub mod term;
#[cfg(test)]
mod tests;

use crate::runtime::Core;
use bridge::RexBridge;
use ops::str_arg;
use proto::{RexError, TERMINAL_CREATOR};
use server::{DataServeFn, RexClient, RexServer};
use serde_json::Value;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct RexGuard {
    tasks: Vec<tokio::task::AbortHandle>,
    unix_paths: Vec<PathBuf>,
}

impl Drop for RexGuard {
    fn drop(&mut self) {
        for h in &self.tasks {
            h.abort();
        }
        for p in &self.unix_paths {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn env_bool(name: &str) -> Option<bool> {
    let val = std::env::var(name).ok()?;
    let low = val.trim().to_ascii_lowercase();
    match low.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub(crate) async fn maybe_start(core: Arc<Core>) -> io::Result<Option<RexGuard>> {
    let cfg = crate::config::delivery(&core.paths.config);
    let listen = std::env::var("HERDR_REX_LISTEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or(cfg.rex_listen)
        .unwrap_or_default();
    let specs: Vec<&str> = listen
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if specs.is_empty() {
        return Ok(None);
    }

    let notify = env_bool("HERDR_REX_NOTIFY").or(cfg.rex_notify).unwrap_or(true);
    let observe = env_bool("HERDR_REX_OBSERVE").or(cfg.rex_observe).unwrap_or(false);
    let rex_config = std::env::var("REX_CONFIG")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or(cfg.rex_config)
        .unwrap_or_default();
    let trace = std::env::var("HERDREX_TRACE").is_ok_and(|s| !s.is_empty());

    let srv = RexServer::new(trace);
    let bridge = RexBridge::new(core, srv.clone(), observe, notify, rex_config);
    register_all(&srv, &bridge);

    // Populate initial snapshot and UUIDv5 IDs before accepting Rex traffic.
    bridge.refresh_full().await;

    let mut tasks = bridge.start_background();
    let mut unix_paths = Vec::new();

    for spec in specs {
        if let Some(raw_path) = spec.strip_prefix("unix://").or_else(|| spec.strip_prefix("unix:")) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let path = PathBuf::from(raw_path);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::remove_file(&path);
                let listener = tokio::net::UnixListener::bind(&path)?;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                unix_paths.push(path);
                let s = srv.clone();
                tasks.push(
                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((stream, _)) => {
                                    let srv = s.clone();
                                    tokio::spawn(async move {
                                        srv.serve_stream(stream, None, true).await;
                                    });
                                }
                                Err(e) => {
                                    eprintln!("rex unix accept error: {e}");
                                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                }
                            }
                        }
                    })
                    .abort_handle(),
                );
                eprintln!("core: rex host listening on {spec}");
            }
            #[cfg(not(unix))]
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("rex unix listener unsupported on this platform: {spec}"),
                ));
            }
        } else {
            let listener = TcpListener::bind(spec).await?;
            let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| spec.to_string());
            let s = srv.clone();
            tasks.push(
                tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((stream, addr)) => {
                                let _ = stream.set_nodelay(true);
                                let srv = s.clone();
                                let peer = Some(addr.ip().to_string());
                                tokio::spawn(async move {
                                    srv.serve_stream(stream, peer, false).await;
                                });
                            }
                            Err(e) => {
                                eprintln!("rex tcp accept error: {e}");
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            }
                        }
                    }
                })
                .abort_handle(),
            );
            eprintln!("core: rex host listening on {bound}");
        }
    }

    Ok(Some(RexGuard { tasks, unix_paths }))
}

fn reg<F, Fut>(srv: &RexServer, bridge: &Arc<RexBridge>, name: &str, f: F)
where
    F: Fn(Arc<RexBridge>, Arc<RexClient>, Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Value, RexError>> + Send + 'static,
{
    let b = bridge.clone();
    srv.handle(name, move |c, p| {
        let sid = str_arg(&p, "session_id");
        if !sid.is_empty() {
            c.remember_session(sid);
        }
        f(b.clone(), c, p)
    });
}

fn register_all(srv: &RexServer, b: &Arc<RexBridge>) {
    {
        let bd = b.clone();
        srv.set_on_disconnect(Arc::new(move |c| {
            bd.on_client_disconnect(&c);
        }));
    }
    {
        let bd = b.clone();
        srv.set_data_source(Arc::new(move |_c, req| {
            let bd = bd.clone();
            Box::pin(async move {
                if req.data_ref_id != "terminal" {
                    return Err(RexError::not_found(format!(
                        "block has no data source {}",
                        req.data_ref_id
                    )));
                }
                if !req.session_id.is_empty() {
                    bd.herdr_id(&req.session_id, "session")?;
                }
                let pane = bd.herdr_id(&req.block_id, "block")?;
                let _ = bd.pane(&pane).await?;
                let serve: DataServeFn = Box::new(move |st| {
                    Box::pin(async move {
                        bd.serve_terminal_stream(pane, st).await;
                    })
                });
                Ok(serve)
            })
        }));
    }

    reg(srv, b, "server.status", |b, _, _| async move { ops::h_status(&b).await });
    reg(srv, b, "server.version", |_, _, _| async move { ops::h_version().await });
    reg(srv, b, "server.apple.grant_file_access", |_, c, p| async move {
        ops::h_grant_file_access(&c, &p).await
    });
    reg(srv, b, "session.list", |b, _, _| async move { ops::h_list(&b).await });
    reg(srv, b, "session.view", |b, _, p| async move { ops::h_view(&b, &p).await });
    reg(srv, b, "session.attach", |b, c, p| async move { ops::h_attach(&b, &c, &p).await });
    reg(srv, b, "session.attach_all", |b, c, p| async move { ops::h_attach_all(&b, &c, &p).await });
    reg(srv, b, "session.bootstrap", |b, c, p| async move { ops::h_bootstrap(&b, &c, &p).await });
    reg(srv, b, "session.create", |b, c, p| async move { ops::h_create(&b, &c, &p).await });
    reg(srv, b, "session.destroy", |b, _, p| async move { ops::h_destroy(&b, &p).await });
    reg(srv, b, "session.set_label", |b, _, p| async move { ops::h_set_label(&b, &p).await });
    reg(srv, b, "session.new_window", |b, c, p| async move { ops::h_new_window(&b, &c, &p).await });
    reg(srv, b, "session.close_window", |b, _, p| async move { ops::h_close_window(&b, &p).await });
    reg(srv, b, "session.set_window_label", |b, _, p| async move { ops::h_rename_window(&b, &p).await });
    reg(srv, b, "session.focus_window", |b, _, p| async move { ops::h_focus_window(&b, &p).await });
    reg(srv, b, "session.new_block", |_, _, _| async move {
        Err(RexError::not_supported(
            "herdr-core has no unplaced blocks; use session.new_split or session.new_window",
        ))
    });
    reg(srv, b, "session.detach_block", |_, _, _| async move {
        Err(RexError::not_supported(
            "herdr-core cannot take a pane out of its tab without closing it",
        ))
    });
    reg(srv, b, "session.focus_block", |b, c, p| async move { ops::h_focus_block(&b, &c, &p).await });
    reg(srv, b, "session.new_split", |b, c, p| async move { ops::h_new_split(&b, &c, &p).await });
    reg(srv, b, "session.set_block_label", |b, _, p| async move { ops::h_set_block_label(&b, &p).await });
    reg(srv, b, "session.zoom_block", |b, _, p| async move { ops::h_zoom(&b, &p).await });
    reg(srv, b, "session.swap_blocks", |b, _, p| async move { ops::h_swap(&b, &p).await });
    reg(srv, b, "session.resize_pane", |b, c, p| async move { ops::h_resize_pane(&b, &c, &p).await });
    reg(srv, b, "session.list_blocks", |b, _, p| async move { ops::h_list_blocks(&b, &p).await });
    reg(srv, b, "session.describe_block", |b, _, p| async move { ops::h_describe_block(&b, &p).await });
    reg(srv, b, "block.close", |b, _, p| async move { ops::h_block_close(&b, &p).await });
    reg(srv, b, "session.float_block", |b, c, p| async move { ops::h_float_block(&b, &c, &p).await });
    reg(srv, b, "session.resize_layer", |b, _, p| async move { ops::h_resize_layer(&b, &p).await });
    reg(srv, b, "session.raise_layer", |b, _, p| async move { ops::h_restack_layer(&b, &p, true).await });
    reg(srv, b, "session.lower_layer", |b, _, p| async move { ops::h_restack_layer(&b, &p, false).await });
    reg(srv, b, "session.close_layer", |b, _, p| async move { ops::h_close_layer(&b, &p).await });
    reg(srv, b, "session.new_layer", |b, c, p| async move { ops::h_new_layer(&b, &c, &p).await });
    reg(srv, b, "session.move_block", |b, c, p| async move { ops::h_move_block(&b, &c, &p).await });
    reg(srv, b, "session.set_layer_state", |b, _, p| async move { ops::h_set_layer_state(&b, &p).await });
    reg(srv, b, "block.method", |b, c, p| async move { term::h_block_method(&b, &c, &p).await });
    reg(srv, b, "block.event", |b, c, p| async move { term::h_block_event(&b, &c, &p).await });
    reg(srv, b, "block_creator.list", |b, _, _| async move { ops::h_creators(&b).await });
    reg(srv, b, "target.resolve", |b, c, p| async move { resolve::h_resolve(&b, &c, &p).await });
    reg(srv, b, "target.complete", |b, c, p| async move { resolve::h_complete(&b, &c, &p).await });
    reg(srv, b, "client.key", |b, c, p| async move { term::h_client_key(&b, &c, &p).await });
    reg(srv, b, "session.own_block", |b, c, p| async move { ops::h_own_block(&b, &c, &p).await });
    reg(srv, b, "session.disown_block", |b, c, p| async move { ops::h_disown_block(&b, &c, &p).await });
    reg(srv, b, "hosts.list", |b, c, p| async move { keymap::h_hosts_list(&b, &c, &p).await });
    reg(srv, b, "client.keymap", |b, c, p| async move { keymap::h_keymap(&b, &c, &p).await });
    reg(srv, b, "client.action", |b, c, p| async move { keymap::h_client_action(&b, &c, &p).await });
    reg(srv, b, "server.config_reload", |b, c, p| async move { keymap::h_config_reload(&b, &c, &p).await });
    reg(srv, b, "session.focus_next_pane", |b, _, p| async move { ops::h_focus_pane_step(&b, &p, 1).await });
    reg(srv, b, "session.focus_previous_pane", |b, _, p| async move { ops::h_focus_pane_step(&b, &p, -1).await });
    reg(srv, b, "session.focus_next_window", |b, _, p| async move { ops::h_focus_window_step(&b, &p, 1).await });
    reg(srv, b, "session.focus_previous_window", |b, _, p| async move { ops::h_focus_window_step(&b, &p, -1).await });
    reg(srv, b, "session.focus_direction", |b, _, p| async move { ops::h_focus_direction(&b, &p).await });
    reg(srv, b, "session.move", |b, _, p| async move { ops::h_move(&b, &p).await });
    reg(srv, b, "session.move_window", |b, _, p| async move { ops::h_move_window(&b, &p).await });
    reg(srv, b, "session.list_clients", |b, _, p| async move { ops::h_list_clients(&b, &p).await });
    reg(srv, b, "session.help", |b, _, p| async move { ops::h_session_help(&b, &p).await });

    for &m in term::TERMINAL_METHODS {
        let full = format!("{TERMINAL_CREATOR}.{m}");
        reg(srv, b, &full, move |b, c, p| async move {
            term::h_terminal_method(&b, &c, &p, m).await
        });
    }
}
