//! The method table: every method's description, errors and handler. Its
//! params and results are in `api/types.rs`; `run` and the waits have their
//! own files.

use crate::holder_proto as proto;
use crate::rpc::{RpcError, methods};
use crate::runtime::{Core, now_ms};
use crate::terminals::{NewTerminal, Public, Terminal};
use crate::wait::{WaitResult, WaitSpec};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

pub const GENERATION: u32 = 1;
pub const FEATURES: &[&str] = &[
    "framed",
    "attach",
    "events",
    "status",
    "shell",
    "resize_notifications",
    "automatic_input",
    "restart_environment",
    "put_chunks",
];
pub const FINISHED_LINES: usize = 1000;
/// Terminal identity variables replaced by the core's defaults unless explicitly overridden.
pub const IDENTITY_VARS: &[&str] = &["TERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION", "COLORTERM"];

mod doc;
mod put;
mod run;
mod types;
use doc::*;
use put::*;
pub use put::{begin_read, forget_puts};
mod waiting;
use run::*;
pub(crate) use run::{child_env, not_stopping, tail, terminal_env};
pub use types::*;
use waiting::*;

/// The whole API as an OpenRPC document, generated from the method table.
pub fn openrpc() -> serde_json::Value {
    let (methods, defs) = discover();
    crate::rpc::openrpc(methods, defs, &version(), GENERATION)
}

/// One call: the core plus the connection it came on.
pub struct Call<'a> {
    pub core: &'a Arc<Core>,
    /// The framed connection, if any.
    pub conn: Option<&'a Arc<crate::wire::Conn>>,
    /// Where a plain connection receives its subscription.
    pub plain: Option<&'a std::sync::Mutex<Option<PlainSub>>>,
}

impl std::ops::Deref for Call<'_> {
    type Target = Arc<Core>;
    fn deref(&self) -> &Arc<Core> {
        self.core
    }
}

type Ctx<'a> = &'a Call<'a>;

methods! { Ctx<'_>;
    "hello" => hello, HelloParams => HelloResult,
        "Handshake: protocol generation, core identity, methods and features. `framed: true` switches the connection to framed mode.",
        errors ["unsupported_generation"];
    "server.status" => server_status, Empty => StatusResult,
        "This core's identity, version, pid, uptime, holder and terminal counts.",
        errors [];
    "server.stop" => server_stop, Empty => StopResult,
        "Stop the core and its programs. Kept terminals remain pending and get new shells when the core next starts.",
        errors [];
    "server.restart" => server_restart, RestartParams => StopResult,
        "Planned restart (e.g. after an update): screens are saved, programs keep running, the next core adopts them.",
        errors ["invalid_params"];
    "terminal.run" => terminal_run, RunParams => RunResult,
        "Start a program in a new terminal; or, when argv[0] names a template, start its command and send its body plus the rest of argv as the first message once the agent is ready. Returns once it runs (and the first message is sent or not).",
        errors ["invalid_params", "name_taken", "spawn_failed", "unavailable", "invalid_template", "not_found", "machine_unknown", "config"];
    "templates.list" => templates_list, Empty => TemplatesResult,
        "Templates by name and description, so you can pick a role without knowing its command.",
        errors [];
    "terminal.list" => terminal_list, ListParams => ListResult,
        "Live terminals (all with `all`), optionally filtered by labels.",
        errors [];
    "terminal.get" => terminal_get, TerminalParams => Public,
        "One terminal's facts, live or finished.",
        errors ["not_found", "machine_unknown"];
    "terminal.kill" => terminal_kill, TerminalParams => Public,
        "End the program: hangup, then terminate, then kill. Returns the observed result.",
        errors ["not_found", "machine_unknown", "unavailable"];
    "terminal.rm" => terminal_rm, TerminalParams => RemoveResult,
        "Remove a finished terminal.",
        errors ["not_found", "machine_unknown", "live", "unavailable"];
    "terminal.keep" => terminal_keep, KeepParams => Public,
        "Set whether a live terminal restarts as a shell after loss, including death by signal without an exit code. Exit with a code and explicit kill close it. Recovery runs on every OS after a grace delay, except while the core stops/restarts or Windows reports session shutdown. Streams end on loss; reattach after restarted.", errors ["not_found", "invalid_params", "unavailable"];
    "terminal.label" => terminal_label, LabelParams => Public,
        "Set or remove labels (free-form `key=value`, never interpreted).",
        errors ["not_found", "machine_unknown", "invalid_params", "unavailable"];
    "terminal.read" => terminal_read, ReadParams => ReadResult,
        "The screen plus `lines` of history as text, live or finished.",
        errors ["not_found", "machine_unknown"];
    "terminal.paint" => terminal_paint, PaintParams => PaintResult,
        "VT sequences that repaint the screen and `history` scrollback lines on a fresh viewer, with styles and the cursor. Soft wraps stay as display rows.",
        errors ["not_found", "machine_unknown"];
    "terminal.clear" => terminal_clear, TerminalParams => ClearResult,
        "Clear the host emulator's screen and scrollback. Does not write to the program's PTY.",
        errors ["not_found", "machine_unknown"];
    "terminal.scroll" => terminal_scroll, ScrollParams => ScrollResult,
        "Get or set how far the view sits above the live bottom. Omit offset_from_bottom to read it. The view is a window over stored scrollback; it does not send keys to a full-screen app.",
        errors ["not_found", "machine_unknown"];
    "terminal.unscroll" => terminal_unscroll, TerminalParams => ScrollResult,
        "Move the view to the live bottom (offset_from_bottom 0). Same result as terminal.scroll.",
        errors ["not_found", "machine_unknown"];
    "terminal.selection_read" => terminal_selection_read, SelectionReadParams => SelectionReadResult,
        "The plain text of an inclusive cell range. Rows are absolute: 0 is the oldest scrollback line, and the live screen starts at the max_offset_from_bottom from terminal.scroll.",
        errors ["not_found", "machine_unknown"];
    "terminal.attach" => terminal_attach, AttachParams => AttachResult,
        "Open a raw stream to a live terminal on this framed connection (see `hello` with `framed`). Loss ends the stream even when kept; reattach after the restarted event.",
        errors ["not_found", "machine_unknown", "finished", "unavailable", "needs_framed"];
    "terminal.send" => terminal_send, SendParams => SendResult,
        "Paste text and press Enter after a person sends or clears their draft (at most 60 s since their last key), otherwise after ~3 s of quiet. Keys pressed during delivery are held, then delivered. Refuses a blocked program unless `force`.",
        errors ["not_found", "machine_unknown", "finished", "unavailable", "blocked", "status_mismatch", "invalid_params", "config", "cancelled"];
    "terminal.wait" => terminal_wait, WaitParams => crate::wait::WaitResult,
        "Wait until the program is not working (any word but working, or it exited/was lost); already not working returns at once. A program that never reported status is working until it exits. After a send from the same caller, waits for the turn that send started. A message to the caller also ends it: ended false, reason message, from = sender. A timeout is a check-in: ended false, current status.",
        errors ["not_found", "machine_unknown", "invalid_params", "needs_target", "config", "unavailable"];
    "terminal.keys" => terminal_keys, KeysParams => KeysResult,
        "Press named keys, encoded for the program's current keyboard modes, after ~3 s of quiet. Does not wait for an unsent draft.",
        errors ["not_found", "machine_unknown", "finished", "unavailable", "invalid_params"];
    "terminal.interrupt" => terminal_interrupt, InterruptParams => InterruptResult,
        "Press the stop key (esc if it reports status, else ctrl+c), then report what was observed. Never escalates.",
        errors ["not_found", "machine_unknown", "finished", "unavailable", "invalid_params"];
    "terminal.put" => terminal_put, PutParams => PutResult,
        "Write bytes to a file beside a live terminal, on its machine, for its program to read (a pasted image). Lands in a folder of its own, removed with the terminal; the name is kept (a suffix when taken). On a direct route with chunk support, the timeout applies to each piece. A core sending the whole file to a relay applies its machine timeout to that call. Types nothing: paste the path yourself.",
        errors ["not_found", "machine_unknown", "finished", "invalid_params", "unavailable", "internal"];
    "terminal.put_begin" => terminal_put_begin, PutBeginParams => PutBeginResult,
        "Between cores: begin a put that comes in pieces, so a big file never holds up a line. The file appears only once finished.",
        errors ["not_found", "finished", "invalid_params", "unavailable", "internal", "needs_framed"];
    "terminal.put_chunk" => terminal_put_chunk, PutPieceParams => PutPieceResult,
        "Between cores: the next piece of a put, at exactly the offset received so far. Answers once written.",
        errors ["not_found", "finished", "invalid_params", "internal", "needs_framed"];
    "terminal.put_finish" => terminal_put_finish, PutTransferParams => PutResult,
        "Between cores: the put is whole: the file lands as terminal.put lands it, never replacing another.",
        errors ["not_found", "finished", "invalid_params", "internal", "needs_framed"];
    "terminal.put_abort" => terminal_put_abort, PutTransferParams => Empty,
        "Between cores: give up a put; what came is removed. Also happens when its connection or terminal goes.",
        errors ["invalid_params", "unavailable", "needs_framed"];
    "machine.exec" => machine_exec, ExecParams => ExecResult,
        "Run one program here or on a machine (`on`) without a terminal; return its exit code and exactly what it wrote (base64). `argv` runs as given, `line` in that machine's shell. Everything it started ends with it: at its exit, at `timeout` (default 60 s), or when the caller goes away. A nonzero exit or a timeout is a result, not an error.",
        errors ["invalid_params", "spawn_failed", "machine_unknown", "unavailable", "needs_update"];
    "file.read" => file_read, FileReadParams => FileReadResult,
        "Read a text file here or on a machine (`on`): lines from `offset`, at most `limit` and 8 MB, and how many it has.",
        errors ["invalid_params", "not_found", "not_text", "io", "machine_unknown", "unavailable", "needs_update"];
    "file.write" => file_write, FileWriteParams => FileResult,
        "Write a file here or on a machine (`on`), making missing folders. Swapped in whole: a reader sees old or new, never half. An existing file keeps its mode; a symlink is followed.",
        errors ["invalid_params", "io", "machine_unknown", "unavailable", "needs_update"];
    "file.edit" => file_edit, FileEditParams => FileResult,
        "Edit a text file here or on a machine (`on`): each `old` must be found exactly once in the file as it was, edits must not overlap; all are made or none. Written like file.write.",
        errors ["invalid_params", "edit_failed", "not_found", "not_text", "io", "machine_unknown", "unavailable", "needs_update"];
    "doc.get" => doc_get, DocGetParams => DocGetResult,
        "Read an opaque JSON document and its version (zero when never written). Optional on selects another machine.",
        errors ["invalid_params", "machine_unknown", "unavailable", "needs_update"];
    "doc.set" => doc_set, DocSetParams => DocSetResult,
        "Write an opaque JSON document (at most 1 MiB) if its version still matches. Null deletes the value but retains its version. Persists atomically and emits a doc event.",
        errors ["invalid_params", "conflict", "internal", "machine_unknown", "unavailable", "needs_update"];
    "events.subscribe" => events_subscribe, SubscribeParams => SubscribeResult,
        "Snapshot of matching terminals, then every matching fact change in order (created, lost, restarted, keep, finished, removed, status, turn, title, labels, size, doc) as `event` notifications, `heartbeat` every 15 s, and `missed` + fresh snapshot for a subscriber that fell behind. Document-only subscriptions receive empty terminal snapshots.",
        errors ["not_found", "machine_unknown"];
    "machine.add" => machine_add, MachineAddParams => crate::machines::Machine,
        "Add another machine: dial it over ssh, check that hc answers there, and keep it under a name.",
        errors ["invalid_params", "name_taken", "already_added", "unreachable", "hc_missing", "incompatible"];
    "machine.list" => machine_list, Empty => MachineListResult,
        "The machines this core has added.",
        errors [];
    "machine.connect" => machine_connect, MachineParams => crate::remote::MachineView,
        "Dial a machine now instead of at its next retry (after a login), and report its line.",
        errors ["machine_unknown"];
    "machine.rename" => machine_rename, MachineRenameParams => crate::machines::Machine,
        "Give a machine a new name here. Only this core's name for it changes.",
        errors ["invalid_params", "name_taken", "machine_unknown"];
    "machine.rm" => machine_rm, MachineParams => RemoveResult,
        "Forget a machine. Its terminals keep running there.",
        errors ["machine_unknown"];
    "rpc.discover" => rpc_discover, Empty => serde_json::Value,
        "The whole API as an OpenRPC document: every method with its params, result and errors in JSON Schema.",
        errors [];
}

fn version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

fn resolve(core: &Core, address: &str) -> Result<u32, RpcError> {
    let local = crate::addr::local(address, &core.info.id, &core.info.name)?;
    core.lock().reg.resolve(local)
}

fn record(core: &Core, id: u32) -> Result<Terminal, RpcError> {
    core.lock().reg.terminals.get(&id).cloned().ok_or_else(|| {
        RpcError::new("not_found", format!("{} was removed", crate::terminals::address(id)), "see `hc ls --all`")
    })
}

async fn hello(core: Ctx<'_>, p: HelloParams) -> Result<HelloResult, RpcError> {
    if let Some(g) = p.generation.filter(|g| *g != GENERATION) {
        return Err(RpcError::new(
            "unsupported_generation",
            format!("protocol generation {g} not supported"),
            format!("this core speaks generation {GENERATION}"),
        ));
    }
    let (keeps_running_after_logout, logout_linger_user) = crate::platform::logout_linger();
    Ok(HelloResult {
        generation: GENERATION,
        version: version(),
        core: core.info.clone(),
        framed: p.framed,
        methods: METHOD_NAMES.iter().map(|m| m.to_string()).collect(),
        features: FEATURES.iter().map(|f| f.to_string()).collect(),
        login_session: core.login_session,
        keeps_running_after_logout,
        logout_linger_user,
    })
}

async fn server_status(core: Ctx<'_>, _: Empty) -> Result<StatusResult, RpcError> {
    let (keeps_running_after_logout, logout_linger_user) = crate::platform::logout_linger();
    let st = core.lock();
    let live = st.reg.terminals.values().filter(|t| t.is_live()).count();
    let holders: Vec<HolderInfo> = st
        .holders
        .iter()
        .map(|l| HolderInfo {
            pid: l.pid,
            instance: l.instance.clone(),
            current: l.current,
            terminals: st
                .reg
                .terminals
                .values()
                .filter(|t| t.is_live() && t.holder.as_ref() == Some(&l.instance))
                .count(),
        })
        .collect();
    Ok(StatusResult {
        core: core.info.clone(),
        version: version(),
        pid: std::process::id(),
        uptime_ms: core.started.elapsed().as_millis() as u64,
        holder: holders.iter().find(|h| h.current).cloned(),
        holders,
        live,
        finished: st.reg.terminals.len() - live,
        installed_by: crate::client::installed_by().map(String::from),
        keeps_running_after_logout,
        logout_linger_user,
    })
}

async fn server_stop(core: Ctx<'_>, _: Empty) -> Result<StopResult, RpcError> {
    if core.restart.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(RpcError::new("unavailable", "the core is restarting", "run it again once it has restarted"));
    }
    crate::restart::discard(&core.paths);
    if let Err(e) = core.shutdown().await {
        let _ = writeln!(io::stderr(), "core: shutdown registry flush failed: {}", e.message);
    }
    Ok(StopResult { stopped: true })
}

async fn server_restart(core: Ctx<'_>, p: RestartParams) -> Result<StopResult, RpcError> {
    crate::restart::prepare(core, p.environment).map_err(|e| {
        if e.kind() == std::io::ErrorKind::InvalidInput {
            RpcError::invalid_params(e.to_string())
        } else {
            RpcError::internal(e.to_string())
        }
    })?;
    Ok(StopResult { stopped: true })
}

async fn templates_list(core: Ctx<'_>, _: Empty) -> Result<TemplatesResult, RpcError> {
    Ok(TemplatesResult { templates: crate::templates::list(&core.paths) })
}

async fn terminal_list(core: Ctx<'_>, p: ListParams) -> Result<ListResult, RpcError> {
    // Asked from another machine: only ours. Two machines that added each
    // other would otherwise ask each other back until the timeout.
    let afar = from_afar(core);
    let (mut terminals, mut hidden_finished, machines) = {
        let mut st = core.lock();
        core.prune(&mut st);
        let matching: Vec<&Terminal> = st
            .reg
            .terminals
            .values()
            .filter(|t| p.labels.iter().all(|Label(k, v)| t.labels.get(k) == Some(v)))
            .collect();
        let hidden = if p.all { 0 } else { matching.iter().filter(|t| !t.is_live()).count() };
        let terminals: Vec<serde_json::Value> =
            matching.into_iter().filter(|t| p.all || t.is_live()).cloned().map(|t| json!(Public(t))).collect();
        let machines = if afar { Vec::new() } else { st.machines.clone() };
        (terminals, hidden, machines)
    };
    // Each machine at once, each given a moment: a slow one never holds up the list.
    let asks: Vec<_> = machines
        .iter()
        .map(|m| {
            let (core, m, params) = (core.core.clone(), m.clone(), serde_json::to_value(&p).unwrap_or_default());
            tokio::spawn(async move {
                let ask = crate::remote::forward(&core, &m, "terminal.list", params);
                tokio::time::timeout(Duration::from_secs(3), ask).await.ok().and_then(Result::ok)
            })
        })
        .collect();
    for ask in asks {
        if let Ok(Some(r)) = ask.await {
            terminals.extend(r["terminals"].as_array().cloned().unwrap_or_default());
            hidden_finished += r["hidden_finished"].as_u64().unwrap_or(0) as usize;
        }
    }
    let machines = {
        let st = core.lock();
        machines.iter().map(|m| crate::remote::view(&st, m)).collect()
    };
    core.flush_observed().await?;
    Ok(ListResult { terminals, hidden_finished, machines })
}

async fn terminal_get(core: Ctx<'_>, p: TerminalParams) -> Result<Public, RpcError> {
    let id = resolve(core, &p.terminal)?;
    core.saw(p.caller.as_deref(), id);
    let result = record(core, id).map(Public);
    core.flush_observed().await?;
    result
}

async fn terminal_kill(core: Ctx<'_>, p: TerminalParams) -> Result<Public, RpcError> {
    let id = resolve(core, &p.terminal)?;
    if core.lock().reg.terminals.get(&id).is_some_and(|t| t.is_live()) {
        core.lock().killing.insert(id);
        core.kill(&[id]).await;
    }
    core.saw(p.caller.as_deref(), id); // covers the exit it caused
    let result = record(core, id).map(Public);
    core.flush_saved().await?;
    result
}

async fn terminal_rm(core: Ctx<'_>, p: TerminalParams) -> Result<RemoveResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    {
        let mut st = core.lock();
        if st.reg.terminals.get(&id).is_some_and(|t| t.is_live()) {
            return Err(RpcError::new(
                "live",
                format!("{} is still running", crate::terminals::address(id)),
                format!("kill it first: hc kill {}", crate::terminals::address(id)),
            ));
        }
        core.remove(&mut st, id);
    }
    core.flush_saved().await?;
    Ok(RemoveResult { removed: crate::terminals::address(id) })
}

async fn terminal_keep(core: Ctx<'_>, p: KeepParams) -> Result<Public, RpcError> {
    let id = resolve(core, &p.terminal)?;
    {
        let mut st = core.lock();
        let t = st.reg.terminals.get_mut(&id).expect("resolved");
        if !t.is_live() {
            return Err(RpcError::invalid_params("only live terminals can be kept"));
        }
        t.keep = p.keep;
        let lost = (!p.keep && t.holder.is_none()).then(|| t.reason.clone().unwrap_or_else(|| "holder_lost".into()));
        core.emit(&mut st, "keep", id, json!({"keep": p.keep}));
        if let Some(reason) = lost {
            core.record_finish(&mut st, id, proto::Exit { code: None, signal: None }, &reason);
            core.changed.notify_waiters();
        }
        core.save(&st);
    }
    let result = record(core, id).map(Public);
    core.flush_saved().await?;
    result
}

async fn terminal_label(core: Ctx<'_>, p: LabelParams) -> Result<Public, RpcError> {
    let id = resolve(core, &p.terminal)?;
    {
        let mut st = core.lock();
        let was = st.reg.terminals.get(&id).cloned();
        st.reg.label(id, &labels(&p.labels))?;
        core.save(&st);
        let labels = serde_json::to_value(&st.reg.terminals[&id].labels).unwrap_or_default();
        core.emit_from(&mut st, "labels", id, json!({"labels": labels}), was.as_ref());
    }
    let result = record(core, id).map(Public);
    core.flush_saved().await?;
    result
}

async fn terminal_read(core: Ctx<'_>, p: ReadParams) -> Result<ReadResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    core.saw(p.caller.as_deref(), id);
    // A full-screen app keeps its history to itself: scroll it to read it.
    let full_screen = core.lock().screens.get(&id).is_some_and(|s| s.alt_screen());
    if full_screen && p.lines > 0 {
        let lines = p.lines.min(FINISHED_LINES);
        let result = match core.stitch(id, lines).await {
            Some((text, complete)) => ReadResult { text, complete, how: "stitched".into(), why: None },
            None => {
                let st = core.lock();
                let text = st.screens.get(&id).map(|s| crate::stitch::text(&s.screen_rows())).unwrap_or_default();
                let why = st
                    .reg
                    .terminals
                    .get(&id)
                    .and_then(|t| t.status.as_ref())
                    .filter(|s| matches!(s.state.as_str(), "working" | "blocked" | "error"))
                    .map(|s| s.state.clone());
                ReadResult { text, complete: false, how: "screen".into(), why }
            }
        };
        core.flush_observed().await?;
        return Ok(result);
    }
    let result = {
        let st = core.lock();
        let t = st.reg.terminals.get(&id).expect("resolved");
        let lines = if t.is_live() { p.lines } else { p.lines.min(FINISHED_LINES) };
        let rows = t.rows as usize;
        let exact = t.screen == "exact";
        let text = core.screen_text(&st, id);
        let mut complete = exact && text.is_some();
        let text = text.unwrap_or_default();
        let all: Vec<&str> = text.trim_end_matches('\n').lines().collect();
        let start = all.len().saturating_sub(rows + lines);
        // Asked for more than is kept, and more was printed than is kept: some is gone.
        let kept = all.len().saturating_sub(rows).min(lines);
        if p.lines > kept && t.printed > (kept + rows) as u64 {
            complete = false;
        }
        if p.lines > 0 && !t.is_live() && t.full_screen {
            complete = false;
        }
        ReadResult {
            text: all[start..].join("\n"),
            complete,
            how: if p.lines == 0 { "screen" } else { "history" }.into(),
            why: None,
        }
    };

    core.flush_observed().await?;
    Ok(result)
}

async fn terminal_paint(core: Ctx<'_>, p: PaintParams) -> Result<PaintResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    core.saw(p.caller.as_deref(), id);
    let result = {
        let st = core.lock();
        match core.screen_paint(&st, id, p.history) {
            Some((vt, cols, rows)) => PaintResult { vt: String::from_utf8_lossy(&vt).into_owned(), cols, rows },
            None => PaintResult { vt: String::new(), cols: 80, rows: 24 },
        }
    };
    core.flush_observed().await?;
    Ok(result)
}

async fn terminal_clear(core: Ctx<'_>, p: TerminalParams) -> Result<ClearResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    core.saw(p.caller.as_deref(), id);
    let ok = {
        let mut st = core.lock();
        core.screen_clear(&mut st, id)
    };
    core.flush_observed().await?;
    Ok(ClearResult { ok })
}

fn scroll_state(st: &crate::runtime::State, id: u32) -> ScrollResult {
    let hist = st.screens.get(&id).map(|s| s.history_rows()).unwrap_or(0);
    let offset = st.scroll.get(&id).copied().unwrap_or(0).min(hist);
    ScrollResult { offset_from_bottom: offset, max_offset_from_bottom: hist, view_top: hist.saturating_sub(offset) }
}

fn set_scroll(st: &mut crate::runtime::State, id: u32, offset: u32) -> ScrollResult {
    let hist = st.screens.get(&id).map(|s| s.history_rows()).unwrap_or(0);
    let offset = offset.min(hist);
    if offset == 0 {
        st.scroll.remove(&id);
    } else {
        st.scroll.insert(id, offset);
    }
    scroll_state(st, id)
}

/// Display cell width of a character (0 / 1 / 2). Combining marks and
/// format characters are 0; East Asian wide/fullwidth and most emoji are 2.
fn cell_cols(c: char) -> usize {
    match c {
        '\0' | '\u{7f}'..='\u{9f}' => 0,
        c if (c as u32) < 0x20 => 0,
        c if (c as u32) < 0x7f => 1,
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' => 0,
        '\u{fe00}'..='\u{fe0f}' => 0,
        '\u{e0100}'..='\u{e01ef}' => 0,
        c if unicode_zero_width(c) => 0,
        c if unicode_wide(c) => 2,
        _ => 1,
    }
}

fn unicode_zero_width(c: char) -> bool {
    matches!(c, '\u{0300}'..='\u{036f}' | '\u{0483}'..='\u{0489}' | '\u{07a6}'..='\u{07b0}' | '\u{135d}'..='\u{135f}' | '\u{1ab0}'..='\u{1ace}' | '\u{1dc0}'..='\u{1dff}' | '\u{20d0}'..='\u{20f0}' | '\u{2cef}'..='\u{2cf1}' | '\u{2d7f}' | '\u{2de0}'..='\u{2dff}' | '\u{302a}'..='\u{302f}' | '\u{3099}' | '\u{309a}' | '\u{a66f}'..='\u{a672}' | '\u{a674}'..='\u{a67d}' | '\u{a69e}' | '\u{a69f}' | '\u{a6f0}' | '\u{a6f1}' | '\u{a8e0}'..='\u{a8f1}' | '\u{fe20}'..='\u{fe2f}')
        || matches!(c as u32, 0x1160..=0x11ff) // Hangul jamo medial/final
}

fn unicode_wide(c: char) -> bool {
    matches!(c as u32,
        0x1100..=0x115F
            | 0x2329
            | 0x232A
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
    )
}

fn crop_line_cells(line: &str, start_col: usize, end_col: usize) -> String {
    if end_col < start_col {
        return String::new();
    }
    let mut out = String::new();
    let mut col = 0usize;
    let mut included = false;
    for ch in line.chars() {
        let w = cell_cols(ch);
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
        col = col.saturating_add(w);
    }
    out
}

/// Crop an inclusive cell range from a terminal.read-style dump (row 0 is the first line).
/// Columns are display cells, not grapheme or UTF-8 indices. A wide character is
/// included if any of its cells is in the range.
fn crop_text(text: &str, start_row: u32, start_col: u32, end_row: u32, end_col: u32) -> String {
    let mut lines: Vec<&str> = text.trim_end_matches('\n').lines().collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let (mut fr, mut fc, mut tr, mut tc) = (start_row as usize, start_col as usize, end_row as usize, end_col as usize);
    if (tr, tc) < (fr, fc) {
        (fr, fc, tr, tc) = (tr, tc, fr, fc);
    }
    let mut out = String::new();
    for r in fr..=tr {
        if r >= lines.len() {
            break;
        }
        let start = if r == fr { fc } else { 0 };
        let end = if r == tr { tc } else { usize::MAX / 2 };
        if r > fr {
            out.push('\n');
        }
        out.push_str(&crop_line_cells(lines[r], start, end));
    }
    out
}

async fn terminal_scroll(core: Ctx<'_>, p: ScrollParams) -> Result<ScrollResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    core.saw(p.caller.as_deref(), id);
    let result = {
        let mut st = core.lock();
        if let Some(offset) = p.offset_from_bottom {
            set_scroll(&mut st, id, offset)
        } else {
            scroll_state(&st, id)
        }
    };
    core.flush_observed().await?;
    Ok(result)
}

async fn terminal_unscroll(core: Ctx<'_>, p: TerminalParams) -> Result<ScrollResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    core.saw(p.caller.as_deref(), id);
    let result = {
        let mut st = core.lock();
        set_scroll(&mut st, id, 0)
    };
    core.flush_observed().await?;
    Ok(result)
}

async fn terminal_selection_read(core: Ctx<'_>, p: SelectionReadParams) -> Result<SelectionReadResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    core.saw(p.caller.as_deref(), id);
    let text = {
        let st = core.lock();
        if let Some(text) = core.screen_plain_range(&st, id, p.start_col as u16, p.start_row, p.end_col as u16, p.end_row) {
            text
        } else {
            crop_text(&core.screen_text(&st, id).unwrap_or_default(), p.start_row, p.start_col, p.end_row, p.end_col)
        }
    };
    core.flush_observed().await?;
    Ok(SelectionReadResult { text })
}

async fn terminal_attach(core: Ctx<'_>, p: AttachParams) -> Result<AttachResult, RpcError> {
    let Some(conn) = core.conn else {
        return Err(RpcError::new(
            "needs_framed",
            "attach needs a framed connection",
            "send hello with framed: true first, or use `hc attach`",
        ));
    };
    let id = resolve(core, &p.terminal)?;
    if p.caller.as_deref().and_then(crate::terminals::parse_id) == Some(id) {
        return Err(RpcError::new(
            "refused",
            format!(
                "{} is the terminal you are in: attached to itself, it would show its own output forever",
                crate::terminals::address(id)
            ),
            "attach from another terminal",
        ));
    }
    let req = crate::viewers::AttachRequest {
        observe: p.observe,
        resize_notifications: p.resize_notifications,
        history: p.history,
        size: (p.cols, p.rows),
        display: p.display,
        resumed: p.resumed,
    };
    let channel = core.attach(conn, id, req)?;
    Ok(AttachResult {
        channel,
        terminal: Public(record(core, id)?),
        resize_notifications: p.observe && p.resize_notifications,
        automatic_input: true,
    })
}

async fn terminal_send(core: Ctx<'_>, p: SendParams) -> Result<SendResult, RpcError> {
    let timeout = wait_timeout(core, p.timeout)?; // checked before anything is typed
    let id = resolve(core, &p.terminal)?;
    let text = core.tagged(p.caller.as_deref(), id, &p.text, false);
    let sent = core.send(id, &text, p.force, p.only_if.map(|w| word(&w)).as_deref()).await?;
    if let Some(child) = p.caller.as_deref().and_then(crate::terminals::parse_id) {
        let mut st = core.lock();
        if let Some(c) = st
            .reg
            .terminals
            .get_mut(&child)
            .filter(|c| c.parent.as_deref() == Some(crate::terminals::address(id).as_str()))
        {
            c.told_parent = true;
        }
    }
    if sent.status.as_deref() == Some("working") {
        let mut st = core.lock();
        let from = p
            .caller
            .as_deref()
            .and_then(crate::terminals::parse_id)
            .and_then(|c| st.reg.terminals.get(&c))
            .map(|t| t.address.clone());
        let from = from.or_else(|| p.caller.clone().filter(|c| c.contains('/'))); // a child on another machine
        st.messages.insert(id, from);
        drop(st);
        core.changed.notify_waiters();
    }
    core.saw(p.caller.as_deref(), id);
    if let Some(caller) = &p.caller {
        core.lock().last_send.insert((caller.clone(), id), sent.turn);
    }
    let wait = if p.wait && sent.started == Some(false) {
        Some(core.wait_result(id, false, "not_started", None))
    } else if p.wait {
        let spec = WaitSpec { output: None, timeout, after_turn: Some(sent.turn) };
        Some(watched(core, p.caller.clone(), id, spec).await)
    } else {
        None
    };
    core.flush_observed().await?;
    Ok(SendResult { status: sent.status, turn: sent.turn, started: sent.started, wait })
}

async fn machine_exec(core: Ctx<'_>, p: ExecParams) -> Result<ExecResult, RpcError> {
    crate::exec::run(core, p, from_afar(core)).await
}

fn from_afar(core: Ctx<'_>) -> bool {
    core.conn.is_some_and(|conn| crate::remote::is_peer(core, conn))
}

async fn file_read(core: Ctx<'_>, p: FileReadParams) -> Result<FileReadResult, RpcError> {
    let afar = from_afar(core);
    blocking(move || crate::files::read(p, afar)).await
}

async fn file_write(core: Ctx<'_>, p: FileWriteParams) -> Result<FileResult, RpcError> {
    let afar = from_afar(core);
    blocking(move || crate::files::write(p, afar)).await
}

async fn file_edit(core: Ctx<'_>, p: FileEditParams) -> Result<FileResult, RpcError> {
    let afar = from_afar(core);
    blocking(move || crate::files::edit(p, afar)).await
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, RpcError> + Send + 'static) -> Result<T, RpcError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| RpcError::internal(e.to_string()))?
}

async fn terminal_keys(core: Ctx<'_>, p: KeysParams) -> Result<KeysResult, RpcError> {
    let id = resolve(core, &p.terminal)?;
    let (status, turn) = core.keys(id, &p.keys).await?;
    core.saw(p.caller.as_deref(), id);
    core.flush_observed().await?;
    Ok(KeysResult { status, turn })
}

async fn terminal_interrupt(core: Ctx<'_>, p: InterruptParams) -> Result<InterruptResult, RpcError> {
    use crate::input::Interrupted;
    let timeout = seconds(p.timeout)?.unwrap_or(Duration::from_secs(10));
    let id = resolve(core, &p.terminal)?;
    let (outcome, key) = core.interrupt(id, timeout).await?;
    let outcome = match outcome {
        Interrupted::Stopped => "stopped",
        Interrupted::Exited => "exited",
        Interrupted::StillWorking => "still_working",
        Interrupted::Unknown => "unknown",
    };
    core.flush_observed().await?;
    Ok(InterruptResult { outcome: outcome.into(), key })
}

async fn events_subscribe(core: Ctx<'_>, p: SubscribeParams) -> Result<SubscribeResult, RpcError> {
    use crate::events::{Filter, Sink};
    // A terminal on a machine is named as it is here; one here, by its id.
    let address = |t: &str| match t.split_once('/').filter(|(m, _)| core.lock().machines.iter().any(|x| x.name == *m)) {
        Some(_) => Ok(t.to_string()),
        None => resolve(core, t).map(crate::terminals::address),
    };
    let terminal = p.terminal.as_deref().map(address).transpose()?;
    let children_of = p.children_of.as_deref().map(address).transpose()?;
    let filter = Filter { terminal, children_of, labels: labels(&p.labels), docs: p.docs, here_only: from_afar(core) };
    let (sink, channel) = match (core.conn, core.plain) {
        (Some(conn), _) => {
            let channel = conn.new_channel();
            conn.with(|out| out.open(channel));
            (Sink::Framed { conn: conn.clone(), channel }, Some(channel))
        }
        (None, Some(slot)) => {
            let (tx, rx) = tokio::sync::mpsc::channel(crate::events::PLAIN_QUEUE);
            let behind = Arc::new(std::sync::atomic::AtomicBool::new(false));
            *slot.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(PlainSub { rx, behind: behind.clone(), filter: filter.clone() });
            (Sink::Plain { tx, behind }, None)
        }
        (None, None) => return Err(RpcError::internal("no connection to deliver events on")),
    };
    let (seq, terminals) = {
        let mut st = core.lock();
        let terminals = core.matching(&st, &filter);
        core.subscribe(&mut st, filter, sink);
        (st.events.seq, terminals)
    };
    if let Some(channel) = channel {
        crate::server::heartbeat(core.core.clone(), core.conn.expect("framed").clone(), channel);
    }
    Ok(SubscribeResult { seq, terminals, channel })
}

/// A machine name that is free: valid, not another machine's, not this core's own.
fn free_name(core: &Core, st: &crate::runtime::State, name: &str) -> Result<(), RpcError> {
    crate::addr::check_name(name)?;
    if name == core.info.name || name == core.info.id || st.machines.iter().any(|m| m.name == name) {
        return Err(RpcError::new(
            "name_taken",
            format!("{name:?} is already a machine here"),
            "pick another with --name",
        ));
    }
    Ok(())
}

async fn machine_add(core: Ctx<'_>, p: MachineAddParams) -> Result<crate::machines::Machine, RpcError> {
    let (target, via) = match (p.target, p.via) {
        (Some(target), None) => (crate::machines::ssh_target(target), false),
        (None, Some(command)) => (command, true),
        _ => return Err(RpcError::invalid_params("give either target or via")),
    };
    let to = crate::machines::Reach { target: &target, via };
    crate::machines::check_target(to)?;
    if let Some(session) = &p.session {
        crate::addr::check_name(session)?;
    }
    let name = |st: &crate::runtime::State| match &p.name {
        Some(name) => free_name(core, st, name).map(|_| name.clone()),
        None => (!via)
            .then(|| crate::machines::default_name(&target, |name| free_name(core, st, name).is_err()))
            .flatten()
            .ok_or_else(|| {
                RpcError::invalid_params(format!("can't make a name from {target:?}")).with_hint("give one with --name")
            }),
    };
    name(&core.lock())?;
    let hello = crate::machines::hello(&core.paths, to, p.session.as_deref()).await?;
    let text = |k: &str| hello["core"][k].as_str().unwrap_or_default().to_string();
    let mut st = core.lock();
    let machine = crate::machines::Machine {
        name: name(&st)?,
        target,
        via,
        temporary: p.temporary,
        session: p.session,
        id: text("id"),
        host: text("name"),
        version: hello["version"].as_str().unwrap_or_default().into(),
        keeps_running_after_logout: hello["keeps_running_after_logout"].as_bool(),
        logout_linger_user: hello["logout_linger_user"].as_str().map(String::from),
    };
    if machine.id == core.info.id {
        return Err(RpcError::invalid_params(format!("{} is this core", machine.target))
            .with_hint("add another machine, or another --session"));
    }
    if let Some(m) = st.machines.iter().find(|m| m.id == machine.id) {
        // Reached another way yet the same core: a copy of that machine's disk
        // whose system kept its machine id (some container images).
        if (m.target.as_str(), m.via) != (machine.target.as_str(), machine.via) {
            return Err(RpcError::new(
                "already_added",
                format!("{} answers as {}'s core: it looks like a copy of {}", machine.target, m.name, m.name),
                "on the copy, stop hc and delete its core.json in hc's state folder, then add it again",
            ));
        }
        return Err(RpcError::new(
            "already_added",
            format!("that core is already added as {}", m.name),
            format!("rename it: hc machine rename {} <name>", m.name),
        ));
    }
    st.machines.push(machine.clone());
    crate::machines::save(&core.paths.state, &st.machines);
    drop(st);
    crate::remote::keep_up(core.core, machine.id.clone());
    Ok(machine)
}

async fn machine_list(core: Ctx<'_>, _: Empty) -> Result<MachineListResult, RpcError> {
    let st = core.lock();
    Ok(MachineListResult { machines: st.machines.iter().map(|m| crate::remote::view(&st, m)).collect() })
}

async fn machine_connect(core: Ctx<'_>, p: MachineParams) -> Result<crate::remote::MachineView, RpcError> {
    let m = {
        let st = core.lock();
        st.machines
            .iter()
            .find(|m| m.name == p.machine)
            .cloned()
            .ok_or_else(|| crate::machines::unknown(&st.machines, &p.machine))?
    };
    let connected = matches!(core.lock().lines.get(&m.id), Some(crate::remote::LineState::Connected(_)));
    if !connected {
        crate::remote::keep_up(core.core, m.id.clone());
        crate::remote::dialed(core, &m.id).await;
    }
    Ok(crate::remote::view(&core.lock(), &m))
}

async fn machine_rename(core: Ctx<'_>, p: MachineRenameParams) -> Result<crate::machines::Machine, RpcError> {
    let mut st = core.lock();
    let i = st
        .machines
        .iter()
        .position(|m| m.name == p.machine)
        .ok_or_else(|| crate::machines::unknown(&st.machines, &p.machine))?;
    if p.new_name != p.machine {
        free_name(core, &st, &p.new_name)?;
    }
    let id = st.machines[i].id.clone();
    st.machines[i].name = p.new_name.clone();
    if p.new_name != p.machine {
        crate::remote::rename_mirror(core, &mut st, &id, &p.machine, &p.new_name);
    }
    crate::machines::save(&core.paths.state, &st.machines);
    Ok(st.machines[i].clone())
}

async fn machine_rm(core: Ctx<'_>, p: MachineParams) -> Result<RemoveResult, RpcError> {
    let mut st = core.lock();
    let i = st
        .machines
        .iter()
        .position(|m| m.name == p.machine)
        .ok_or_else(|| crate::machines::unknown(&st.machines, &p.machine))?;
    let gone = st.machines.remove(i);
    crate::remote::forget(core, &mut st, &gone.id);
    crate::machines::save(&core.paths.state, &st.machines);
    let last_on_target = !st.machines.iter().any(|m| m.target == gone.target);
    drop(st);
    if last_on_target {
        crate::machines::logout(&core.paths, gone.reach());
    }
    Ok(RemoveResult { removed: gone.name })
}

async fn rpc_discover(_: Ctx<'_>, _: Empty) -> Result<serde_json::Value, RpcError> {
    Ok(openrpc())
}

#[cfg(test)]
mod crop_tests {
    use super::{cell_cols, crop_text};

    #[test]
    fn wide_characters_are_two_cells() {
        assert_eq!(cell_cols('你'), 2);
        assert_eq!(cell_cols('a'), 1);
        assert_eq!(cell_cols('\u{0301}'), 0);
    }

    #[test]
    fn crop_text_uses_cell_columns() {
        // 你(0-1) 好(2-3) 世(4-5) 界(6-7)
        assert_eq!(crop_text("你好世界", 0, 2, 0, 5), "好世");
        assert_eq!(crop_text("e\u{0301}x", 0, 0, 0, 0), "e\u{0301}");
        assert_eq!(crop_text("hello", 0, 1, 0, 3), "ell");
    }
}
