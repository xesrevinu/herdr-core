//! Unit tests for the embedded Rex host server.

use super::appdoc::*;
use super::bridge::RexBridge;
use super::hub::{feed_pty_modes, take_osc52};
use super::model::Ids;
use super::ops::{check_layout, create_target, leaf_command, leaf_cwd, remote_shell_fallback};
use super::proto::*;
use super::register_all;
use super::server::RexServer;
use super::term::{
    encode_rex_key, encode_rex_key_with_screen, is_safe_file_name, parse_upload, pasted, shell_word,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

#[test]
fn uuidv5_matches_go_herdrex() {
    // Verified against Go Herdrex on /tmp/herdrex-isolated/herdr-core.sock
    let ids = Ids::new("/tmp/herdrex-isolated/herdr-core.sock");
    let host = ids.host_id.clone();
    assert!(!host.is_empty());
    let s1 = ids.rex("session", "sp_test");
    assert!(s1.starts_with("session:"));
    assert_eq!(ids.herdr(&s1).as_deref(), Some("sp_test"));
    // Determinism across restarts with same socket path
    let ids2 = Ids::new("/tmp/herdrex-isolated/herdr-core.sock");
    assert_eq!(ids.host_id, ids2.host_id);
    assert_eq!(s1, ids2.rex("session", "sp_test"));
    assert_eq!(ids.split_id("tb1", &[false, true]), ids2.split_id("tb1", &[false, true]));
}

#[test]
fn pty_modes_strips_mouse_and_reasserts_on_ris_decstr_without_no_autowrap() {
    // Strips mouse DECSET (?1000h/?1002h/?1003h/?1006h) while tracking mouse=true
    let (out, rest, note) = feed_pty_modes(&[], b"hi\x1b[?1000h\x1b[?1006hworld");
    assert!(rest.is_empty());
    assert_eq!(out, b"hiworld");
    assert_eq!(note.mouse, Some(true));

    // Must NOT emit ?7l (noAutowrap) on RIS or DECSTR; must reassert paste+focus (?2004h?1004h)
    let (out_ris, _, note_ris) = feed_pty_modes(&[], b"\x1bc");
    assert!(!out_ris.windows(5).any(|w| w == b"\x1b[?7l"));
    assert!(out_ris.windows(8).any(|w| w == b"\x1b[?2004h"));
    assert!(out_ris.windows(8).any(|w| w == b"\x1b[?1004h"));
    assert_eq!(note_ris.mouse, Some(false));
    assert_eq!(note_ris.alt, Some(false));

    let (out_dec, _, note_dec) = feed_pty_modes(&[], b"\x1b[!p");
    assert!(!out_dec.windows(5).any(|w| w == b"\x1b[?7l"));
    assert!(out_dec.windows(8).any(|w| w == b"\x1b[?2004h"));
    assert_eq!(note_dec.paste, Some(false));

    // Split CSI sequence across chunks buffers cleanly
    let (o1, r1, _) = feed_pty_modes(&[], b"abc\x1b[?10");
    assert_eq!(o1, b"abc");
    assert_eq!(r1, b"\x1b[?10");
    let (o2, r2, n2) = feed_pty_modes(&r1, b"03hxyz");
    assert_eq!(o2, b"xyz");
    assert!(r2.is_empty());
    assert_eq!(n2.mouse, Some(true));
}

#[test]
fn osc52_extracts_clipboard_and_preserves_stream() {
    let seq = b"\x1b]52;c;aGVsbG8=\x07";
    let mut full = Vec::new();
    full.extend_from_slice(b"before");
    full.extend_from_slice(seq);
    full.extend_from_slice(b"after");
    let (out, rest, clips) = take_osc52(&[], &full);
    assert_eq!(out, full);
    assert!(rest.is_empty());
    assert_eq!(clips, vec!["aGVsbG8=".to_string()]);

    // Split across chunks (> 64 bytes payload)
    let big = "QUFB".repeat(30); // 120 bytes
    let big_seq = format!("\x1b]52;c;{big}\x1b\\");
    let (head, tail) = big_seq.as_bytes().split_at(80);
    let (o1, r1, c1) = take_osc52(&[], head);
    assert!(o1.is_empty());
    assert!(c1.is_empty());
    assert_eq!(r1.len(), 80);
    let (o2, r2, c2) = take_osc52(&r1, tail);
    assert_eq!(o2, big_seq.as_bytes());
    assert!(r2.is_empty());
    assert_eq!(c2, vec![big]);
}

#[test]
fn marshal_rex_orders_type_before_payload() {
    let v = json!({"payload": {"z": 1}, "seq": 4, "type": "event"});
    let s = marshal_rex(&v);
    assert_eq!(s, r#"{"type":"event","seq":4,"payload":{"z":1}}"#);
}

#[test]
fn file_url_and_decode_roundtrip_with_remote_host() {
    let u = file_url("jp", "/home/kee/my dir/foo#1");
    assert_eq!(u, "file://jp/home/kee/my%20dir/foo%231");
    assert_eq!(decode_file_url(&u), "/home/kee/my dir/foo#1");
    assert_eq!(decode_file_url("/plain/path"), "/plain/path");
}

#[test]
fn appdoc_split_ratio_swap_close() {
    let mut doc = Map::new();
    let sp = make_space("sp1", "work", "/tmp", vec![make_tab("tb1", "t1", make_block("p1", "t1"))]);
    doc_append_space(&mut doc, sp);

    assert!(doc_split_pane(&mut doc, "t1", "row", "p2", "t2", "s1", "after", 0.4));
    assert!(doc_set_split_ratio(&mut doc, "t1", "t2", "row", 0.7));
    assert!(doc_set_pane_title(&mut doc, "t2", "editor"));
    assert!(doc_swap_panes(&mut doc, "t1", "t2"));

    let closed = doc_close_pane(&mut doc, "t2").expect("close t2");
    assert_eq!(closed.0, vec!["t2".to_string()]);
    assert!(closed.1.is_empty());

    let closed_last = doc_close_pane(&mut doc, "t1").expect("close t1");
    assert_eq!(closed_last.0, vec!["t1".to_string()]);
    assert_eq!(closed_last.1, "tb1");
    assert_eq!(closed_last.2, "sp1");
}

#[test]
fn upload_validation_rejects_oversized_early() {
    let ok = parse_upload(&json!({
        "ref": "upload:11111111-1111-1111-1111-111111111111",
        "name": "photo.png",
        "size": 8 << 20,
    }));
    assert!(ok.is_ok());

    let too_big = parse_upload(&json!({
        "ref": "upload:11111111-1111-1111-1111-111111111111",
        "name": "huge.bin",
        "size": (8 << 20) + 1,
    }));
    assert!(too_big.is_err());

    assert!(!is_safe_file_name("../etc/passwd"));
    assert!(is_safe_file_name("report 2026.pdf"));
    assert_eq!(shell_word("/tmp/a.png"), "/tmp/a.png");
    assert_eq!(shell_word("/tmp/x;id;#"), "'/tmp/x;id;#'");
}

#[test]
fn layout_and_key_helpers() {
    let lay = json!({
        "block": {
            "flavor": SHELL_FLAVOR,
            "options": {
                "cwd": "file://jp/home/kee/app",
                "command": "htop",
            }
        }
    });
    assert!(check_layout(&lay).is_ok());
    assert_eq!(leaf_cwd(&lay), "/home/kee/app");
    assert_eq!(leaf_command(&lay), vec!["/bin/zsh", "-lc", "htop"]);

    assert_eq!(pasted("\x1b[200~hello\x1b[201~"), Some("hello"));
    assert_eq!(pasted("plain"), None);

    let (raw, _) = encode_rex_key(&json!({"key": "key_c", "mods": "ctrl"}));
    assert_eq!(raw, vec![0x03]);
    let (raw_enter, _) = encode_rex_key(&json!({"key": "enter"}));
    assert_eq!(raw_enter, b"\r");

    let machines = vec!["tokyo-jp".to_string(), "virginia-us".to_string()];
    assert_eq!(create_target("jp / api", "", "", "mac", &machines), ("tokyo-jp".into(), "api".into()));
    assert_eq!(create_target("api", "", "tokyo-jp", "mac", &machines), ("tokyo-jp".into(), "api".into()));
    assert_eq!(create_target("mac / dev", "", "tokyo-jp", "mac", &machines), (String::new(), "dev".into()));
}

#[test]
fn host_id_distinguishes_local_and_remote_panes() {
    let ids = Ids::new("/tmp/herdrex-hostid-test/core.sock");
    let local_pane = Pane { id: "t1".into(), ..Pane::default() };
    let jp_pane = Pane { id: "cc-remote-jp/t12".into(), ..Pane::default() };
    let us_pane = Pane { id: "cc-remote-us/t1".into(), ..Pane::default() };

    let local_blk = ids.block(&local_pane);
    let jp_blk = ids.block(&jp_pane);
    let us_blk = ids.block(&us_pane);

    assert_eq!(local_blk.host_id, ids.host_id);
    assert_ne!(jp_blk.host_id, ids.host_id);
    assert_ne!(us_blk.host_id, ids.host_id);
    assert_ne!(jp_blk.host_id, us_blk.host_id);
    // Deterministic across restarts
    let ids2 = Ids::new("/tmp/herdrex-hostid-test/core.sock");
    assert_eq!(jp_blk.host_id, ids2.block(&jp_pane).host_id);
}

#[test]
fn ghostty_key_encoding_respects_legacy_kitty_and_modify_other_keys() {
    let mut screen = ghostty_vt::Terminal::new(80, 24, 0);

    // Legacy mode: Ctrl+V -> 0x16 (whether text is empty or C0 "\x16")
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "key_v", "mods": "ctrl", "consumed_mods": "", "text": "", "unshifted_codepoint": 118})
        ),
        vec![0x16]
    );
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "key_v", "mods": "ctrl", "consumed_mods": "", "text": "\x16", "unshifted_codepoint": 118})
        ),
        vec![0x16]
    );
    assert_eq!(
        encode_rex_key_with_screen(&screen, &json!({"key": "key_v", "mods": "ctrl"})),
        vec![0x16]
    );
    // Legacy mode: Enter -> \r, Super+V -> empty, release -> empty
    assert_eq!(
        encode_rex_key_with_screen(&screen, &json!({"key": "enter", "mods": ""})),
        b"\r"
    );
    // Ghostty's default encoder uses xterm modifyOtherKeys for Shift+Enter (newline in Agents!)
    assert_eq!(
        encode_rex_key_with_screen(&screen, &json!({"key": "enter", "mods": "shift"})),
        b"\x1b[27;2;13~"
    );
    assert!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "key_v", "mods": "super", "consumed_mods": "", "text": "v", "unshifted_codepoint": 118})
        )
        .is_empty()
    );
    assert!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "release", "key": "key_v", "mods": "ctrl", "unshifted_codepoint": 118})
        )
        .is_empty()
    );
    // Unconsumed Alt sends ESC prefix; consumed Alt (macOS Option char) sends UTF-8 text
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "key_b", "mods": "alt", "consumed_mods": "", "text": "", "unshifted_codepoint": 98})
        ),
        b"\x1bb"
    );
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "key_p", "mods": "alt", "consumed_mods": "alt", "text": "π", "unshifted_codepoint": 112})
        ),
        "π".as_bytes()
    );

    // Application cursor keys (DECCKM)
    screen.write(b"\x1b[?1h");
    assert_eq!(
        encode_rex_key_with_screen(&screen, &json!({"key": "arrow_up", "mods": ""})),
        b"\x1bOA"
    );

    // modifyOtherKeys mode 2 -> Shift+Enter becomes CSI 27;2;13~
    screen.write(b"\x1b[>4;2m");
    assert_eq!(
        encode_rex_key_with_screen(&screen, &json!({"key": "enter", "mods": "shift"})),
        b"\x1b[27;2;13~"
    );

    // Kitty keyboard disambiguate (CSI > 1 u): Ctrl+V -> CSI 118;5u, Shift+Enter -> CSI 13;2u
    screen.write(b"\x1b[>1u");
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "key_v", "mods": "ctrl", "consumed_mods": "", "text": "", "unshifted_codepoint": 118})
        ),
        b"\x1b[118;5u"
    );
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "key_v", "mods": "ctrl", "consumed_mods": "", "text": "\x16", "unshifted_codepoint": 118})
        ),
        b"\x1b[118;5u"
    );
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "press", "key": "enter", "mods": "shift", "consumed_mods": "", "text": "", "unshifted_codepoint": 13})
        ),
        b"\x1b[13;2u"
    );
    assert_eq!(
        encode_rex_key_with_screen(&screen, &json!({"key": "escape", "mods": ""})),
        b"\x1b[27u"
    );

    // Kitty report events (CSI > 3 u): release is reported
    screen.write(b"\x1b[>3u");
    assert_eq!(
        encode_rex_key_with_screen(
            &screen,
            &json!({"action": "release", "key": "key_v", "mods": "ctrl", "unshifted_codepoint": 118})
        ),
        b"\x1b[118;5:3u"
    );
}

#[tokio::test]
async fn rex_e2e_api_rev_11_upload_bytes_v1_and_grant_file_access() {
    let root = crate::test_tmp().join(format!("hc-rex-upload-{}", crate::platform::random_hex()));
    let paths = crate::paths::Paths {
        socket: root.join("core.sock"),
        holder_socket: root.join("holder.sock"),
        state: root.clone(),
        config: root.join("config.toml"),
    };
    paths.create_dirs().unwrap();
    let core = crate::runtime::Core::start(
        paths,
        crate::api::CoreInfo { id: "rex-test".into(), name: "rex-test".into() },
    )
    .unwrap();

    // Register one live terminal (`t1`) with bracketed paste enabled.
    let tid = {
        let mut st = core.lock();
        let id = st
            .reg
            .create(
                crate::terminals::NewTerminal {
                    argv: vec!["sh".into()],
                    cols: 80,
                    rows: 24,
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        let mut screen = ghostty_vt::Terminal::new(80, 24, 0);
        screen.write(b"\x1b[?2004h");
        st.screens.insert(id, screen);
        id
    };
    let pane_addr = crate::terminals::address(tid);

    let srv = RexServer::new(false);
    let bridge = RexBridge::new(core.clone(), srv.clone(), false, false, String::new());
    register_all(&srv, &bridge);
    bridge.refresh_full().await;

    let sid = bridge.ids.rex("session", "sp_test");
    let bid = bridge.ids.rex("block", &pane_addr);

    // Helper: open an in-memory duplex WS connection against RexServer.
    async fn open_ws(
        srv: Arc<RexServer>,
        path: &str,
        subproto: &str,
        is_unix: bool,
    ) -> tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            srv.serve_stream(server_io, (!is_unix).then(|| "127.0.0.1:9999".into()), is_unix)
                .await;
        });
        let mut req = format!("ws://localhost{path}").into_client_request().unwrap();
        req.headers_mut()
            .insert("sec-websocket-protocol", subproto.parse().unwrap());
        let (ws, _) = tokio_tungstenite::client_async(req, client_io).await.unwrap();
        ws
    }

    async fn rpc(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        id: &str,
        method: &str,
        payload: Value,
    ) -> Value {
        ws.send(Message::Text(
            json!({"type": "request", "id": id, "method": method, "payload": payload})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Text(txt) = msg {
                let v: Value = serde_json::from_str(&txt).unwrap();
                if v["type"] == "response" && v["id"] == id {
                    return v;
                }
            }
        }
        panic!("control ws closed waiting for response {id}");
    }

    // 1. Legacy client (rev 7) still negotiates rev 7.
    let mut legacy = open_ws(srv.clone(), "/api/control", CONTROL_PROTOCOL, true).await;
    legacy
        .send(Message::Text(
            json!({"type": "hello", "protocol": CONTROL_PROTOCOL, "api_revision": 7, "api_min_revision": 7})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let legacy_welcome: Value = match legacy.next().await.unwrap().unwrap() {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(legacy_welcome["api_revision"], 7);
    assert_eq!(legacy_welcome["api_server_revision"], 21);
    drop(legacy);

    // 2. Modern Rex.app client (rev 21..7) negotiates rev 21 over Unix socket.
    let mut ctrl = open_ws(srv.clone(), "/api/control", CONTROL_PROTOCOL, true).await;
    ctrl.send(Message::Text(
        json!({"type": "hello", "protocol": CONTROL_PROTOCOL, "api_revision": 21, "api_min_revision": 7})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let welcome: Value = match ctrl.next().await.unwrap().unwrap() {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(welcome["api_revision"], 21);
    let client_id = welcome["client"]["id"].as_str().unwrap().to_string();
    let client = srv.clients().into_iter().find(|c| c.id == client_id).unwrap();
    srv.attach(&client, &sid);

    // 3. server.apple.grant_file_access over Unix socket succeeds, over TCP returns 403.
    let sample = root.join("sample.png");
    std::fs::write(&sample, b"\x89PNG\r\n\x1a\n").unwrap();
    let g_unix = rpc(
        &mut ctrl,
        "g1",
        "server.apple.grant_file_access",
        json!({"files": [
            {"path": sample.to_string_lossy()},
            {"path": "relative.png"},
            {"path": root.join("missing.png").to_string_lossy()},
        ]}),
    )
    .await;
    let files = g_unix["payload"]["files"].as_array().unwrap();
    assert_eq!(files[0]["access"], "readable");
    assert_eq!(files[1]["access"], "denied");
    assert_eq!(files[2]["access"], "denied");

    let mut tcp_ctrl = open_ws(srv.clone(), "/api/control", CONTROL_PROTOCOL, false).await;
    tcp_ctrl
        .send(Message::Text(
            json!({"type": "hello", "protocol": CONTROL_PROTOCOL, "api_revision": 11, "api_min_revision": 7})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let _ = tcp_ctrl.next().await;
    let g_tcp = rpc(
        &mut tcp_ctrl,
        "g2",
        "server.apple.grant_file_access",
        json!({"files": [{"path": sample.to_string_lossy()}]}),
    )
    .await;
    assert_eq!(g_tcp["error"]["status"], 403);
    drop(tcp_ctrl);

    // Helper: run one rex.data.bytes.v1 upload stream and return the server's close code.
    async fn send_bytes_stream(
        srv: Arc<RexServer>,
        ticket: &str,
        chunks: &[&[u8]],
        half_close: bool,
    ) -> u16 {
        let mut ds = open_ws(srv, "/api/data", DATA_BYTES_PROTOCOL, true).await;
        let raw_tk = URL_SAFE_NO_PAD.decode(ticket).unwrap();
        let mut hello = Vec::with_capacity(17);
        hello.push(MSG_HELLO);
        hello.extend_from_slice(&raw_tk);
        ds.send(Message::Binary(hello.into())).await.unwrap();
        let wel = ds.next().await.unwrap().unwrap();
        assert!(matches!(wel, Message::Binary(ref b) if b.len() == 32 && b[0] == MSG_WELCOME));
        for chunk in chunks {
            ds.send(Message::Binary((*chunk).to_vec().into())).await.unwrap();
        }
        if half_close {
            ds.send(Message::Binary(Vec::new().into())).await.unwrap();
        }
        while let Some(item) = ds.next().await {
            if let Ok(Message::Close(Some(cf))) = item {
                return cf.code.into();
            }
        }
        0
    }

    // 4. Single image upload (8 bytes + empty binary frame half-close) -> 1000 & staged on disk.
    let png = b"\x89PNG\r\n\x1a\n";
    let u1 = rpc(
        &mut ctrl,
        "u1",
        "com.superlogical.terminal.upload_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {"ref": "upload:11111111-1111-1111-1111-111111111111", "name": "clipboard.png", "size": png.len()},
        }),
    )
    .await;
    let tk1 = u1["payload"]["ticket"].as_str().unwrap();
    assert_eq!(send_bytes_stream(srv.clone(), tk1, &[&png[..4], &png[4..]], true).await, CLOSE_NORMAL);
    let staged = root.join("files").join(&pane_addr).join("clipboard.png");
    assert_eq!(std::fs::read(&staged).unwrap(), png);

    // 5. Truncated upload (2 of 5 bytes + half-close) -> 4006 protocol violation.
    let u_short = rpc(
        &mut ctrl,
        "u2",
        "com.superlogical.terminal.upload_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {"ref": "upload:22222222-2222-2222-2222-222222222222", "name": "short.png", "size": 5},
        }),
    )
    .await;
    let tk_short = u_short["payload"]["ticket"].as_str().unwrap();
    assert_eq!(
        send_bytes_stream(srv.clone(), tk_short, &[b"hi"], true).await,
        CLOSE_PROTOCOL_VIOLATION
    );
    assert!(!root.join("files").join(&pane_addr).join("short.png").exists());

    // 6. Oversized byte stream (6 of 5 bytes) -> 4006 protocol violation.
    let u_over = rpc(
        &mut ctrl,
        "u3",
        "com.superlogical.terminal.upload_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {"ref": "upload:33333333-3333-3333-3333-333333333333", "name": "over.png", "size": 5},
        }),
    )
    .await;
    let tk_over = u_over["payload"]["ticket"].as_str().unwrap();
    assert_eq!(
        send_bytes_stream(srv.clone(), tk_over, &[b"123456"], false).await,
        CLOSE_PROTOCOL_VIOLATION
    );
    assert!(!root.join("files").join(&pane_addr).join("over.png").exists());

    // 7. Zero-byte upload + empty binary frame half-close -> 1000.
    let u_zero = rpc(
        &mut ctrl,
        "u4",
        "com.superlogical.terminal.upload_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {"ref": "upload:44444444-4444-4444-4444-444444444444", "name": "empty.png", "size": 0},
        }),
    )
    .await;
    let tk_zero = u_zero["payload"]["ticket"].as_str().unwrap();
    assert_eq!(send_bytes_stream(srv.clone(), tk_zero, &[], true).await, CLOSE_NORMAL);
    assert_eq!(std::fs::read(root.join("files").join(&pane_addr).join("empty.png")).unwrap(), b"");

    // 8. Two-file batch upload (index 1 uploaded before index 0) -> both 1000 & both staged.
    let batch = "batch-test-1";
    let ub0 = rpc(
        &mut ctrl,
        "b0",
        "com.superlogical.terminal.upload_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {
                "ref": "upload:55555555-5555-5555-5555-555555555555",
                "name": "first.png",
                "size": 3,
                "batch": batch,
                "index": 0,
                "count": 2,
            },
        }),
    )
    .await;
    let ub1 = rpc(
        &mut ctrl,
        "b1",
        "com.superlogical.terminal.upload_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {
                "ref": "upload:66666666-6666-6666-6666-666666666666",
                "name": "second.png",
                "size": 3,
                "batch": batch,
                "index": 1,
                "count": 2,
            },
        }),
    )
    .await;
    let tk_b1 = ub1["payload"]["ticket"].as_str().unwrap();
    let tk_b0 = ub0["payload"]["ticket"].as_str().unwrap();
    assert_eq!(send_bytes_stream(srv.clone(), tk_b1, &[b"222"], true).await, CLOSE_NORMAL);
    assert_eq!(send_bytes_stream(srv.clone(), tk_b0, &[b"111"], true).await, CLOSE_NORMAL);
    assert_eq!(std::fs::read(root.join("files").join(&pane_addr).join("first.png")).unwrap(), b"111");
    assert_eq!(std::fs::read(root.join("files").join(&pane_addr).join("second.png")).unwrap(), b"222");

    // 9. download_begin (Rev 13): local regular file, 0-byte file, missing/dir errors, if_none_match.
    let dl_file = root.join("demos.mbt");
    let dl_bytes = b"fn main() { println(\"hello rex\") }\n";
    std::fs::write(&dl_file, dl_bytes).unwrap();
    let dl_err_missing = rpc(
        &mut ctrl,
        "dl_miss",
        "com.superlogical.terminal.download_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {"ref": "download:77777777-7777-7777-7777-777777777777", "path": root.join("nope.mbt").to_string_lossy()},
        }),
    )
    .await;
    assert_eq!(dl_err_missing["error"]["code"], CODE_NOT_FOUND);

    let dl_err_dir = rpc(
        &mut ctrl,
        "dl_dir",
        "com.superlogical.terminal.download_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {"ref": "download:88888888-8888-8888-8888-888888888888", "path": root.to_string_lossy()},
        }),
    )
    .await;
    assert_eq!(dl_err_dir["error"]["code"], CODE_BAD_REQUEST);

    let dl_ok = rpc(
        &mut ctrl,
        "dl1",
        "com.superlogical.terminal.download_begin",
        json!({
            "session_id": sid,
            "block_id": bid,
            "args": {"ref": "download:99999999-9999-9999-9999-999999999999", "path": dl_file.to_string_lossy()},
        }),
    )
    .await;
    assert_eq!(dl_ok["payload"]["name"], "demos.mbt");
    assert_eq!(dl_ok["payload"]["size"], dl_bytes.len());
    let dl_tk = dl_ok["payload"]["ticket"].as_str().unwrap();
    let mut ds = open_ws(srv.clone(), "/api/data", DATA_BYTES_PROTOCOL, true).await;
    let raw_tk = URL_SAFE_NO_PAD.decode(dl_tk).unwrap();
    let mut hello = Vec::with_capacity(17);
    hello.push(MSG_HELLO);
    hello.extend_from_slice(&raw_tk);
    ds.send(Message::Binary(hello.into())).await.unwrap();
    let wel = ds.next().await.unwrap().unwrap();
    assert!(matches!(wel, Message::Binary(ref b) if b.len() == 32 && b[0] == MSG_WELCOME));
    let mut received = Vec::new();
    let mut saw_half_close = false;
    let mut close_code = 0u16;
    while let Some(item) = ds.next().await {
        match item.unwrap() {
            Message::Binary(b) if b.is_empty() => {
                saw_half_close = true;
            }
            Message::Binary(b) => received.extend_from_slice(&b),
            Message::Close(Some(cf)) => {
                close_code = cf.code.into();
                break;
            }
            _ => {}
        }
    }
    assert!(saw_half_close, "download stream must send empty binary half-close frame");
    assert_eq!(close_code, CLOSE_NORMAL);
    assert_eq!(received, dl_bytes);

    // 10. Rev 3 modes, Rev 5 privacy_status, Rev 15 ports, Rev 18 event_dropped, Rev 19 focus_history.reverse, Rev 20 client.undo_close.
    let modes = rpc(
        &mut ctrl,
        "m1",
        "com.superlogical.terminal.modes",
        json!({"session_id": sid, "block_id": bid, "args": {}}),
    )
    .await;
    assert_eq!(modes["payload"]["screen"], "primary");
    assert!(
        modes["payload"]["modes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == "bracketed_paste" && m["set"] == true)
    );

    let ports = rpc(
        &mut ctrl,
        "p1",
        "com.superlogical.terminal.ports",
        json!({"session_id": sid, "block_id": bid, "args": {}}),
    )
    .await;
    assert_eq!(ports["payload"]["status"], "ok");
    assert!(ports["payload"]["ports"].is_array());

    let priv_st = rpc(&mut ctrl, "pr1", "server.apple.privacy_status", json!({})).await;
    assert!(priv_st["payload"]["services"].is_array());

    let rev_empty = rpc(&mut ctrl, "fh1", "focus_history.reverse", json!({})).await;
    assert_eq!(rev_empty["payload"]["reversed"], false);

    let undo_empty = rpc(&mut ctrl, "uc1", "client.undo_close", json!({})).await;
    assert_eq!(undo_empty["error"]["code"], CODE_NOT_FOUND);

    // Rev 18: oversized event (>1 MiB) emits event_dropped and keeps connection open.
    let huge = "x".repeat(MAX_MESSAGE_BYTES + 1024);
    client.session_event(
        &sid,
        "block_event",
        json!({
            "block_id": bid,
            "creator_name": TERMINAL_CREATOR,
            "name": "selection_copied",
            "payload": {"text": huge},
        }),
    );
    let mut saw_dropped = false;
    while let Some(Ok(Message::Text(txt))) = ctrl.next().await {
        let v: Value = serde_json::from_str(&txt).unwrap();
        if v["type"] == "event" && v["payload"]["type"] == "event_dropped" {
            assert_eq!(v["payload"]["payload"]["event_type"], "block_event");
            assert_eq!(v["payload"]["payload"]["session_id"], sid);
            assert_eq!(v["payload"]["payload"]["block_id"], bid);
            assert_eq!(v["payload"]["payload"]["block_event_name"], "selection_copied");
            saw_dropped = true;
            break;
        }
    }
    assert!(saw_dropped, "oversized event must send event_dropped on rev >= 18");
    // Connection is still alive after event_dropped!
    let ping_after = rpc(&mut ctrl, "after_drop", "server.version", json!({})).await;
    assert_eq!(ping_after["payload"]["api_revision"], 21);

    // Verify CloseCode conversion matches expected numeric constants.
    assert_eq!(u16::from(CloseCode::Normal), CLOSE_NORMAL);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn transfer_tab_and_rev21_independent_zoom() {
    let mut doc = Map::new();
    doc_append_space(
        &mut doc,
        make_space("sp1", "one", "/tmp", vec![make_tab("tb1", "t1", make_block("p1", "t1")), make_tab("tb2", "t2", make_block("p2", "t2"))]),
    );
    doc_append_space(
        &mut doc,
        make_space("sp2", "two", "/tmp", vec![make_tab("tb3", "t3", make_block("p3", "t3"))]),
    );
    assert_eq!(doc_transfer_tab(&mut doc, "sp1", "tb1", "sp1", ""), Err("same_session"));
    let moved = doc_transfer_tab(&mut doc, "sp1", "tb2", "sp2", "tb3").expect("transfer tb2");
    assert_eq!(moved, vec!["t2".to_string()]);
    let sp2_tabs = doc["spaces"][1]["tabs"].as_array().unwrap();
    assert_eq!(sp2_tabs.len(), 2);
    assert_eq!(sp2_tabs[0]["id"], "tb2");
    assert_eq!(sp2_tabs[1]["id"], "tb3");

    // Rev 21: tiled_zoomed_block_id stays set while focus is in an unzoomed floating layer.
    let ids = Ids::new("/tmp/herdrex-zoom-test/core.sock");
    let tab = Tab { id: "tb1".into(), workspace_id: "sp1".into(), label: "1".into(), focused: true };
    let panes = vec![
        Pane { id: "t1".into(), tab_id: "tb1".into(), workspace_id: "sp1".into(), ..Pane::default() },
        Pane { id: "t2".into(), tab_id: "tb1".into(), workspace_id: "sp1".into(), ..Pane::default() },
    ];
    let floats = vec![super::model::FloatLayer {
        layer_id: "layer:float1".into(),
        pane_id: "t2".into(),
        bounds: [0.1, 0.1, 0.8, 0.8],
        minimized: false,
    }];
    let lay = LayoutNode {
        kind: "split".into(),
        direction: "right".into(),
        ratio: 0.5,
        first: Some(Box::new(LayoutNode::pane("t1".into()))),
        second: Some(Box::new(LayoutNode::pane("t2".into()))),
        focused: "t2".into(),
        zoomed: false,
        pane_id: String::new(),
    };
    let win = ids.window(&tab, &panes, &lay, &floats, Some("t1"), None);
    assert_eq!(win.tiled_zoomed_block_id, Some(ids.rex("block", "t1")));
    assert_eq!(win.zoomed_block_id, None);
    let win_both = ids.window(&tab, &panes, &lay, &floats, Some("t1"), Some("t2"));
    assert_eq!(win_both.tiled_zoomed_block_id, Some(ids.rex("block", "t1")));
    assert_eq!(win_both.zoomed_block_id, Some(ids.rex("block", "t2")));

    assert_eq!(remote_shell_fallback(&["zsh".into(), "-l".into()]), Some(Vec::new()));
    assert_eq!(remote_shell_fallback(&["/bin/zsh".into()]), Some(Vec::new()));
    assert_eq!(
        remote_shell_fallback(&["/bin/zsh".into(), "-lc".into(), "lazygit".into()]),
        Some(vec!["/bin/sh".into(), "-lc".into(), "lazygit".into()]),
    );
    assert_eq!(remote_shell_fallback(&["lazygit".into()]), None);
}
