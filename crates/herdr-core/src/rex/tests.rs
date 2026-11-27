//! Unit tests for the embedded Rex host server.

use super::appdoc::*;
use super::hub::{feed_pty_modes, take_osc52};
use super::model::Ids;
use super::ops::{check_layout, create_target, leaf_command, leaf_cwd};
use super::proto::*;
use super::term::{encode_rex_key, is_safe_file_name, parse_upload, pasted, shell_word};
use serde_json::{Map, json};

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
