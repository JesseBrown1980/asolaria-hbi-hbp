use asolaria_hbi_hbp::*;

#[test]
fn sha256_known_answer_tests() {
    // FIPS/standard KATs — prove the pure-Rust sha256 is correct.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"The quick brown fox jumps over the lazy dog"),
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    );
    // multi-block (>64 bytes) exercises the chunk loop + padding
    let long = "a".repeat(1000);
    assert_eq!(
        sha256_hex(long.as_bytes()),
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
    );
}

#[test]
fn agt_is_stable_deterministic_and_20_chars() {
    assert_eq!(agt(b"hello"), agt(b"hello"));
    assert_ne!(agt(b"hello"), agt(b"world"));
    assert_eq!(agt(b"hello").len(), 20);
    assert!(agt(b"hello").starts_with("AGT-"));
}

#[test]
fn row_roundtrips_even_with_delimiters_in_values() {
    // value carries a pipe, an equals, and a newline — the escaping must survive
    let row = encode_row(
        "BOOTHOST",
        &[("order", "1"), ("name", "bus"), ("note", "a|b=c\nd")],
    );
    assert!(row.ends_with("|json=0"));
    let (tag, fields) = parse_row(&row);
    assert_eq!(tag, "BOOTHOST");
    let get = |k: &str| {
        fields
            .iter()
            .find(|(fk, _)| fk == k)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("order").as_deref(), Some("1"));
    assert_eq!(get("name").as_deref(), Some("bus"));
    assert_eq!(get("note").as_deref(), Some("a|b=c\nd")); // fully recovered
    assert_eq!(get("json").as_deref(), Some("0")); // hot-path marker present
}

#[test]
fn idx_pointer_encodes_hot_path() {
    let p = IdxPointer {
        pid: agt(b"slice-content"),
        off: 4096,
        len: 128,
    };
    let row = p.encode();
    assert!(row.starts_with("IDX|pid=AGT-"));
    assert!(row.contains("|off=4096|"));
    assert!(row.contains("|len=128|"));
    assert!(row.ends_with("|json=0"));
}

#[test]
fn receipt_chain_seals_verifies_and_detects_tamper() {
    let mut chain = ReceiptChain::new();
    let r1 = chain.append(&encode_row("EVT", &[("n", "1")]));
    let r2 = chain.append(&encode_row("EVT", &[("n", "2")]));
    let r3 = chain.append(&encode_row("EVT", &[("n", "3")]));
    assert!(r1.contains("|prev_event_hash="));
    assert!(r1.contains("|event_hash="));
    let receipts = vec![r1.clone(), r2, r3];
    assert!(verify_chain(&receipts), "a clean chain must verify");
    // tamper the first receipt's body (recompute NOT done) -> chain must reject
    let mut tampered = receipts.clone();
    tampered[0] = r1.replace("n=1", "n=9");
    assert!(!verify_chain(&tampered), "a tampered chain must fail");
}
