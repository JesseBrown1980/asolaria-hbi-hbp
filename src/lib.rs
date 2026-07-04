//! Asolaria HBI/HBP bridge codec — the canonical machine-to-machine wire format.
//!
//! HOT PATH, `json=0`. This is the substrate Asolaria and any colony (e.g. Simplicio)
//! use to talk machine-to-machine: pipe-delimited tuple rows, sha256 content-addressing
//! (`AGT-<sha16>`), byte-offset index pointers (`.hbi`), and hash-chained receipts.
//! ZERO external crates (pure `std` + a pure-Rust sha256) so it builds on any toolchain,
//! no_std-portable in spirit, and never pulls a JSON dependency. JSON/TOON are COLD lanes
//! (LLM-context export only) and deliberately absent here.

// ---------------------------------------------------------------------------
// sha256 — pure Rust (FIPS 180-4), no deps. Verified against KATs in the tests.
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Raw sha256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(big_s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = big_s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// Lowercase hex sha256 (64 chars).
pub fn sha256_hex(data: &[u8]) -> String {
    let d = sha256(data);
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Content address: `AGT-` + the first 16 hex chars of sha256(content). 20 chars total.
pub fn agt(content: &[u8]) -> String {
    let mut s = String::from("AGT-");
    s.push_str(&sha256_hex(content)[..16]);
    s
}

// ---------------------------------------------------------------------------
// HBP tuple rows — TAG|k=v|...|json=0
// ---------------------------------------------------------------------------

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\").replace('|', "\\p").replace('\n', "\\n")
}
fn unesc(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('\\') => out.push('\\'),
                Some('p') => out.push('|'),
                Some('n') => out.push('\n'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Encode one HOT-PATH row: `TAG|k=v|...|json=0`. Values are escaped; keys must be bare.
pub fn encode_row(tag: &str, fields: &[(&str, &str)]) -> String {
    let mut s = String::from(tag);
    for (k, v) in fields {
        s.push('|');
        s.push_str(k);
        s.push('=');
        s.push_str(&esc(v));
    }
    s.push_str("|json=0");
    s
}

/// Parse a row back into (tag, fields). The trailing `json=0` marker is kept as a field.
/// Splitting is on UNescaped `|`; each field splits on its FIRST `=` (values may contain `=`).
pub fn parse_row(row: &str) -> (String, Vec<(String, String)>) {
    // split on unescaped '|'
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = row.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push('\\');
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c == '|' {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    let tag = parts.first().cloned().unwrap_or_default();
    let mut fields = Vec::new();
    for p in parts.iter().skip(1) {
        if let Some(eq) = p.find('=') {
            fields.push((p[..eq].to_string(), unesc(&p[eq + 1..])));
        } else if !p.is_empty() {
            fields.push((p.clone(), String::new()));
        }
    }
    (tag, fields)
}

// ---------------------------------------------------------------------------
// .hbi index pointer — IDX|pid=..|off=..|len=..|json=0
// ---------------------------------------------------------------------------

/// A byte-offset pointer into an .hbp blob (the `.hbi` sidecar row shape).
pub struct IdxPointer {
    pub pid: String,
    pub off: u64,
    pub len: u64,
}
impl IdxPointer {
    pub fn encode(&self) -> String {
        encode_row(
            "IDX",
            &[
                ("pid", &self.pid),
                ("off", &self.off.to_string()),
                ("len", &self.len.to_string()),
            ],
        )
    }
}

// ---------------------------------------------------------------------------
// Hash-chained receipts — the append-only evidence ledger, HBP-native.
// event_hash = sha256(row + "|prev_event_hash=" + prev). Genesis prev = 64 zeros.
// ---------------------------------------------------------------------------

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// An append-only, tamper-evident receipt chain over HBP rows.
pub struct ReceiptChain {
    prev: String,
}
impl Default for ReceiptChain {
    fn default() -> Self {
        Self::new()
    }
}
impl ReceiptChain {
    pub fn new() -> Self {
        Self { prev: GENESIS.to_string() }
    }
    /// Seal `row` into a receipt: appends prev_event_hash + event_hash. Returns the receipt row.
    pub fn append(&mut self, row: &str) -> String {
        let body = format!("{row}|prev_event_hash={}", self.prev);
        let eh = sha256_hex(body.as_bytes());
        self.prev = eh.clone();
        format!("{body}|event_hash={eh}")
    }
    /// The current chain head (last event_hash).
    pub fn head(&self) -> &str {
        &self.prev
    }
}

/// Verify a full chain of receipt rows: each event_hash must equal sha256 of everything
/// before `|event_hash=`, and each prev_event_hash must equal the previous row's event_hash.
pub fn verify_chain(receipts: &[String]) -> bool {
    let mut prev = GENESIS.to_string();
    for r in receipts {
        let marker = "|event_hash=";
        let Some(pos) = r.rfind(marker) else { return false };
        let body = &r[..pos];
        let claimed = &r[pos + marker.len()..];
        if sha256_hex(body.as_bytes()) != claimed {
            return false;
        }
        // the body must carry the correct prev
        let pm = "|prev_event_hash=";
        let Some(pp) = body.rfind(pm) else { return false };
        if &body[pp + pm.len()..] != prev {
            return false;
        }
        prev = claimed.to_string();
    }
    true
}
