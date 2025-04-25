//! STACKSAT‑128
//! -------------
//! A 256‑bit sponge hash specifically tailored for Bitcoin‐Script friendliness.
//! Only 4‑bit additions (mod 16), a 16‑entry S‑box and fixed stack shuffles are
//! required.  No XOR, rotate, multiply, CAT, etc.
//!
//! • State  : 64 × 4-bit nibbles  (256 bit)
//! • Rate   : 32 nibbles          (128 bit)
//! • Rounds : 12                  (S-box → permute → add-mix → constant)
//!
//! Only nibble-wise addition (mod 16) and a 16-entry S-box are used, mirroring
//! the operations that map cleanly to main-net Bitcoin Script (`OP_ADD`,
//! `OP_PICK`, `OP_IF`, …).  No XOR, shift, rotate or multiplication appears.
//!
//! Security target: ≥128-bit collision & pre-image resistance.
//!
//! The design is an SPN:  S‑box → row‑rotation permute → pair/cross‑row nibble
//! adds → round constants.
#![no_std]

/// PRESENT‑style 4‑bit S‑box.
const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

/// 8×8 row‑rotation permutation table (nibble indices).
const PERM: [usize; 64] = {
    let mut p = [0usize; 64];
    let mut idx = 0;
    while idx < 64 {
        let row = idx / 8;
        let col = idx % 8;
        let new_col = (col + 8 - row) % 8; // left‑rotate by `row`
        p[idx] = row * 8 + new_col;
        idx += 1;
    }
    p
};

const RATE: usize = 32; // 128‑bit
const STATE: usize = 64; // 256‑bit
const ROUNDS: usize = 16;

/// Add two 4‑bit values modulo 16.
#[inline(always)]
fn add16(a: u8, b: u8) -> u8 {
    (a + b) & 0xF
}

/// 4‑bit round‑constant sequence (x⁴ + x + 1 LFSR).
const RC: [u8; ROUNDS] = {
    let mut rc = [0u8; ROUNDS];
    let mut v = 1u8;
    let mut i = 0;
    while i < ROUNDS {
        rc[i] = v;
        // LFSR feedback: x⁴ + x + 1  ⇒ feedback = v₃ ⊕ v₀ of previous v
        let fb = ((v >> 3) ^ (v & 1)) & 1;
        v = ((v << 1) & 0xF) | fb;
        i += 1;
    }
    rc
};

/// Apply one round to the internal 64‑nibble state.
fn round(st: &mut [u8; STATE], r: usize) {
    // --- 1. S‑box ---------------------------------------------------------
    for b in st.iter_mut() {
        *b = SBOX[*b as usize];
    }

    // --- 2. Permutation (row rotate) -------------------------------------
    let tmp = *st;
    for (d, &s) in st.iter_mut().zip(PERM.iter()) {
        *d = tmp[s];
    }

    // --- 3. Pair‑wise nibble add (carry‑based diffusion) -----------------
    if r & 1 == 0 {
        for i in (0..STATE).step_by(2) {
            st[i] = add16(st[i], st[i + 1]);
        }
    } else {
        for i in (1..STATE).step_by(2) {
            st[i] = add16(st[i], st[i - 1]);
        }
    }

    // --- 4. Cross‑row add: rows 0–3 feed rows 4–7 ------------------------
    for col in 0..8 {
        let upper = 32 + col; // row 4..7 block starts at 32
        st[upper] = add16(st[upper], st[col]);
    }

    // --- 5. Round constants (position‑varying) ---------------------------
    let c = RC[r];
    for (i, b) in st.iter_mut().enumerate() {
        *b = add16(*b, (c + (i as u8 & 0xF)) & 0xF);
    }
}

/// Multi‑rate padding: append 1, zeros, then 1.
fn pad(mut nibbles: heapless::Vec<u8, 512>) -> heapless::Vec<u8, 512> {
    nibbles.push(0x8).ok(); // "1" bit in high position
    while (nibbles.len() % RATE) != RATE - 1 {
        nibbles.push(0x0).ok();
    }
    nibbles.push(0x1).ok(); // final "1" terminator
    nibbles
}

/// Compute STACKSAT‑128 hash of input; returns 32‑byte digest.
pub fn stacksat_hash(msg: &[u8]) -> [u8; 32] {
    // --- 1.  message → nibble vector ------------------------------------
    let mut v = heapless::Vec::<u8, 512>::new();
    for &b in msg {
        v.push(b >> 4).ok();
        v.push(b & 0xF).ok();
    }
    let nibbles = pad(v);

    // --- 2.  initialise state -------------------------------------------
    let mut st = [0u8; STATE];

    // --- 3.  absorb ------------------------------------------------------
    let mut idx = 0;
    while idx < nibbles.len() {
        for j in 0..RATE {
            st[j] = add16(st[j], nibbles[idx + j]);
        }
        idx += RATE;
        for r in 0..ROUNDS {
            round(&mut st, r);
        }
    }

    // --- 4.  final permutation ------------------------------------------
    for r in 0..ROUNDS {
        round(&mut st, r);
    }

    // --- 5.  squeeze 256‑bit digest -------------------------------------
    let mut out = [0u8; 32];
    for (i, pair) in (0..STATE).step_by(2).enumerate() {
        out[i] = (st[pair] << 4) | st[pair + 1];
    }
    out
}

// -----------------------------------------------------------------------
//  TESTS
// -----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(
            hex::encode(stacksat_hash(b"")),
            "b515acc06d0641a4e9ce74f1eaa83cda1e096614c068c201806c1fa96803cdfd"
        );
        assert_eq!(
            hex::encode(stacksat_hash(b"abc")),
            "20acba146d0641a4e9ce74f1eaa83cdab469724ec068c201806c1fa96803cdfd"
        );
    }

    #[test]
    fn avalanche() {
        let h1 = stacksat_hash(b"hello world");
        let h2 = stacksat_hash(b"hello worle"); // flip one bit (d→e)
        let diff = h1
            .iter()
            .zip(h2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();
        // Expect roughly half of 256 bits to differ
        assert!(diff > 90 && diff < 170, "avalanche weak: {diff}");
    }
}
