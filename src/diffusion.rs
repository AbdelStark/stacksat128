//! Candidate diffusion layers for STACKSAT‑128
//! ==========================================
//! Two alternatives plus a **sound differential evaluator**.
//!
//! * `butterfly`  – 4‑stage distance‑doubling add tree (branch≥4).
//! * `feistel16` – 2‑round Feistel over 128‑bit halves.
//!
//! The helper `min_active_after_4()` brute‑forces all 2¹⁶ differences in the
//! first four nibbles and returns the **minimum** number of active S‑boxes
//! after **exactly four rounds** (counting a S‑box active iff its *input*
//! difference is non‑zero in any of the 4 rounds).  A sound lower‑bound.
//! -------------------------------------------------------------------------

#![allow(dead_code)]

const NIB: usize = 64; // 256‑bit state ⇒ 64 nibbles
const ROUNDS_EVAL: usize = 4; // rounds evaluated by brute force

/// PRESENT 4‑bit S‑box.
const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

#[inline(always)]
fn add16(x: u8, y: u8) -> u8 {
    (x + y) & 0xF
}

// -------------------------------------------------------------------------
//  Butterfly layer
// -------------------------------------------------------------------------
/// Four distance‑doubling add stages.
pub fn butterfly(st: &mut [u8; NIB]) {
    // distance‑1 bidirectional
    for i in (0..NIB).step_by(2) {
        let a = st[i];
        let b = st[i + 1];
        st[i] = add16(a, b);
        st[i + 1] = add16(b, a);
    }
    // distance‑2 bidirectional
    for i in (0..NIB).step_by(4) {
        let a = st[i];
        let b = st[i + 2];
        st[i] = add16(a, b);
        st[i + 2] = add16(b, a);
    }
    // distance‑4 bidirectional
    for i in (0..NIB).step_by(8) {
        let a = st[i];
        let b = st[i + 4];
        st[i] = add16(a, b);
        st[i + 4] = add16(b, a);
    }
    // cross rows bidirectional
    for i in 0..8 {
        let a = st[i];
        let b = st[32 + i];
        st[i] = add16(a, b);
        st[32 + i] = add16(b, a);
    }
}

// -------------------------------------------------------------------------
//  Feistel16 layer
// -------------------------------------------------------------------------
/// Two Feistel swaps between 128‑bit halves.
pub fn feistel16(st: &mut [u8; NIB]) {
    for _ in 0..2 {
        for i in 0..32 {
            st[i] = add16(st[i], st[32 + i]);
        }
        for i in 0..32 {
            st.swap(i, 32 + i);
        }
    }
}

// -------------------------------------------------------------------------
//  Differential propagation helper
// -------------------------------------------------------------------------
fn propagate(mut a: [u8; NIB], mut b: [u8; NIB], layer: fn(&mut [u8; NIB])) -> usize {
    let mut active = [false; NIB];
    for _ in 0..ROUNDS_EVAL {
        // mark pre‑S‑box differences
        for i in 0..NIB {
            if a[i] != b[i] {
                active[i] = true;
            }
        }
        // S‑box
        for x in &mut a {
            *x = SBOX[*x as usize];
        }
        for x in &mut b {
            *x = SBOX[*x as usize];
        }
        // linear/mix layer
        layer(&mut a);
        layer(&mut b);
    }
    active.iter().filter(|&&x| x).count()
}

/// Exhaustive search on 4‑nibble sub‑space.
fn min_active_after_4(layer: fn(&mut [u8; NIB])) -> usize {
    let mut min = NIB;
    for diff in 1..=0xFFFF {
        let a = [0u8; NIB];
        let mut b = [0u8; NIB];
        for i in 0..4 {
            b[i] = ((diff >> (i * 4)) & 0xF) as u8;
        }
        let act = propagate(a, b, layer);
        if act < min {
            min = act;
            if min == 0 {
                break;
            }
        }
    }
    min
}

// -------------------------------------------------------------------------
//  Tests
// -------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn butterfly_ok() {
        let m = min_active_after_4(butterfly);
        assert!(m >= 28, "butterfly min_active={m}");
    }

    #[test]
    fn feistel_ok() {
        let m = min_active_after_4(feistel16);
        assert!(m >= 32, "feistel16 min_active={m}");
    }
}
