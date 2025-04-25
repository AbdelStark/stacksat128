// SPDX-License-Identifier: MIT
//! STACKSAT-128 — a 256-bit sponge hash purpose-built for Bitcoin Script
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

#![no_std]

/// 4-bit PRESENT-style S-box  (hex values).
const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

/// Pre-computed nibble permutation (8×8 state, each row rotated `row` steps).
const PERM: [usize; 64] = {
    let mut p = [0usize; 64];
    let mut i = 0;
    while i < 64 {
        // row & col
        let row = i / 8;
        let col = i % 8;
        let new_col = (col + 8 - row) % 8; // left-rotate each row by `row`
        p[i] = row * 8 + new_col;
        i += 1;
    }
    p
};

const RATE_NIBBLES: usize = 32; // 128 bit
const STATE_NIBBLES: usize = 64; // 256 bit
const N_ROUNDS: usize = 12;

/// Add two nibbles mod 16.
#[inline(always)]
fn add16(a: u8, b: u8) -> u8 {
    (a + b) & 0xF
}

/// Apply one internal round (non-linear + diffusion).
fn round(state: &mut [u8; STATE_NIBBLES], r: usize) {
    // --- Substitution ------------------------------------------------------
    for x in state.iter_mut() {
        *x = SBOX[*x as usize];
    }

    // --- Permutation -------------------------------------------------------
    let tmp = *state;
    for (dst, &src_idx) in state.iter_mut().zip(PERM.iter()) {
        *dst = tmp[src_idx];
    }

    // --- Pair-wise add-mix --------------------------------------------------
    if r & 1 == 0 {
        // even rounds: add even ← odd
        for i in (0..STATE_NIBBLES).step_by(2) {
            state[i] = add16(state[i], state[i + 1]);
        }
    } else {
        // odd rounds: add odd ← even
        for i in (1..STATE_NIBBLES).step_by(2) {
            state[i] = add16(state[i], state[i - 1]);
        }
    }

    // --- Round constant -----------------------------------------------------
    state[STATE_NIBBLES - 1] = add16(state[STATE_NIBBLES - 1], ((r + 1) & 0xF) as u8);
}

/// Pad message nibbles with 10*1 multi-rate padding.
fn pad(mut nibbles: heapless::Vec<u8, 512>) -> heapless::Vec<u8, 512> {
    nibbles.push(0x8).ok();
    while (nibbles.len() % RATE_NIBBLES) != RATE_NIBBLES - 1 {
        nibbles.push(0x0).ok();
    }
    nibbles.push(0x1).ok();
    nibbles
}

/// Hash the input and return 32-byte digest.
pub fn stacksat_hash(data: &[u8]) -> [u8; 32] {
    // --- 1.  message → nibble vector ---------------------------------------
    let mut msg = heapless::Vec::<u8, 512>::new(); // supports < 256 byte msg
    for &b in data {
        msg.push(b >> 4).ok();
        msg.push(b & 0xF).ok();
    }
    let nibbles = pad(msg);

    // --- 2.  initialise 256-bit state to zero ------------------------------
    let mut st = [0u8; STATE_NIBBLES];

    // --- 3.  absorb blocks --------------------------------------------------
    for chunk in nibbles.chunks(RATE_NIBBLES) {
        for (s, &m) in st[..RATE_NIBBLES].iter_mut().zip(chunk) {
            *s = add16(*s, m);
        }
        for r in 0..N_ROUNDS {
            round(&mut st, r);
        }
    }

    // --- 4.  final permutation ---------------------------------------------
    for r in 0..N_ROUNDS {
        round(&mut st, r);
    }

    // --- 5.  squeeze 256-bit output ----------------------------------------
    let mut out = [0u8; 32];
    for (i, pair) in (0..STATE_NIBBLES).step_by(2).enumerate() {
        out[i] = (st[pair] << 4) | st[pair + 1];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::stacksat_hash;

    #[test]
    fn vectors() {
        let empty_string = b"";
        let abc = b"abc";
        // Empty string
        assert_eq!(
            hex::encode(stacksat_hash(empty_string)),
            "0e5252529c9c9c9c525252529c9c9c9a525252529c9c9c9c5252525289a89c09"
        );
        // \"abc\"
        assert_eq!(
            hex::encode(stacksat_hash(abc)),
            "6830810e9c9c9c9c525252529c9c9c9a525252529c9c9c9c5252525289a89c09"
        );
    }
}
