//! Public key tokens of strong names (ECMA-335 II.6.2.1.3): the last 8
//! bytes of the SHA-1 hash of the public key, in reverse order.

/// Returns the public key token of a public key blob.
#[must_use]
pub fn public_key_token(public_key: &[u8]) -> [u8; 8] {
    let hash = sha1(public_key);
    let mut token = [0; 8];
    for (slot, &byte) in token.iter_mut().zip(hash.iter().rev()) {
        *slot = byte;
    }
    token
}

/// Returns the SHA-1 hash of `data` (FIPS 180-4).
#[must_use]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let (blocks, rest) = data.as_chunks::<64>();
    for block in blocks {
        compress(&mut state, block);
    }
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].as_chunks::<64>().0 {
        compress(&mut state, block);
    }
    let mut out = [0; 20];
    for (slot, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *slot = word.to_be_bytes();
    }
    out
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut schedule = [0u32; 80];
    for (slot, bytes) in schedule.iter_mut().zip(block.as_chunks::<4>().0) {
        *slot = u32::from_be_bytes(*bytes);
    }
    for round in 16..80 {
        schedule[round] = (schedule[round - 3]
            ^ schedule[round - 8]
            ^ schedule[round - 14]
            ^ schedule[round - 16])
            .rotate_left(1);
    }
    // The working variables a, b, c, d and e of FIPS 180-4.
    let mut v = *state;
    for (round, &word) in schedule.iter().enumerate() {
        let (mix, constant) = match round {
            0..20 => ((v[1] & v[2]) | (!v[1] & v[3]), 0x5A82_7999),
            20..40 => (v[1] ^ v[2] ^ v[3], 0x6ED9_EBA1),
            40..60 => ((v[1] & v[2]) | (v[1] & v[3]) | (v[2] & v[3]), 0x8F1B_BCDC),
            _ => (v[1] ^ v[2] ^ v[3], 0xCA62_C1D6),
        };
        let next = v[0]
            .rotate_left(5)
            .wrapping_add(mix)
            .wrapping_add(v[4])
            .wrapping_add(constant)
            .wrapping_add(word);
        v = [next, v[0], v[1].rotate_left(30), v[2], v[3]];
    }
    for (slot, value) in state.iter_mut().zip(v) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        bytes.iter().fold(alloc::string::String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn sha1_matches_the_test_vectors_of_fips_180() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn the_token_of_the_ecma_key_is_b77a5c561934e089() {
        // The "ECMA key" of the standard libraries (II.6.2.1.3).
        let ecma_key = [0u8, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(hex(&public_key_token(&ecma_key)), "b77a5c561934e089");
    }
}
