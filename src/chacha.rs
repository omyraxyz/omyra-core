//! ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! Clean-room, `std`-only, constant-time tag compare. Validated against the
//! RFC 8439 test vectors below. Production can swap the audited
//! `chacha20poly1305` crate behind the [`crate::Aead`] trait.

use crate::Aead;

// ---- ChaCha20 ---------------------------------------------------------------

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// One 64-byte ChaCha20 keystream block.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = le32(&key[i * 4..]);
    }
    s[12] = counter;
    s[13] = le32(&nonce[0..]);
    s[14] = le32(&nonce[4..]);
    s[15] = le32(&nonce[8..]);

    let mut w = s;
    for _ in 0..10 {
        // column rounds
        quarter_round(&mut w, 0, 4, 8, 12);
        quarter_round(&mut w, 1, 5, 9, 13);
        quarter_round(&mut w, 2, 6, 10, 14);
        quarter_round(&mut w, 3, 7, 11, 15);
        // diagonal rounds
        quarter_round(&mut w, 0, 5, 10, 15);
        quarter_round(&mut w, 1, 6, 11, 12);
        quarter_round(&mut w, 2, 7, 8, 13);
        quarter_round(&mut w, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = w[i].wrapping_add(s[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// XOR `data` with the ChaCha20 keystream starting at `counter`.
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut ctr = counter;
    for chunk in data.chunks(64) {
        let ks = chacha20_block(key, ctr, nonce);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        ctr = ctr.wrapping_add(1);
    }
    out
}

// ---- Poly1305 (poly1305-donna, 32-bit limbs) --------------------------------

/// Poly1305 one-time MAC (RFC 8439 §2.5).
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // clamp r
    let r0 = le32(&key[0..]) & 0x03ff_ffff;
    let r1 = (le32(&key[3..]) >> 2) & 0x03ff_ff03;
    let r2 = (le32(&key[6..]) >> 4) & 0x03ff_c0ff;
    let r3 = (le32(&key[9..]) >> 6) & 0x03f0_3fff;
    let r4 = (le32(&key[12..]) >> 8) & 0x000f_ffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);

    let process = |b: &[u8; 16], hibit: u32, h: &mut [u32; 5]| {
        h[0] = h[0].wrapping_add(le32(&b[0..]) & 0x03ff_ffff);
        h[1] = h[1].wrapping_add((le32(&b[3..]) >> 2) & 0x03ff_ffff);
        h[2] = h[2].wrapping_add((le32(&b[6..]) >> 4) & 0x03ff_ffff);
        h[3] = h[3].wrapping_add((le32(&b[9..]) >> 6) & 0x03ff_ffff);
        h[4] = h[4].wrapping_add((le32(&b[12..]) >> 8) | hibit);

        let d0 = h[0] as u64 * r0 as u64
            + h[1] as u64 * s4 as u64
            + h[2] as u64 * s3 as u64
            + h[3] as u64 * s2 as u64
            + h[4] as u64 * s1 as u64;
        let mut d1 = h[0] as u64 * r1 as u64
            + h[1] as u64 * r0 as u64
            + h[2] as u64 * s4 as u64
            + h[3] as u64 * s3 as u64
            + h[4] as u64 * s2 as u64;
        let mut d2 = h[0] as u64 * r2 as u64
            + h[1] as u64 * r1 as u64
            + h[2] as u64 * r0 as u64
            + h[3] as u64 * s4 as u64
            + h[4] as u64 * s3 as u64;
        let mut d3 = h[0] as u64 * r3 as u64
            + h[1] as u64 * r2 as u64
            + h[2] as u64 * r1 as u64
            + h[3] as u64 * r0 as u64
            + h[4] as u64 * s4 as u64;
        let mut d4 = h[0] as u64 * r4 as u64
            + h[1] as u64 * r3 as u64
            + h[2] as u64 * r2 as u64
            + h[3] as u64 * r1 as u64
            + h[4] as u64 * r0 as u64;

        let mut c: u64 = d0 >> 26;
        h[0] = (d0 as u32) & 0x03ff_ffff;
        d1 += c;
        c = d1 >> 26;
        h[1] = (d1 as u32) & 0x03ff_ffff;
        d2 += c;
        c = d2 >> 26;
        h[2] = (d2 as u32) & 0x03ff_ffff;
        d3 += c;
        c = d3 >> 26;
        h[3] = (d3 as u32) & 0x03ff_ffff;
        d4 += c;
        c = d4 >> 26;
        h[4] = (d4 as u32) & 0x03ff_ffff;
        let h0_64 = h[0] as u64 + c * 5;
        h[0] = (h0_64 as u32) & 0x03ff_ffff;
        h[1] = h[1].wrapping_add((h0_64 >> 26) as u32);
    };

    let mut h = [h0, h1, h2, h3, h4];
    let mut chunks = msg.chunks_exact(16);
    for chunk in chunks.by_ref() {
        let mut b = [0u8; 16];
        b.copy_from_slice(chunk);
        process(&b, 1 << 24, &mut h);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut b = [0u8; 16];
        b[..rem.len()].copy_from_slice(rem);
        b[rem.len()] = 1;
        process(&b, 0, &mut h);
    }
    h0 = h[0];
    h1 = h[1];
    h2 = h[2];
    h3 = h[3];
    h4 = h[4];

    // final carry
    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 = h2.wrapping_add(c);
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 = h3.wrapping_add(c);
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 = h4.wrapping_add(c);
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 = h0.wrapping_add(c * 5);
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 = h1.wrapping_add(c);

    // compute h + -p (i.e. h + 5) and conditionally use it
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 31).wrapping_sub(1); // all-ones if g4 >= 0 (use g)
    h0 = (h0 & !mask) | (g0 & mask);
    h1 = (h1 & !mask) | (g1 & mask);
    h2 = (h2 & !mask) | (g2 & mask);
    h3 = (h3 & !mask) | (g3 & mask);
    h4 = (h4 & !mask) | (g4 & mask);

    // serialize 130-bit h into four 32-bit words (mask the limb overlap bits —
    // they belong to the next word, not a carry)
    let f0 = ((h0 as u64) | ((h1 as u64) << 26)) & 0xffff_ffff;
    let f1 = (((h1 as u64) >> 6) | ((h2 as u64) << 20)) & 0xffff_ffff;
    let f2 = (((h2 as u64) >> 12) | ((h3 as u64) << 14)) & 0xffff_ffff;
    let f3 = (((h3 as u64) >> 18) | ((h4 as u64) << 8)) & 0xffff_ffff;

    // add the key's second half (s)
    let mut tag = [0u8; 16];
    let mut carry = 0u64;
    for (i, f) in [f0, f1, f2, f3].into_iter().enumerate() {
        let val = f + le32(&key[16 + i * 4..]) as u64 + carry;
        tag[i * 4..i * 4 + 4].copy_from_slice(&(val as u32).to_le_bytes());
        carry = val >> 32;
    }
    tag
}

// ---- AEAD construction (RFC 8439 §2.8) --------------------------------------

fn pad16(v: &mut Vec<u8>) {
    let rem = v.len() % 16;
    if rem != 0 {
        v.resize(v.len() + (16 - rem), 0);
    }
}

fn poly1305_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[..32]);
    otk
}

fn tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let otk = poly1305_key(key, nonce);
    let mut mac_data = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    mac_data.extend_from_slice(aad);
    pad16(&mut mac_data);
    mac_data.extend_from_slice(ciphertext);
    pad16(&mut mac_data);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305(&otk, &mac_data)
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// ChaCha20-Poly1305 (IETF, 96-bit nonce). Output of [`Aead::seal`] is
/// `ciphertext || 16-byte tag`; [`Aead::open`] verifies the tag in constant time
/// before returning plaintext.
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Seal with additional authenticated data.
    pub fn seal_aad(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut ct = chacha20_xor(key, nonce, 1, plaintext);
        let t = tag(key, nonce, aad, &ct);
        ct.extend_from_slice(&t);
        ct
    }

    /// Open with additional authenticated data.
    pub fn open_aad(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        if sealed.len() < 16 {
            return None;
        }
        let (ct, t) = sealed.split_at(sealed.len() - 16);
        let expected = tag(key, nonce, aad, ct);
        if !ct_eq(&expected, t) {
            return None;
        }
        Some(chacha20_xor(key, nonce, 1, ct))
    }
}

impl Aead for ChaCha20Poly1305 {
    fn seal(&self, key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        Self::seal_aad(key, nonce, &[], plaintext)
    }
    fn open(&self, key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
        Self::open_aad(key, nonce, &[], ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn chacha20_keystream_is_deterministic_and_reversible() {
        // ChaCha20 correctness itself is pinned by the RFC 8439 §2.8.2 AEAD KAT
        // below (full canonical ciphertext + tag). Here we just assert the
        // stream cipher's structural properties.
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let data = b"private inference payload";
        let ct = chacha20_xor(&key, &nonce, 1, data);
        assert_ne!(&ct[..], &data[..]);
        assert_eq!(chacha20_xor(&key, &nonce, 1, &ct), data);
        // counter advances the keystream
        assert_ne!(chacha20_block(&key, 0, &nonce), chacha20_block(&key, 1, &nonce));
    }

    #[test]
    fn poly1305_rfc8439_2_5_2() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn aead_roundtrips_and_detects_tampering() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];
        let msg = b"sovereign memory entry";
        let mut sealed = ChaCha20Poly1305.seal(&key, &nonce, msg);
        assert_eq!(ChaCha20Poly1305.open(&key, &nonce, &sealed).unwrap(), msg);

        // flip a ciphertext byte → authentication must fail
        sealed[0] ^= 1;
        assert!(ChaCha20Poly1305.open(&key, &nonce, &sealed).is_none());
    }

    #[test]
    fn aead_rfc8439_2_8_2_tag() {
        // Full AEAD vector: validates chacha20 (counter=1), poly key-gen
        // (counter=0), AAD padding, and the Poly1305 tag end-to-end.
        let key: [u8; 32] = (0x80u8..0xa0).collect::<Vec<u8>>().try_into().unwrap();
        let nonce = [0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = ChaCha20Poly1305::seal_aad(&key, &nonce, &aad, plaintext);
        let (ct, t) = sealed.split_at(sealed.len() - 16);
        assert_eq!(
            hex(ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex(t), "1ae10b594f09e26a7e902ecbd0600691");
    }
}
