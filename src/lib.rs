//! Shared primitives for the Omyra utility stack.
//!
//! Every other crate depends on this one and nothing else cross-depends. Kept
//! `std`-only on purpose so the whole workspace builds offline — including the
//! cryptography, which is real (not placeholder):
//!
//! * [`Hash`] is SHA-256 (FIPS 180-4).
//! * [`ChaCha20Poly1305`] is the RFC 8439 AEAD, constant-time tag compare.
//! * [`derive_key`] is HKDF-SHA256 (RFC 5869).
//!
//! Each is a clean-room implementation checked against published test vectors
//! (see the `sha256`/`chacha` modules). Production may swap the audited
//! `sha2` / `chacha20poly1305` / `hkdf` crates behind these same types.
#![forbid(unsafe_code)]

use std::fmt;

mod chacha;
mod ed25519;
pub mod keypair;
mod sha256;
mod sha512;
pub mod transcript;

pub use chacha::{
    chacha20_block, chacha20_xor, ct_eq, poly1305, ChaCha20Poly1305,
};
pub use ed25519::{
    public_key as ed25519_public_key, sign as ed25519_sign, verify as ed25519_verify,
};
pub use sha256::{hkdf_sha256, hmac_sha256, sha256, Sha256};
pub use sha512::sha512;

/// A 256-bit SHA-256 digest. Used for model/input/output hashes, commitments,
/// merkle nodes, and proof-chain links.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn zero() -> Self {
        Hash([0u8; 32])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// SHA-256 of a single byte string.
    pub fn of(data: &[u8]) -> Self {
        Hash(sha256(data))
    }

    /// Domain-separated hash over several parts (length-prefixed so
    /// `[a, b]` and `[ab]` can't collide).
    pub fn of_parts(parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        for p in parts {
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        Hash(h.finalize())
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    pub fn from_hex(s: &str) -> Option<Hash> {
        let bytes = from_hex(s)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        Some(Hash(h))
    }

    /// First 4 bytes as hex — for compact logging.
    pub fn short(&self) -> String {
        to_hex(&self.0[..4])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.short())
    }
}

/// An ed25519 public key (same key type Solana wallets use).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct WalletPubkey(pub [u8; 32]);

impl WalletPubkey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Sig(pub [u8; 64]);

impl Ed25519Sig {
    /// Placeholder signature bytes. Signing/verification is an asymmetric-key
    /// concern that lives behind the `omyra-proof` signature seam; production
    /// wires `ed25519-dalek` with the provider's key.
    pub const fn stub() -> Self {
        Ed25519Sig([0u8; 64])
    }
}

impl fmt::Debug for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Sig(..)")
    }
}

/// A half-open Solana slot window `[start, end)`. Replay protection: a proof is
/// only valid while `current_slot` is inside its window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotRange {
    pub start: u64,
    pub end: u64,
}

impl SlotRange {
    pub fn new(start: u64, end: u64) -> Self {
        SlotRange { start, end }
    }

    pub fn contains(&self, slot: u64) -> bool {
        slot >= self.start && slot < self.end
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.start.to_le_bytes());
        b[8..].copy_from_slice(&self.end.to_le_bytes());
        b
    }
}

/// A binding commitment to a value (Pedersen in production; here a hash).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Commitment(pub Hash);

/// Derive a per-entry key from a root key + index via HKDF-SHA256, so one
/// compromised entry key doesn't expose the rest of the vault.
pub fn derive_key(root: &[u8; 32], index: u64) -> [u8; 32] {
    let okm = hkdf_sha256(b"omyra/vault/v1", root, &index.to_le_bytes(), 32);
    let mut k = [0u8; 32];
    k.copy_from_slice(&okm);
    k
}

/// Authenticated encryption seam. The shipped impl is [`ChaCha20Poly1305`];
/// production may swap `aes-gcm` or the audited `chacha20poly1305` crate.
pub trait Aead {
    fn seal(&self, key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8>;
    /// Returns `None` if authentication fails.
    fn open(&self, key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// Lowercase hex encode.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Hex decode (lowercase or uppercase). `None` on odd length or non-hex.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_sha256_and_separates() {
        // matches FIPS 180-4 "abc"
        assert_eq!(
            Hash::of(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(Hash::of(b"omyra"), Hash::of(b"omyrb"));
        // length-prefixing prevents the classic concat collision
        assert_ne!(
            Hash::of_parts(&[b"ab", b"c"]),
            Hash::of_parts(&[b"a", b"bc"])
        );
        assert!(Hash::zero().is_zero());
    }

    #[test]
    fn hex_roundtrips() {
        let h = Hash::of(b"receipt");
        assert_eq!(Hash::from_hex(&h.to_hex()), Some(h));
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("abc"), None); // odd length
    }

    #[test]
    fn slot_window_is_half_open() {
        let w = SlotRange::new(10, 20);
        assert!(!w.contains(9));
        assert!(w.contains(10));
        assert!(w.contains(19));
        assert!(!w.contains(20));
    }

    #[test]
    fn aead_roundtrips() {
        let key = derive_key(&[7u8; 32], 0);
        let nonce = [1u8; 12];
        let msg = b"sealed memory entry";
        let ct = ChaCha20Poly1305.seal(&key, &nonce, msg);
        assert_ne!(&ct[..], &msg[..]);
        assert_eq!(ChaCha20Poly1305.open(&key, &nonce, &ct).unwrap(), msg);
    }
}
