//! Provider and user identity management.
//!
//! [`WalletKeypair`] wraps an Ed25519 seed and exposes sign / verify / derive
//! helpers. Used by every node that emits signed receipts or reputation metrics.

use crate::{
    ed25519_public_key, ed25519_sign, ed25519_verify, hkdf_sha256, Ed25519Sig, Hash, WalletPubkey,
};

/// An Ed25519 keypair held as a 32-byte seed (private) + cached public key.
#[derive(Clone)]
pub struct WalletKeypair {
    seed: [u8; 32],
    pubkey: WalletPubkey,
}

impl WalletKeypair {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let pubkey = WalletPubkey(ed25519_public_key(&seed));
        WalletKeypair { seed, pubkey }
    }

    pub fn pubkey(&self) -> &WalletPubkey {
        &self.pubkey
    }

    /// Derive a child keypair for a sub-role (e.g. "vault", "mesh") via HKDF.
    pub fn derive_child(&self, label: &[u8]) -> Self {
        let child_seed_vec = hkdf_sha256(b"omyra/keypair/derive", &self.seed, label, 32);
        let mut child_seed = [0u8; 32];
        child_seed.copy_from_slice(&child_seed_vec);
        Self::from_seed(child_seed)
    }

    pub fn sign(&self, msg: &[u8]) -> Ed25519Sig {
        Ed25519Sig(ed25519_sign(&self.seed, msg))
    }

    pub fn verify(&self, msg: &[u8], sig: &Ed25519Sig) -> bool {
        ed25519_verify(&self.pubkey.0, msg, &sig.0)
    }

    /// Sign a [`Hash`] directly (most receipts / metrics sign their proof hash).
    pub fn sign_hash(&self, h: &Hash) -> Ed25519Sig {
        self.sign(&h.0)
    }
}

/// A signed message binding a payload to a signer pubkey.
#[derive(Clone, Debug)]
pub struct SignedMessage {
    pub payload: Vec<u8>,
    pub signer: WalletPubkey,
    pub sig: Ed25519Sig,
}

impl SignedMessage {
    pub fn sign(keypair: &WalletKeypair, payload: Vec<u8>) -> Self {
        let sig = keypair.sign(&payload);
        SignedMessage {
            sig,
            signer: *keypair.pubkey(),
            payload,
        }
    }

    /// Returns `true` if the signature is valid and the signer matches `expected`.
    pub fn verify_from(&self, expected: &WalletPubkey) -> bool {
        self.signer == *expected
            && ed25519_verify(&self.signer.0, &self.payload, &self.sig.0)
    }

    pub fn verify_any(&self) -> bool {
        ed25519_verify(&self.signer.0, &self.payload, &self.sig.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_produces_distinct_children() {
        let kp = WalletKeypair::from_seed([1u8; 32]);
        let v = kp.derive_child(b"vault");
        let m = kp.derive_child(b"mesh");
        assert_ne!(v.pubkey(), m.pubkey());
        assert_ne!(v.pubkey(), kp.pubkey());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = WalletKeypair::from_seed([5u8; 32]);
        let msg = b"omyra provider attestation";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
        // tampered msg fails
        assert!(!kp.verify(b"tampered", &sig));
    }

    #[test]
    fn signed_message_verify() {
        let kp = WalletKeypair::from_seed([9u8; 32]);
        let sm = SignedMessage::sign(&kp, b"reputation metrics".to_vec());
        assert!(sm.verify_from(kp.pubkey()));
        assert!(sm.verify_any());
        // wrong expected key
        let other = WalletKeypair::from_seed([10u8; 32]);
        assert!(!sm.verify_from(other.pubkey()));
    }
}
