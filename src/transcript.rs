//! Fiat-Shamir transcript accumulator.
//!
//! Used to derive verifier challenges deterministically from a prover's
//! commitments. Every absorb call is domain-separated by its label so the order
//! of absorptions is part of the transcript's identity — reordering a commitment
//! produces a different challenge. The underlying primitive is [`crate::Sha256`].

use crate::{sha256, Hash, Sha256};

/// A rolling domain-separated hash accumulator.
///
/// # Example (non-doc)
/// ```ignore
/// let mut t = Transcript::new(b"omyra/proof/v1");
/// t.absorb(b"model",  b"sha256-of-model");
/// t.absorb(b"input",  b"sha256-of-input");
/// let challenge = t.challenge_hash(b"beta");
/// ```
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    /// Start a new transcript with a domain-separation label.
    pub fn new(domain: &[u8]) -> Self {
        Transcript {
            state: sha256(domain),
        }
    }

    /// Absorb a labeled field. The label prevents two fields of the same value
    /// but different semantic roles from colliding.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
        let mut h = Sha256::new();
        h.update(&self.state);
        h.update(&(label.len() as u64).to_le_bytes());
        h.update(label);
        h.update(&(data.len() as u64).to_le_bytes());
        h.update(data);
        self.state = h.finalize();
    }

    /// Derive a 256-bit challenge hash labeled `label`. Does not mutate the
    /// transcript — the same transcript can issue multiple independent challenges.
    pub fn challenge_hash(&self, label: &[u8]) -> Hash {
        let mut h = Sha256::new();
        h.update(b"omyra/transcript/challenge");
        h.update(&self.state);
        h.update(&(label.len() as u64).to_le_bytes());
        h.update(label);
        Hash(h.finalize())
    }

    /// Derive `n` challenge bytes (XOF-style via counter mode).
    pub fn challenge_bytes(&self, label: &[u8], n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut counter: u64 = 0;
        while out.len() < n {
            let mut h = Sha256::new();
            h.update(b"omyra/transcript/xof");
            h.update(&self.state);
            h.update(&(label.len() as u64).to_le_bytes());
            h.update(label);
            h.update(&counter.to_le_bytes());
            out.extend_from_slice(&h.finalize());
            counter += 1;
        }
        out.truncate(n);
        out
    }

    /// Current state as a [`Hash`] — useful as a commitment to the transcript
    /// before issuing challenges.
    pub fn state(&self) -> Hash {
        Hash(self.state)
    }
}

/// Convenience: build a transcript for an inference receipt's public inputs.
/// Both the prover (node) and verifier must call this in the same order.
pub fn receipt_transcript(
    model_hash: &Hash,
    input_hash: &Hash,
    output_hash: &Hash,
    attestation_hash: &Hash,
) -> Transcript {
    let mut t = Transcript::new(b"omyra/receipt/v1");
    t.absorb(b"model",       &model_hash.0);
    t.absorb(b"input",       &input_hash.0);
    t.absorb(b"output",      &output_hash.0);
    t.absorb(b"attestation", &attestation_hash.0);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_matters() {
        let mut t1 = Transcript::new(b"test");
        t1.absorb(b"a", b"1");
        t1.absorb(b"b", b"2");

        let mut t2 = Transcript::new(b"test");
        t2.absorb(b"b", b"2");
        t2.absorb(b"a", b"1");

        assert_ne!(t1.challenge_hash(b"x"), t2.challenge_hash(b"x"));
    }

    #[test]
    fn same_absorbs_give_same_challenge() {
        let mut t1 = Transcript::new(b"omyra");
        t1.absorb(b"m", b"model");
        t1.absorb(b"i", b"input");
        let c1 = t1.challenge_hash(b"beta");

        let mut t2 = Transcript::new(b"omyra");
        t2.absorb(b"m", b"model");
        t2.absorb(b"i", b"input");
        let c2 = t2.challenge_hash(b"beta");

        assert_eq!(c1, c2);
    }

    #[test]
    fn challenge_bytes_length() {
        let t = Transcript::new(b"test");
        assert_eq!(t.challenge_bytes(b"r", 100).len(), 100);
        assert_eq!(t.challenge_bytes(b"r", 1).len(), 1);
    }

    #[test]
    fn label_collisions_dont_happen() {
        let mut ta = Transcript::new(b"test");
        ta.absorb(b"alpha", b"v");
        let mut tb = Transcript::new(b"test");
        tb.absorb(b"beta", b"v");
        assert_ne!(ta.challenge_hash(b"q"), tb.challenge_hash(b"q"));
    }
}
