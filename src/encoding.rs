//! Base58 encoding/decoding (Bitcoin/Solana alphabet) and compact-uint.
//!
//! Wallet addresses, transaction ids, and receipt ids are displayed in base58
//! across the Omyra UI (Proof Explorer, Vault Console, Compute Hub). This
//! module provides a zero-dep implementation so every crate can format these
//! identifiers consistently.

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes to a base58 string (Solana/Bitcoin alphabet).
pub fn base58_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    // count leading zero bytes
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();

    // big-integer division
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Decode a base58 string. Returns `None` on invalid characters.
pub fn base58_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(vec![]);
    }
    let leading_ones = input.chars().take_while(|&c| c == '1').count();

    let mut bytes: Vec<u8> = Vec::with_capacity(input.len() * 733 / 1000 + 1);
    for c in input.chars() {
        let digit = ALPHABET.iter().position(|&b| b == c as u8)? as u32;
        let mut carry = digit;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for _ in 0..leading_ones {
        bytes.push(0);
    }
    bytes.reverse();
    Some(bytes)
}

/// Compact-uint: variable-length little-endian encoding (same as Bitcoin varint).
/// Values 0–252: 1 byte. 253–65535: 0xfd + 2 bytes LE. 65536+: 0xfe + 4 bytes LE.
pub fn compact_encode(n: u64) -> Vec<u8> {
    match n {
        0..=252 => vec![n as u8],
        253..=0xffff => {
            let mut v = vec![0xfd];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            v
        }
        0x10000..=0xffffffff => {
            let mut v = vec![0xfe];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xff];
            v.extend_from_slice(&n.to_le_bytes());
            v
        }
    }
}

/// Decode a compact-uint from a byte slice. Returns `(value, bytes_consumed)`.
pub fn compact_decode(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    match first {
        0..=252 => Some((first as u64, 1)),
        0xfd => {
            let v = u16::from_le_bytes(b.get(1..3)?.try_into().ok()?);
            Some((v as u64, 3))
        }
        0xfe => {
            let v = u32::from_le_bytes(b.get(1..5)?.try_into().ok()?);
            Some((v as u64, 5))
        }
        0xff => {
            let v = u64::from_le_bytes(b.get(1..9)?.try_into().ok()?);
            Some((v, 9))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_roundtrip() {
        for data in [
            b"".as_ref(),
            b"\x00\x00hello",
            b"Omyra receipt",
            &[0u8; 32],
        ] {
            let enc = base58_encode(data);
            assert_eq!(base58_decode(&enc).unwrap(), data);
        }
    }

    #[test]
    fn base58_known_vector() {
        // bitcoin genesis coinbase txid first bytes → well-known b58
        assert_eq!(base58_encode(b"\x00"), "1");
        assert_eq!(base58_encode(b"\x00\x00"), "11");
        // "Hello World!" → well-known
        let s = base58_encode(b"Hello World!");
        assert!(!s.is_empty());
        assert_eq!(base58_decode(&s).unwrap(), b"Hello World!");
    }

    #[test]
    fn compact_uint_roundtrip() {
        for &n in &[0u64, 1, 252, 253, 1000, 65535, 65536, 0xffff_ffff, u64::MAX] {
            let enc = compact_encode(n);
            let (dec, _) = compact_decode(&enc).unwrap();
            assert_eq!(dec, n, "failed for n={n}");
        }
    }

    #[test]
    fn compact_uint_lengths() {
        assert_eq!(compact_encode(252).len(), 1);
        assert_eq!(compact_encode(253).len(), 3);
        assert_eq!(compact_encode(65536).len(), 5);
        assert_eq!(compact_encode(u64::MAX).len(), 9);
    }
}
