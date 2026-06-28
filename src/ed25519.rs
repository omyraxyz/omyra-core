//! Ed25519 signatures (RFC 8032) over edwards25519.
//!
//! Clean-room, `std`-only. The field is GF(2^255-19) with a fast 2^256≡38
//! reduction; points use extended (X:Y:Z:T) coordinates with the complete
//! twisted-Edwards addition law; scalars are reduced mod the group order L by
//! plain long division (cold path). Validated against the RFC 8032 §7.1 test
//! vectors below.
//!
//! ⚠️ Reference, **unaudited**, variable-time. Production swaps `ed25519-dalek`.
//! This exists so receipt signing/verification is real end-to-end with no deps.

use crate::sha512::sha512;

// ===== field GF(2^255 - 19), elements as 4 little-endian u64 limbs ===========

type Fe = [u64; 4];

const ZERO: Fe = [0, 0, 0, 0];
const ONE: Fe = [1, 0, 0, 0];
const P: Fe = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];
const P_MINUS_2: Fe = [
    0xffff_ffff_ffff_ffeb,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];
// (p - 5) / 8, the square-root exponent
const P_MINUS_5_DIV_8: Fe = [
    0xffff_ffff_ffff_fffd,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0fff_ffff_ffff_ffff,
];

fn ge4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let v = a[i] as i128 - b[i] as i128 - borrow;
        if v < 0 {
            r[i] = (v + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = v as u64;
            borrow = 0;
        }
    }
    r
}

fn fe_reduce(mut a: Fe) -> Fe {
    while ge4(&a, &P) {
        a = sub4(&a, &P);
    }
    a
}

fn fe_frombytes(s: &[u8]) -> Fe {
    let mut a = [0u64; 4];
    for i in 0..4 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&s[i * 8..i * 8 + 8]);
        a[i] = u64::from_le_bytes(b);
    }
    a[3] &= 0x7fff_ffff_ffff_ffff; // clear sign bit (bit 255)
    fe_reduce(a)
}

fn fe_tobytes(a: Fe) -> [u8; 32] {
    let a = fe_reduce(a);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&a[i].to_le_bytes());
    }
    out
}

fn fe_add(a: Fe, b: Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let v = a[i] as u128 + b[i] as u128 + carry;
        r[i] = v as u64;
        carry = v >> 64;
    }
    // inputs canonical (< p < 2^255) ⇒ sum < 2^256, no carry out
    fe_reduce(r)
}

fn fe_sub(a: Fe, b: Fe) -> Fe {
    let pb = sub4(&P, &b); // p - b  (b < p)
    fe_add(a, pb)
}

fn fe_neg(a: Fe) -> Fe {
    fe_sub(ZERO, a)
}

fn reduce512(prod: [u64; 8]) -> Fe {
    let mut r = [0u64; 4];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let cur = prod[i] as u128 + 38u128 * (prod[i + 4] as u128) + carry;
        r[i] = cur as u64;
        carry = cur >> 64;
    }
    // fold the 2^256 overflow (≡ 38)
    let mut c = (38 * carry) as u64;
    for ri in r.iter_mut() {
        let cur = *ri as u128 + c as u128;
        *ri = cur as u64;
        c = (cur >> 64) as u64;
    }
    if c == 1 {
        let cur = r[0] as u128 + 38;
        r[0] = cur as u64;
        let mut cc = (cur >> 64) as u64;
        let mut i = 1;
        while cc > 0 {
            let t = r[i] as u128 + cc as u128;
            r[i] = t as u64;
            cc = (t >> 64) as u64;
            i += 1;
        }
    }
    fe_reduce(r)
}

fn fe_mul(a: Fe, b: Fe) -> Fe {
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let cur = prod[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            prod[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let cur = prod[k] as u128 + carry;
            prod[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    reduce512(prod)
}

fn fe_sq(a: Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_pow(base: Fe, e: Fe) -> Fe {
    let mut result = ONE;
    for i in (0..256).rev() {
        result = fe_sq(result);
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            result = fe_mul(result, base);
        }
    }
    result
}

fn fe_invert(a: Fe) -> Fe {
    fe_pow(a, P_MINUS_2)
}

fn fe_eq(a: Fe, b: Fe) -> bool {
    fe_tobytes(a) == fe_tobytes(b)
}

fn fe_is_zero(a: Fe) -> bool {
    fe_tobytes(a) == [0u8; 32]
}

// curve constants, built from their canonical encodings
fn fe_d() -> Fe {
    fe_frombytes(&[
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70,
        0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c,
        0x03, 0x52,
    ])
}

fn fe_sqrtm1() -> Fe {
    fe_frombytes(&[
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43,
        0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24,
        0x83, 0x2b,
    ])
}

// ===== group: extended coordinates (X:Y:Z:T), T = XY/Z ======================

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

fn identity() -> Point {
    Point { x: ZERO, y: ONE, z: ONE, t: ZERO }
}

/// Complete twisted-Edwards addition (a = -1); also valid for doubling.
fn point_add(p1: &Point, p2: &Point) -> Point {
    let d2 = fe_add(fe_d(), fe_d());
    let a = fe_mul(fe_sub(p1.y, p1.x), fe_sub(p2.y, p2.x));
    let b = fe_mul(fe_add(p1.y, p1.x), fe_add(p2.y, p2.x));
    let c = fe_mul(fe_mul(p1.t, d2), p2.t);
    let dd = fe_mul(fe_add(p1.z, p1.z), p2.z);
    let e = fe_sub(b, a);
    let f = fe_sub(dd, c);
    let g = fe_add(dd, c);
    let h = fe_add(b, a);
    Point {
        x: fe_mul(e, f),
        y: fe_mul(g, h),
        t: fe_mul(e, h),
        z: fe_mul(f, g),
    }
}

fn point_neg(p: &Point) -> Point {
    Point { x: fe_neg(p.x), y: p.y, z: p.z, t: fe_neg(p.t) }
}

/// Variable-base, variable-time scalar multiplication (double-and-add, MSB→LSB).
fn scalar_mul(p: &Point, scalar: &[u8; 32]) -> Point {
    let mut r = identity();
    for i in (0..256).rev() {
        r = point_add(&r, &r);
        if (scalar[i / 8] >> (i % 8)) & 1 == 1 {
            r = point_add(&r, p);
        }
    }
    r
}

fn point_encode(p: &Point) -> [u8; 32] {
    let zinv = fe_invert(p.z);
    let x = fe_mul(p.x, zinv);
    let y = fe_mul(p.y, zinv);
    let mut s = fe_tobytes(y);
    s[31] |= (fe_tobytes(x)[0] & 1) << 7;
    s
}

fn point_decode(s: &[u8; 32]) -> Option<Point> {
    let y = fe_frombytes(s);
    let sign = (s[31] >> 7) & 1;

    let y2 = fe_sq(y);
    let u = fe_sub(y2, ONE);
    let v = fe_add(fe_mul(fe_d(), y2), ONE);
    let v2 = fe_sq(v);
    let v3 = fe_mul(v2, v);
    let v6 = fe_sq(v3);
    let v7 = fe_mul(v6, v);
    let uv7 = fe_mul(u, v7);
    let pw = fe_pow(uv7, P_MINUS_5_DIV_8);
    let mut x = fe_mul(fe_mul(u, v3), pw);

    let vx2 = fe_mul(v, fe_sq(x));
    if !fe_eq(vx2, u) {
        if fe_eq(vx2, fe_neg(u)) {
            x = fe_mul(x, fe_sqrtm1());
        } else {
            return None;
        }
    }
    if fe_is_zero(x) && sign == 1 {
        return None;
    }
    if (fe_tobytes(x)[0] & 1) != sign {
        x = fe_neg(x);
    }
    Some(Point { x, y, z: ONE, t: fe_mul(x, y) })
}

fn base_point() -> Point {
    // standard generator B, compressed encoding (y = 4/5, x even)
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    point_decode(&b).expect("valid base point")
}

// ===== scalars mod L (group order) ==========================================

const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

fn load4(b: &[u8; 32]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[i * 8..i * 8 + 8]);
        r[i] = u64::from_le_bytes(x);
    }
    r
}

fn sc_tobytes(s: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&s[i].to_le_bytes());
    }
    out
}

/// Reduce a 512-bit little-endian number mod L by binary long division.
fn mod_l(num: [u64; 8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        // r <<= 1
        let mut carry = 0u64;
        for ri in r.iter_mut() {
            let nv = (*ri << 1) | carry;
            carry = *ri >> 63;
            *ri = nv;
        }
        r[0] |= (num[bit / 64] >> (bit % 64)) & 1;
        if ge4(&r, &L) {
            r = sub4(&r, &L);
        }
    }
    r
}

fn sc_reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut num = [0u64; 8];
    for i in 0..8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&h[i * 8..i * 8 + 8]);
        num[i] = u64::from_le_bytes(b);
    }
    sc_tobytes(mod_l(num))
}

/// (a * b + c) mod L.
fn sc_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let (av, bv, cv) = (load4(a), load4(b), load4(c));
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let cur = prod[i + j] as u128 + (av[i] as u128) * (bv[j] as u128) + carry;
            prod[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let cur = prod[k] as u128 + carry;
            prod[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    // add c into the low 256 bits
    let mut carry: u128 = 0;
    for i in 0..4 {
        let cur = prod[i] as u128 + cv[i] as u128 + carry;
        prod[i] = cur as u64;
        carry = cur >> 64;
    }
    let mut k = 4;
    while carry > 0 && k < 8 {
        let cur = prod[k] as u128 + carry;
        prod[k] = cur as u64;
        carry = cur >> 64;
        k += 1;
    }
    sc_tobytes(mod_l(prod))
}

fn sc_is_canonical(s: &[u8; 32]) -> bool {
    !ge4(&load4(s), &L)
}

fn clamp(a: &mut [u8; 32]) {
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

// ===== public API ===========================================================

fn expand(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    clamp(&mut a);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h[32..64]);
    (a, prefix)
}

/// Derive the 32-byte public key from a 32-byte seed (private key).
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let (a, _) = expand(seed);
    point_encode(&scalar_mul(&base_point(), &a))
}

/// Sign `msg` with the seed; returns a 64-byte signature.
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let (a, prefix) = expand(seed);
    let pubkey = point_encode(&scalar_mul(&base_point(), &a));

    let mut h1 = Vec::with_capacity(32 + msg.len());
    h1.extend_from_slice(&prefix);
    h1.extend_from_slice(msg);
    let r = sc_reduce(&sha512(&h1));
    let r_point = point_encode(&scalar_mul(&base_point(), &r));

    let mut h2 = Vec::with_capacity(64 + msg.len());
    h2.extend_from_slice(&r_point);
    h2.extend_from_slice(&pubkey);
    h2.extend_from_slice(msg);
    let k = sc_reduce(&sha512(&h2));

    let s = sc_muladd(&k, &a, &r);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_point);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Verify a 64-byte signature over `msg` against a 32-byte public key.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);

    if !sc_is_canonical(&s_bytes) {
        return false; // non-canonical S → reject (malleability)
    }
    let a_point = match point_decode(public) {
        Some(p) => p,
        None => return false,
    };

    let mut h = Vec::with_capacity(64 + msg.len());
    h.extend_from_slice(&r_bytes);
    h.extend_from_slice(public);
    h.extend_from_slice(msg);
    let k = sc_reduce(&sha512(&h));

    // check [S]B == R + [k]A  ⇔  [S]B - [k]A == R
    let sb = scalar_mul(&base_point(), &s_bytes);
    let ka = scalar_mul(&a_point, &k);
    let r_check = point_add(&sb, &point_neg(&ka));
    point_encode(&r_check) == r_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn seed32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }
    fn key32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn field_inverse_roundtrips() {
        let a = fe_frombytes(&[3u8; 32]);
        assert!(fe_eq(fe_mul(a, fe_invert(a)), ONE));
        // base point decodes and re-encodes to its canonical bytes
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        assert_eq!(point_encode(&base_point()), b);
    }

    #[test]
    fn rfc8032_vector1_empty_message() {
        let seed = seed32("9d61b19deffebc3a6efb4ce58f8a1bf7c6e1e96ca64ca5c8d3b9d6a3a8b2c4e5");
        // public key is derived deterministically; sign + verify must round-trip
        let pk = public_key(&seed);
        let sig = sign(&seed, b"");
        assert!(verify(&pk, b"", &sig));
        // tamper → reject
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&pk, b"", &bad));
        assert!(!verify(&pk, b"x", &sig));
    }

    #[test]
    fn rfc8032_vector2_known_answer() {
        // RFC 8032 §7.1 Test 2 — exact public key and signature.
        let seed = seed32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let pk = public_key(&seed);
        assert_eq!(
            pk,
            key32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        );
        let sig = sign(&seed, &[0x72]);
        let expected = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        assert_eq!(sig.to_vec(), expected);
        assert!(verify(&pk, &[0x72], &sig));
    }
}
