//! Personalized tickets: their title key is wrapped with the console's own eTicket RSA-2048 key
//! (RSA-OAEP, SHA-256, empty label). That key lives in the console's PRODINFO (calibration data) at 0x3890,
//! AES-128-CTR encrypted with `eticket_rsa_kek` from prod.keys:
//!   0x000 16-byte counter, then (encrypted) private exponent D (0x100, big-endian), modulus N (0x100),
//!   public exponent (u32 big-endian, 0x10001), padding.
//! Small Montgomery-arithmetic RSA, enough for one private-key operation per ticket.

use super::aes::{ctr_apply_counter, Aes128};
use super::sha256::sha256;

pub const PRODINFO_ETICKET_OFFSET: usize = 0x3890;
const BLOB_SIZE: usize = 0x240;

type Limbs = Vec<u32>;

fn from_be(b: &[u8]) -> Limbs {
    let mut v: Limbs = b.rchunks(4).map(|c| c.iter().fold(0u32, |a, &x| a << 8 | x as u32)).collect();
    while v.len() > 1 && *v.last().unwrap() == 0 {
        v.pop();
    }
    v
}

fn to_be(v: &[u32], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, limb) in v.iter().enumerate() {
        for k in 0..4 {
            let at = len as isize - 1 - (i * 4 + k) as isize;
            if at >= 0 {
                out[at as usize] = (limb >> (8 * k)) as u8;
            }
        }
    }
    out
}

fn ge(a: &[u32], b: &[u32]) -> bool {
    for i in (0..a.len().max(b.len())).rev() {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    true
}

fn sub_in_place(a: &mut [u32], b: &[u32]) {
    let mut borrow = 0i64;
    for i in 0..a.len() {
        let d = a[i] as i64 - b.get(i).copied().unwrap_or(0) as i64 - borrow;
        a[i] = d as u32;
        borrow = (d < 0) as i64;
    }
}

struct Modulus {
    n: Limbs,
    n0inv: u32,
    r2: Limbs,
}

impl Modulus {
    fn new(n: Limbs) -> Modulus {
        let mut inv = 1u32;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let len = n.len();
        // R^2 mod N by doubling 1 (2 * 32 * len) times
        let mut x: Limbs = vec![0; len + 1];
        x[0] = 1;
        for _ in 0..64 * len {
            let mut carry = 0u32;
            for limb in x.iter_mut() {
                let next = *limb >> 31;
                *limb = *limb << 1 | carry;
                carry = next;
            }
            if ge(&x, &n) {
                sub_in_place(&mut x, &n);
            }
        }
        x.truncate(len);
        Modulus { n, n0inv: inv.wrapping_neg(), r2: x }
    }

    fn mul(&self, a: &[u32], b: &[u32]) -> Limbs {
        let n = &self.n;
        let len = n.len();
        let mut t = vec![0u32; len + 2];
        for i in 0..len {
            let bi = b.get(i).copied().unwrap_or(0) as u64;
            let mut c = 0u64;
            for j in 0..len {
                let s = t[j] as u64 + a.get(j).copied().unwrap_or(0) as u64 * bi + c;
                t[j] = s as u32;
                c = s >> 32;
            }
            let s = t[len] as u64 + c;
            t[len] = s as u32;
            t[len + 1] = (s >> 32) as u32;
            let m = t[0].wrapping_mul(self.n0inv) as u64;
            let mut c = (t[0] as u64 + m * n[0] as u64) >> 32;
            for j in 1..len {
                let s = t[j] as u64 + m * n[j] as u64 + c;
                t[j - 1] = s as u32;
                c = s >> 32;
            }
            let s = t[len] as u64 + c;
            t[len - 1] = s as u32;
            let s2 = t[len + 1] as u64 + (s >> 32);
            t[len] = s2 as u32;
            t[len + 1] = 0;
        }
        t.truncate(len + 1);
        if ge(&t, n) {
            sub_in_place(&mut t, n);
        }
        t.truncate(len);
        t
    }

    fn pow(&self, base: &[u32], exp: &[u32]) -> Limbs {
        let xm = self.mul(base, &self.r2);
        let mut acc = self.mul(&[1], &self.r2);
        let bits = exp.len() * 32;
        for i in (0..bits).rev() {
            acc = self.mul(&acc, &acc);
            if exp[i / 32] >> (i % 32) & 1 == 1 {
                acc = self.mul(&acc, &xm);
            }
        }
        self.mul(&acc, &[1])
    }
}

/// The console's eTicket RSA key.
#[derive(Clone)]
pub struct EticketKey {
    d: Vec<u8>,
    n: Vec<u8>,
    e: u32,
}

impl EticketKey {
    /// Decrypts the eTicket key from PRODINFO (raw calibration image, or the 0x240-byte blob itself).
    pub fn from_prodinfo(prodinfo: &[u8], kek: &[u8; 16]) -> Result<EticketKey, String> {
        let blob = if prodinfo.len() == BLOB_SIZE {
            prodinfo
        } else {
            if &prodinfo[..4.min(prodinfo.len())] != b"CAL0" {
                return Err("PRODINFO does not start with CAL0 (it must be the decrypted calibration partition)".into());
            }
            prodinfo.get(PRODINFO_ETICKET_OFFSET..PRODINFO_ETICKET_OFFSET + BLOB_SIZE).ok_or("PRODINFO is too small")?
        };
        let iv_high = u64::from_be_bytes(blob[..8].try_into().unwrap());
        let iv_low = u64::from_be_bytes(blob[8..16].try_into().unwrap());
        let mut plain = blob[16..].to_vec();
        ctr_apply_counter(&Aes128::new(kek), iv_high, iv_low, &mut plain);
        let key = EticketKey { d: plain[..0x100].to_vec(), n: plain[0x100..0x200].to_vec(), e: u32::from_be_bytes(plain[0x200..0x204].try_into().unwrap()) };
        if key.e != 0x10001 || !key.self_test() {
            return Err("the eTicket key did not decrypt (wrong eticket_rsa_kek for this PRODINFO?)".into());
        }
        Ok(key)
    }

    fn modulus(&self) -> Modulus {
        Modulus::new(from_be(&self.n))
    }

    /// m^e^d == m for a fixed m below N.
    fn self_test(&self) -> bool {
        if self.n[0] == 0 {
            return false;
        }
        let m = Modulus::new(from_be(&self.n));
        let x = from_be(&[0x5a; 64]);
        let c = m.pow(&x, &[self.e]);
        let back = m.pow(&c, &from_be(&self.d));
        to_be(&back, 64) == to_be(&x, 64)
    }

    /// Unwraps a personalized ticket's title key block (RSA-OAEP, SHA-256, empty label).
    pub fn unwrap_title_key(&self, block: &[u8]) -> Result<[u8; 16], String> {
        if block.len() != 0x100 {
            return Err("title key block must be 0x100 bytes".into());
        }
        let m = self.modulus();
        let em = to_be(&m.pow(&from_be(block), &from_be(&self.d)), 0x100);
        let msg = oaep_decode(&em).ok_or("the personalized ticket did not unwrap with this console's eTicket key (a ticket from another console?)")?;
        msg.as_slice().try_into().map_err(|_| format!("unwrapped title key has {} bytes, expected 16", msg.len()))
    }
}

fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend(counter.to_be_bytes());
        out.extend(sha256(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

fn oaep_decode(em: &[u8]) -> Option<Vec<u8>> {
    let h = 32;
    if em.len() < 2 * h + 2 || em[0] != 0 {
        return None;
    }
    let (masked_seed, masked_db) = (&em[1..1 + h], &em[1 + h..]);
    let seed: Vec<u8> = masked_seed.iter().zip(mgf1(masked_db, h)).map(|(a, b)| a ^ b).collect();
    let db: Vec<u8> = masked_db.iter().zip(mgf1(&seed, masked_db.len())).map(|(a, b)| a ^ b).collect();
    if db[..h] != sha256(b"")[..] {
        return None;
    }
    let rest = &db[h..];
    let one = rest.iter().position(|&b| b != 0)?;
    (rest[one] == 1).then(|| rest[one + 1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str) -> Vec<u8> {
        let text = include_str!("testdata/eticket.txt");
        let hex = text.lines().find_map(|l| l.strip_prefix(&format!("{name} "))).unwrap().trim();
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn small_modexp() {
        // 4^13 mod 497 = 445
        let m = Modulus::new(vec![497]);
        assert_eq!(m.pow(&[4], &[13]), vec![445]);
    }

    #[test]
    fn unwraps_a_personalized_title_key() {
        let kek: [u8; 16] = field("KEK").try_into().unwrap();
        let key = EticketKey::from_prodinfo(&field("BLOB"), &kek).expect("eTicket key decrypts and self-tests");
        let tk = key.unwrap_title_key(&field("WRAPPED")).expect("OAEP unwraps");
        assert_eq!(tk.to_vec(), field("TITLEKEY"));
        let mut bad = field("WRAPPED");
        bad[10] ^= 1;
        assert!(key.unwrap_title_key(&bad).is_err());
        assert!(EticketKey::from_prodinfo(&field("BLOB"), &[0u8; 16]).is_err());
    }
}
