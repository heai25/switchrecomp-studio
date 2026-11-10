//! AES-128 and the three modes Switch content uses: ECB (key area, title keys),
//! CTR (NCA sections) and XTS with Nintendo's big-endian sector tweak (NCA headers).
//! Plain table implementation: no dependencies, checked against FIPS-197 and SP 800-38A vectors.

const SBOX: [u8; 256] = {
    let mut s = [0u8; 256];
    // Build the S-box from the GF(2^8) inverse plus the affine transform, at compile time.
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 });
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        s[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s[0] = 0x63;
    s
};

const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (if x & 0x80 != 0 { 0x1b } else { 0 })
}

#[inline]
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

#[derive(Clone)]
pub struct Aes128 {
    rk: [[u8; 16]; 11],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Aes128 {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [SBOX[t[1] as usize] ^ rcon, SBOX[t[2] as usize], SBOX[t[3] as usize], SBOX[t[0] as usize]];
                rcon = xtime(rcon);
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }
        let mut rk = [[0u8; 16]; 11];
        for r in 0..11 {
            for c in 0..4 {
                rk[r][c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
        }
        Aes128 { rk }
    }

    pub fn encrypt_block(&self, b: &mut [u8; 16]) {
        xor16(b, &self.rk[0]);
        for r in 1..11 {
            for x in b.iter_mut() {
                *x = SBOX[*x as usize];
            }
            shift_rows(b);
            if r != 10 {
                mix_columns(b);
            }
            xor16(b, &self.rk[r]);
        }
    }

    pub fn decrypt_block(&self, b: &mut [u8; 16]) {
        xor16(b, &self.rk[10]);
        for r in (0..10).rev() {
            inv_shift_rows(b);
            for x in b.iter_mut() {
                *x = INV_SBOX[*x as usize];
            }
            xor16(b, &self.rk[r]);
            if r != 0 {
                inv_mix_columns(b);
            }
        }
    }

    /// ECB decryption of whole blocks in place.
    pub fn ecb_decrypt(&self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(16) {
            self.decrypt_block(chunk.try_into().unwrap());
        }
    }
}

#[inline]
fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
        }
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[((c + r) % 4) * 4 + r] = t[c * 4 + r];
        }
    }
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        s[c * 4] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3];
        s[c * 4 + 1] = a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3];
        s[c * 4 + 2] = a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3]);
        s[c * 4 + 3] = (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3]);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let a = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        s[c * 4] = mul(a[0], 14) ^ mul(a[1], 11) ^ mul(a[2], 13) ^ mul(a[3], 9);
        s[c * 4 + 1] = mul(a[0], 9) ^ mul(a[1], 14) ^ mul(a[2], 11) ^ mul(a[3], 13);
        s[c * 4 + 2] = mul(a[0], 13) ^ mul(a[1], 9) ^ mul(a[2], 14) ^ mul(a[3], 11);
        s[c * 4 + 3] = mul(a[0], 11) ^ mul(a[1], 13) ^ mul(a[2], 9) ^ mul(a[3], 14);
    }
}

/// AES-128-CTR keystream applied in place. The counter block is `iv_high` (big-endian) followed
/// by `offset / 16` (big-endian); `offset % 16` bytes of the first block are skipped.
pub fn ctr_apply(aes: &Aes128, iv_high: u64, offset: u64, data: &mut [u8]) {
    ctr_blocks(aes, iv_high, offset >> 4, (offset & 15) as usize, data)
}

/// AES-128-CTR with a full 128-bit counter block given as (high, low) halves.
pub fn ctr_apply_counter(aes: &Aes128, iv_high: u64, iv_low: u64, data: &mut [u8]) {
    ctr_blocks(aes, iv_high, iv_low, 0, data)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
unsafe fn ctr_blocks_ni(aes: &Aes128, iv_high: u64, block_index: u64, data: &mut [u8]) {
    use std::arch::x86_64::*;
    unsafe {
        let rk: [__m128i; 11] = std::array::from_fn(|r| _mm_loadu_si128(aes.rk[r].as_ptr() as *const __m128i));
        let mut ctr = block_index;
        for chunk in data.chunks_mut(16) {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&iv_high.to_be_bytes());
            block[8..].copy_from_slice(&ctr.to_be_bytes());
            let mut s = _mm_xor_si128(_mm_loadu_si128(block.as_ptr() as *const __m128i), rk[0]);
            for k in &rk[1..10] {
                s = _mm_aesenc_si128(s, *k);
            }
            s = _mm_aesenclast_si128(s, rk[10]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
            for (d, k) in chunk.iter_mut().zip(block) {
                *d ^= k;
            }
            ctr = ctr.wrapping_add(1);
        }
    }
}

fn ctr_blocks(aes: &Aes128, iv_high: u64, mut block_index: u64, mut skip: usize, data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if skip == 0 && std::arch::is_x86_feature_detected!("aes") {
        // SAFETY: the CPU supports AES-NI (checked above).
        unsafe { ctr_blocks_ni(aes, iv_high, block_index, data) };
        return;
    }
    let mut i = 0;
    while i < data.len() {
        let mut ks = [0u8; 16];
        ks[..8].copy_from_slice(&iv_high.to_be_bytes());
        ks[8..].copy_from_slice(&block_index.to_be_bytes());
        aes.encrypt_block(&mut ks);
        let n = (16 - skip).min(data.len() - i);
        for j in 0..n {
            data[i + j] ^= ks[skip + j];
        }
        i += n;
        skip = 0;
        block_index = block_index.wrapping_add(1);
    }
}

/// AES-128-XTS decryption with Nintendo's tweak (sector number as a big-endian 128-bit value).
pub struct Xts {
    data: Aes128,
    tweak: Aes128,
}

fn gf_double(t: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in t.iter_mut() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        t[0] ^= 0x87;
    }
}

impl Xts {
    pub fn new(key: &[u8; 32]) -> Xts {
        Xts { data: Aes128::new(key[..16].try_into().unwrap()), tweak: Aes128::new(key[16..].try_into().unwrap()) }
    }

    pub fn decrypt(&self, data: &mut [u8], first_sector: u64, sector_size: usize) {
        for (n, sector) in data.chunks_mut(sector_size).enumerate() {
            let mut t = [0u8; 16];
            t[8..].copy_from_slice(&(first_sector + n as u64).to_be_bytes());
            self.tweak.encrypt_block(&mut t);
            for block in sector.chunks_exact_mut(16) {
                let b: &mut [u8; 16] = block.try_into().unwrap();
                xor16(b, &t);
                self.data.decrypt_block(b);
                xor16(b, &t);
                gf_double(&mut t);
            }
        }
    }

    #[cfg(test)]
    pub fn encrypt(&self, data: &mut [u8], first_sector: u64, sector_size: usize) {
        for (n, sector) in data.chunks_mut(sector_size).enumerate() {
            let mut t = [0u8; 16];
            t[8..].copy_from_slice(&(first_sector + n as u64).to_be_bytes());
            self.tweak.encrypt_block(&mut t);
            for block in sector.chunks_exact_mut(16) {
                let b: &mut [u8; 16] = block.try_into().unwrap();
                xor16(b, &t);
                self.data.encrypt_block(b);
                xor16(b, &t);
                gf_double(&mut t);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn fips197_vector() {
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let aes = Aes128::new(&key);
        let mut b: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        aes.encrypt_block(&mut b);
        assert_eq!(b.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
        aes.decrypt_block(&mut b);
        assert_eq!(b.to_vec(), hex("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn sbox_spot_checks() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(SBOX[0xff], 0x16);
        assert_eq!(INV_SBOX[0x63], 0x00);
    }

    #[test]
    fn sp800_38a_ctr_vector() {
        // NIST SP 800-38A F.5.1, initial counter f0f1...feff
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let aes = Aes128::new(&key);
        let mut data = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        ctr_blocks(&aes, 0xf0f1f2f3f4f5f6f7, 0xf8f9fafbfcfdfeff, 0, &mut data);
        assert_eq!(data, hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"));
    }

    #[test]
    fn ctr_hardware_matches_software() {
        let aes = Aes128::new(&[9u8; 16]);
        let mut hw = vec![0x5au8; 1000];
        ctr_blocks(&aes, 77, 5, 0, &mut hw);
        // a non-zero skip takes the software path for the whole call
        let mut sw = vec![0x5au8; 1001];
        ctr_blocks(&aes, 77, 4, 15, &mut sw);
        assert_eq!(&sw[1..], &hw[..]);
    }

    #[test]
    fn ctr_unaligned_matches_aligned() {
        let aes = Aes128::new(&[7u8; 16]);
        let mut whole = vec![0u8; 100];
        ctr_apply(&aes, 42, 0x1230, &mut whole);
        let mut part = vec![0u8; 61];
        ctr_apply(&aes, 42, 0x1230 + 39, &mut part);
        assert_eq!(&whole[39..], &part[..]);
    }

    #[test]
    fn xts_ieee1619_vector_2_layout() {
        // IEEE 1619 vector 2 uses a little-endian sector tweak; Nintendo uses big-endian.
        // With sector 0 both agree, so vector 1 (all-zero keys, sector 0) applies exactly.
        let x = Xts::new(&[0u8; 32]);
        let mut data = hex("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e");
        x.decrypt(&mut data, 0, 0x200);
        assert_eq!(data, vec![0u8; 32]);
    }

    #[test]
    fn xts_round_trip() {
        let x = Xts::new(&[0x11u8; 32]);
        let plain: Vec<u8> = (0..0x400u32).map(|i| (i * 7) as u8).collect();
        let mut buf = plain.clone();
        x.encrypt(&mut buf, 3, 0x200);
        assert_ne!(buf, plain);
        x.decrypt(&mut buf, 3, 0x200);
        assert_eq!(buf, plain);
    }
}
