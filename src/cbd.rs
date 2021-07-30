use crate::saber_params::{SABER_N, SABER_POLYCOINBYTES, U16};
use crate::U16;
use std::num::Wrapping;

/// Interprets up to 8 bytes `x` as integer in little endian format.
/// Returns the integer represented in the bytes as u64.
fn load_littleendian(x: &mut [u8]) -> u64 {
    let mut r: u64 = x[0] as u64;

    for (i, val) in x.iter().enumerate().skip(1) {
        r |= (*val as u64) << ((8 * i) as u64);
    }

    r
}

/// Central binomial distribution
///
/// Considers `buf` to be pseudo-random bytes and uses the
/// difference of integers to compute a central binomially distributed
/// value. How many bytes are used to generate one cbd-u16 value depends on
/// the parameter set. But obviously `SABER_POLYCOINBYTES` bytes are transformed
/// into `SABER_N` cbd-u16 values ase `s` is the result of this operation.
pub(crate) fn cbd(s: &mut [U16; SABER_N], buf: [u8; SABER_POLYCOINBYTES]) {
    if cfg!(SABER_L_IS_2) {
        let (mut t, mut d): (u64, u64);
        let (mut a, mut b) = ([0u64; 4], [0u64; 4]);

        for i in 0..SABER_N / 4 {
            let mut x = [0u8; 5];
            x.copy_from_slice(&buf[(5 * i)..(5 * i + 5)]);
            t = load_littleendian(&mut x);
            d = 0;
            for j in 0..5 {
                d += (t >> j) & 0x0842108421u64;
            }

            a[0] = d & 0x1f;
            b[0] = (d >> 5) & 0x1f;
            a[1] = (d >> 10) & 0x1f;
            b[1] = (d >> 15) & 0x1f;
            a[2] = (d >> 20) & 0x1f;
            b[2] = (d >> 25) & 0x1f;
            a[3] = (d >> 30) & 0x1f;
            b[3] = d >> 35;

            s[4 * i] = U16!((a[0] as i32 - b[0] as i32) as u16);
            s[4 * i + 1] = U16!((a[1] as i32 - b[1] as i32) as u16);
            s[4 * i + 2] = U16!((a[2] as i32 - b[2] as i32) as u16);
            s[4 * i + 3] = U16!((a[3] as i32 - b[3] as i32) as u16);
        }
    } else if cfg!(SABER_L_IS_3) {
        let (mut t, mut d): (u32, u32);
        let (mut a, mut b) = ([0u32; 4], [0u32; 4]);

        for i in 0..SABER_N / 4 {
            let mut x = [0u8; 4];
            x.copy_from_slice(&buf[(4 * i)..(4 * i + 4)]);
            t = load_littleendian(&mut x) as u32;
            d = 0;
            for j in 0..4 {
                d += (t >> j) & 0x11111111u32;
            }

            a[0] = d & 0xf;
            b[0] = (d >> 4) & 0xf;
            a[1] = (d >> 8) & 0xf;
            b[1] = (d >> 12) & 0xf;
            a[2] = (d >> 16) & 0xf;
            b[2] = (d >> 20) & 0xf;
            a[3] = (d >> 24) & 0xf;
            b[3] = d >> 28;

            s[4 * i] = U16!((a[0] as i32 - b[0] as i32) as u16);
            s[4 * i + 1] = U16!((a[1] as i32 - b[1] as i32) as u16);
            s[4 * i + 2] = U16!((a[2] as i32 - b[2] as i32) as u16);
            s[4 * i + 3] = U16!((a[3] as i32 - b[3] as i32) as u16);
        }
    } else if cfg!(SABER_L_IS_4) {
        let (mut t, mut d): (u32, u32);
        let (mut a, mut b) = ([0u32; 4], [0u32; 4]);

        for i in 0..SABER_N / 4 {
            const BYTES: usize = 3;
            let mut x = [0u8; BYTES];
            x.copy_from_slice(&buf[(BYTES * i)..(BYTES * i + BYTES)]);
            t = load_littleendian(&mut x) as u32;
            d = 0;
            for j in 0..BYTES {
                d += (t >> j) & 0x249249u32;
            }

            a[0] = d & 0x7;
            b[0] = (d >> 3) & 0x7;
            a[1] = (d >> 6) & 0x7;
            b[1] = (d >> 9) & 0x7;
            a[2] = (d >> 12) & 0x7;
            b[2] = (d >> 15) & 0x7;
            a[3] = (d >> 18) & 0x7;
            b[3] = d >> 21;

            s[4 * i] = U16!((a[0] as i32 - b[0] as i32) as u16);
            s[4 * i + 1] = U16!((a[1] as i32 - b[1] as i32) as u16);
            s[4 * i + 2] = U16!((a[2] as i32 - b[2] as i32) as u16);
            s[4 * i + 3] = U16!((a[3] as i32 - b[3] as i32) as u16);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cbd::cbd;
    use crate::link_c_reference::cbd as cbd_c;
    use crate::saber_params::{wrappedu162u16, SABER_N, SABER_POLYCOINBYTES};
    use crate::U16;
    use rand::Rng;
    use std::num::Wrapping;

    #[test]
    fn test_cbd() {
        let mut rng = rand::thread_rng();
        let mut s = [0u16; SABER_N];
        let mut buf = [0u8; SABER_POLYCOINBYTES];
        for i in 0..SABER_POLYCOINBYTES {
            buf[i] = rng.gen();
        }
        unsafe { cbd_c(&mut s, &mut buf) };
        let mut s2 = [U16!(0); SABER_N];
        cbd(&mut s2, buf);
        let mut check = [0u16; SABER_N];
        wrappedu162u16(&mut check[..], &s2[..]);
        assert_eq!(s, check);
    }
}
