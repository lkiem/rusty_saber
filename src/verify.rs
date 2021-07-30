/// Verify equivalence of bytestrings `a` and `b` in constant time.
/// However, the length of arguments is not checked; only the smaller one is compared with.
/// Returns 0 for equal strings, 1 for non-equal strings.
pub(crate) fn verify(a: &[u8], b: &[u8]) -> u8 {
    let mut r: u64 = 0;
    let len = a.len().min(b.len());

    for i in 0..len {
        r |= (a[i] ^ b[i]) as u64;
    }
    r = -(r as i64) as u64 >> 63;
    r as u8
}

/// Move conditionally. If b = 1, then copy `x` to `r`. If b = 0, no operation.
pub(crate) fn cmov(r: &mut [u8], x: &[u8], mut b: u8) {
    b = -(b as i8) as u8;

    for i in 0..x.len() {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}

#[cfg(test)]
mod tests {
    use crate::link_c_reference::{cmov as cmov_c, verify as verify_c};
    use crate::saber_params::{SABER_BYTES_CCA_DEC, SABER_KEYBYTES, SABER_SECRETKEYBYTES};
    use crate::verify::{cmov, verify};

    #[test]
    fn test_verify() {
        let mut a = [0u8; SABER_BYTES_CCA_DEC];
        let mut b = [0u8; SABER_BYTES_CCA_DEC];
        for i in 0..SABER_BYTES_CCA_DEC {
            a[i] = b'a';
            b[i] = b'a';
        }
        let len: usize = SABER_BYTES_CCA_DEC;

        let mut r1 = [0u8; 64];
        let mut x = [0u8; SABER_SECRETKEYBYTES];

        let mut res: u64;
        unsafe { res = verify_c(&a, &b, len) };

        unsafe { cmov_c(&mut r1, &x, SABER_KEYBYTES, res as u8) };

        let mut r2 = [0u8; 64];

        for i in 0..SABER_KEYBYTES {
            x[i] = b'a';
            r1[i] = b'b';
            r2[i] = b'b';
        }

        let mut res2 = verify(&a, &b);
        cmov(
            &mut r2[0..SABER_KEYBYTES],
            &x[0..SABER_KEYBYTES],
            res2 as u8,
        );

        assert_eq!(res as u8, res2);
        assert_eq!(r1, r2);

        b[b.len() - 1] = b'b';

        unsafe { res = verify_c(&a, &b, len) };

        unsafe { cmov_c(&mut r1, &x, SABER_KEYBYTES, res as u8) };

        res2 = verify(&a, &b);
        cmov(
            &mut r2[0..SABER_KEYBYTES],
            &x[0..SABER_KEYBYTES],
            res2 as u8,
        );
        assert_eq!(res as u8, res2);
        assert_eq!(r1, r2);
    }
}
