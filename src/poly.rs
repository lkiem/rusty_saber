use crate::cbd::cbd;
use crate::fips202::shake_128;
use crate::pack_unpack::bs2polvecq;
use crate::poly_mul::poly_mul_acc;
use crate::saber_params::{
    SABER_L, SABER_N, SABER_NOISE_SEEDBYTES, SABER_POLYCOINBYTES, SABER_POLYVECBYTES,
    SABER_SEEDBYTES, U16,
};
use std::error::Error;

/// Let `a` be a vector of vectors of polynomials (a vector of module elements) and thus a matrix.
/// Let `s` be a vector of polynomials (a module element).
/// Let `×` denote matrix multiplication and `M^t` denote the transpose of matrix `M`.
/// If `transpose`, compute `a^t × s`. Else compute `a × s`.
/// The product is returned as vector `res`.
pub(crate) fn matrix_vector_mul(
    a: [[[U16; SABER_N]; SABER_L]; SABER_L],
    s: [[U16; SABER_N]; SABER_L],
    res: &mut [[U16; SABER_N]; SABER_L],
    transpose: bool,
) {
    for i in 0..SABER_L {
        for j in 0..SABER_L {
            if transpose {
                poly_mul_acc(a[j][i], s[j], &mut res[i]);
            } else {
                poly_mul_acc(a[i][j], s[j], &mut res[i]);
            }
        }
    }
}

/// Compute the inner product between vectors `b` and `s`.
/// The scalar is returned as `res`.
pub(crate) fn inner_prod(
    b: [[U16; SABER_N]; SABER_L],
    s: [[U16; SABER_N]; SABER_L],
    res: &mut [U16; SABER_N],
) {
    for j in 0..SABER_L {
        poly_mul_acc(b[j], s[j], res);
    }
}

/// Use `seed` to derive matrix `a` from it.
/// Matrix generation is used as part of the key generation step
/// and encryption reproduces the results.
pub(crate) fn gen_matrix(
    a: &mut [[[U16; SABER_N]; SABER_L]; SABER_L],
    seed: [u8; SABER_SEEDBYTES],
) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; SABER_L * SABER_POLYVECBYTES];
    shake_128(&mut buf, &seed)?;
    for i in 0..SABER_L {
        let mut tmp: [u8; SABER_POLYVECBYTES] = [0; SABER_POLYVECBYTES];
        tmp.copy_from_slice(&buf[(i * SABER_POLYVECBYTES)..((i + 1) * SABER_POLYVECBYTES)]);
        bs2polvecq(tmp, &mut a[i])
    }
    Ok(())
}

/// Use `seed` to derive secret vector `s` from it.
/// Matrix generation is used as part of the key generation step
/// and encryption reproduces the results.
pub(crate) fn gen_secret(
    s: &mut [[U16; SABER_N]; SABER_L],
    seed: [u8; SABER_NOISE_SEEDBYTES],
) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; SABER_L * SABER_POLYCOINBYTES];

    shake_128(&mut buf, &seed)?;
    for i in 0..SABER_L {
        let mut tmp: [u8; SABER_POLYCOINBYTES] = [0u8; SABER_POLYCOINBYTES];
        tmp.copy_from_slice(&buf[(i * SABER_POLYCOINBYTES)..((i + 1) * SABER_POLYCOINBYTES)]);
        cbd(&mut s[i], tmp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::link_c_reference::{GenMatrix, GenSecret, InnerProd, MatrixVectorMul};
    use crate::poly::{gen_matrix, gen_secret, inner_prod, matrix_vector_mul};
    use crate::saber_params::{wrappedu162u16, SABER_L, SABER_N, SABER_SEEDBYTES, U16};
    use crate::U16;
    use rand::Rng;
    use std::num::Wrapping;

    #[test]
    fn test_matrix_vector_mul() {
        let mut a: [[[U16; SABER_N]; SABER_L]; SABER_L] = [[[U16!(0); SABER_N]; SABER_L]; SABER_L];
        let mut s: [[U16; SABER_N]; SABER_L] = [[U16!(0); SABER_N]; SABER_L];
        let mut a_c: [[[u16; SABER_N]; SABER_L]; SABER_L] = [[[0u16; SABER_N]; SABER_L]; SABER_L];
        let mut s_c: [[u16; SABER_N]; SABER_L] = [[0u16; SABER_N]; SABER_L];
        let mut res1: [[u16; SABER_N]; SABER_L] = [[0u16; SABER_N]; SABER_L];
        let mut res2: [[U16; SABER_N]; SABER_L] = [[U16!(0); SABER_N]; SABER_L];
        let transpose: i16 = 0;

        let mut rng = rand::thread_rng();

        for i in 0..SABER_L {
            for j in 0..SABER_L {
                for x in 0..SABER_N {
                    let a_x: u16 = rng.gen_range(0..8192);
                    a[i][j][x] = U16!(a_x);
                    a_c[i][j][x] = a_x;
                }
            }
        }
        for i in 0..SABER_L {
            for j in 0..SABER_N {
                let s_x: u16 = rng.gen_range(0..8192);
                s[i][j] = U16!(s_x);
                s_c[i][j] = s_x;
            }
        }

        unsafe { MatrixVectorMul(&mut a_c, &mut s_c, &mut res1, transpose) };
        matrix_vector_mul(a, s, &mut res2, transpose == 1);

        let mut check: [[u16; SABER_N]; SABER_L] = [[0u16; SABER_N]; SABER_L];
        for i in 0..SABER_L {
            wrappedu162u16(&mut check[i][..], &res2[i][..]);
        }
        assert_eq!(res1, check);
        unsafe { MatrixVectorMul(&mut a_c, &mut s_c, &mut res1, 1) };
        matrix_vector_mul(a, s, &mut res2, true);

        let mut check: [[u16; SABER_N]; SABER_L] = [[0u16; SABER_N]; SABER_L];
        for i in 0..SABER_L {
            wrappedu162u16(&mut check[i][..], &res2[i][..]);
        }
        assert_eq!(res1, check);
    }

    #[test]
    fn test_inner_prod() {
        let mut b: [[U16; SABER_N]; SABER_L] = [[U16!(0); SABER_N]; SABER_L];
        let mut s: [[U16; SABER_N]; SABER_L] = [[U16!(0); SABER_N]; SABER_L];
        let mut b_c: [[u16; SABER_N]; SABER_L] = [[0u16; SABER_N]; SABER_L];
        let mut s_c: [[u16; SABER_N]; SABER_L] = [[0u16; SABER_N]; SABER_L];
        let mut res1: [u16; SABER_N] = [0u16; SABER_N];
        let mut res2: [U16; SABER_N] = [U16!(0); SABER_N];

        let mut rng = rand::thread_rng();

        for i in 0..SABER_L {
            for j in 0..SABER_N {
                let b_x: u16 = rng.gen_range(0..8192);
                b[i][j] = U16!(b_x);
                b_c[i][j] = b_x;
            }
        }
        for i in 0..SABER_L {
            for j in 0..SABER_N {
                let s_x: u16 = rng.gen_range(0..8192);
                s[i][j] = U16!(s_x);
                s_c[i][j] = s_x;
            }
        }

        unsafe { InnerProd(&mut b_c, &mut s_c, &mut res1) };
        inner_prod(b, s, &mut res2);

        let mut check = [0u16; SABER_N];
        wrappedu162u16(&mut check[..], &res2[..]);
        assert_eq!(res1, check);
    }

    #[test]
    fn test_gen_matrix() {
        let mut a1 = [[[0u16; SABER_N]; SABER_L]; SABER_L];
        let mut a2 = [[[U16!(0); SABER_N]; SABER_L]; SABER_L];
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; SABER_SEEDBYTES];
        for i in 0..SABER_SEEDBYTES {
            seed[i] = rng.gen();
        }
        unsafe { GenMatrix(&mut a1, &mut seed) };
        gen_matrix(&mut a2, seed).expect("gen_matrix failed!");

        let mut check = [[[0u16; SABER_N]; SABER_L]; SABER_L];
        for i in 0..SABER_L {
            for j in 0..SABER_L {
                wrappedu162u16(&mut check[i][j][..], &a2[i][j][..]);
            }
        }
        assert_eq!(a1, check);
    }

    #[test]
    fn test_gen_secret() {
        let mut s1 = [[0u16; SABER_N]; SABER_L];
        let mut s2 = [[U16!(0); SABER_N]; SABER_L];
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; SABER_SEEDBYTES];
        for i in 0..SABER_SEEDBYTES {
            seed[i] = rng.gen();
        }
        unsafe { GenSecret(&mut s1, &mut seed) };
        gen_secret(&mut s2, seed).expect("gen_secret failed!");

        let mut check = [[0u16; SABER_N]; SABER_L];
        for i in 0..SABER_L {
            wrappedu162u16(&mut check[i][..], &s2[i][..]);
        }
        assert_eq!(s1, check);
    }
}
