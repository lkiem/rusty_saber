use crate::saber_params::{SABER_N, U16};
use crate::U16;
use std::num::Wrapping;

const N_SB: usize = SABER_N >> 2;
const N_SB_RES: usize = 2 * N_SB - 1;

/// A simple wrapper to apply `wrapping_mul` to two U16 instances
fn wrapping_mul(x: U16, y: U16) -> U16 {
    U16!(((x.0 as u32).wrapping_mul(y.0 as u32) % 65536) as u16)
}

/// Apply Karatsuba multiplication to `a_1` and `b_1`
/// to compute `result_final`.
fn karatsuba_simple(a_1: [U16; N_SB], b_1: [U16; N_SB], result_final: &mut [U16]) {
    const KARATSUBA_N: usize = 64;

    let mut d01 = [U16!(0); KARATSUBA_N / 2 - 1];
    let mut d0123 = [U16!(0); KARATSUBA_N / 2 - 1];
    let mut d23 = [U16!(0); KARATSUBA_N / 2 - 1];
    let mut result_d01 = [U16!(0); KARATSUBA_N - 1];

    let (mut acc1, mut acc2, mut acc3, mut acc4, mut acc5): (U16, U16, U16, U16, U16);
    let (mut acc6, mut acc7, mut acc8, mut acc9, mut acc10): (U16, U16, U16, U16, U16);

    for i in 0..KARATSUBA_N / 4 {
        acc1 = a_1[i]; //a0
        acc2 = a_1[i + KARATSUBA_N / 4]; //a1
        acc3 = a_1[i + 2 * KARATSUBA_N / 4]; //a2
        acc4 = a_1[i + 3 * KARATSUBA_N / 4]; //a3

        for j in 0..KARATSUBA_N / 4 {
            acc5 = b_1[j]; //b0
            acc6 = b_1[j + KARATSUBA_N / 4]; //b1

            result_final[i + j] += wrapping_mul(acc1, acc5);
            result_final[i + j + 2 * KARATSUBA_N / 4] += wrapping_mul(acc2, acc6);

            acc7 = acc5 + acc6; //b01
            acc8 = acc1 + acc2; //a01
            d01[i + j] += acc7 * acc8;
            //--------------------------------------------------------

            acc7 = b_1[j + 2 * KARATSUBA_N / 4]; //b2
            acc8 = b_1[j + 3 * KARATSUBA_N / 4]; //b3
            result_final[i + j + KARATSUBA_N] += wrapping_mul(acc7, acc3);

            result_final[i + j + 6 * KARATSUBA_N / 4] += wrapping_mul(acc8, acc4);

            acc9 = acc3 + acc4;
            acc10 = acc7 + acc8;
            d23[i + j] += wrapping_mul(acc9, acc10);
            //--------------------------------------------------------

            acc5 += acc7; //b02
            acc7 = acc1 + acc3; //a02
            result_d01[i + j] += wrapping_mul(acc5, acc7);

            acc6 += acc8; //b13
            acc8 = acc2 + acc4;
            result_d01[i + j + 2 * KARATSUBA_N / 4] += wrapping_mul(acc6, acc8);

            acc5 += acc6;
            acc7 += acc8;
            d0123[i + j] += wrapping_mul(acc5, acc7);
        }
    }

    // 2nd last stage
    for i in 0..KARATSUBA_N / 2 - 1 {
        d0123[i] = d0123[i] - result_d01[i] - result_d01[i + 2 * KARATSUBA_N / 4];
        d01[i] = d01[i] - result_final[i] - result_final[i + 2 * KARATSUBA_N / 4];
        d23[i] = d23[i] - result_final[i + KARATSUBA_N] - result_final[i + 6 * KARATSUBA_N / 4];
    }

    for i in 0..KARATSUBA_N / 2 - 1 {
        result_d01[i + KARATSUBA_N / 4] += d0123[i];
        result_final[i + KARATSUBA_N / 4] += d01[i];
        result_final[i + 5 * KARATSUBA_N / 4] += d23[i];
    }

    // Last stage
    for i in 0..KARATSUBA_N - 1 {
        result_d01[i] = result_d01[i] - result_final[i] - result_final[i + KARATSUBA_N];
    }

    for i in 0..KARATSUBA_N - 1 {
        result_final[i + KARATSUBA_N / 2] += result_d01[i];
    }
}

/// Apply Toom-Cook multiplication with k=4.
///
/// `a` and `b` are considered as polynomials and `result` will contain the result
/// of the convolution. `k` stands for the parameter defining into how many chunks
/// both arguments are split. For resulting smaller integers, Karatsuba multiplication
/// is applied as part of this implementation.
fn toom_cook_4way(a: [U16; SABER_N], b: [U16; SABER_N], result: &mut [U16]) {
    let (inv3, inv9, inv15) = (U16!(43691), U16!(36409), U16!(61167));

    let mut aw1 = [U16!(0); N_SB];
    let mut aw2 = [U16!(0); N_SB];
    let mut aw3 = [U16!(0); N_SB];
    let mut aw4 = [U16!(0); N_SB];
    let mut aw5 = [U16!(0); N_SB];
    let mut aw6 = [U16!(0); N_SB];
    let mut aw7 = [U16!(0); N_SB];

    let mut bw1 = [U16!(0); N_SB];
    let mut bw2 = [U16!(0); N_SB];
    let mut bw3 = [U16!(0); N_SB];
    let mut bw4 = [U16!(0); N_SB];
    let mut bw5 = [U16!(0); N_SB];
    let mut bw6 = [U16!(0); N_SB];
    let mut bw7 = [U16!(0); N_SB];

    let mut w1 = [U16!(0); N_SB_RES];
    let mut w2 = [U16!(0); N_SB_RES];
    let mut w3 = [U16!(0); N_SB_RES];
    let mut w4 = [U16!(0); N_SB_RES];
    let mut w5 = [U16!(0); N_SB_RES];
    let mut w6 = [U16!(0); N_SB_RES];
    let mut w7 = [U16!(0); N_SB_RES];

    let (mut r0, mut r1, mut r2, mut r3): (U16, U16, U16, U16);
    let (mut r4, mut r5, mut r6, mut r7): (U16, U16, U16, U16);

    let a0 = &a[0..N_SB];
    let a1 = &a[N_SB..2 * N_SB];
    let a2 = &a[2 * N_SB..3 * N_SB];
    let a3 = &a[3 * N_SB..4 * N_SB];
    let b0 = &b[0..N_SB];
    let b1 = &b[N_SB..2 * N_SB];
    let b2 = &b[2 * N_SB..3 * N_SB];
    let b3 = &b[3 * N_SB..4 * N_SB];

    let c = result;
    for j in 0..N_SB {
        r0 = a0[j];
        r1 = a1[j];
        r2 = a2[j];
        r3 = a3[j];
        r4 = r0 + r2;
        r5 = r1 + r3;
        r6 = r4 + r5;
        r7 = r4 - r5;
        aw3[j] = r6;
        aw4[j] = r7;
        r4 = ((r0 << 2) + r2) << 1;
        r5 = (r1 << 2) + r3;
        r6 = r4 + r5;
        r7 = r4 - r5;
        aw5[j] = r6;
        aw6[j] = r7;
        r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
        aw2[j] = r4;
        aw7[j] = r0;
        aw1[j] = r3;
    }

    for j in 0..N_SB {
        r0 = b0[j];
        r1 = b1[j];
        r2 = b2[j];
        r3 = b3[j];
        r4 = r0 + r2;
        r5 = r1 + r3;
        r6 = r4 + r5;
        r7 = r4 - r5;
        bw3[j] = r6;
        bw4[j] = r7;
        r4 = ((r0 << 2) + r2) << 1;
        r5 = (r1 << 2) + r3;
        r6 = r4 + r5;
        r7 = r4 - r5;
        bw5[j] = r6;
        bw6[j] = r7;
        r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
        bw2[j] = r4;
        bw7[j] = r0;
        bw1[j] = r3;
    }

    karatsuba_simple(aw1, bw1, &mut w1);
    karatsuba_simple(aw2, bw2, &mut w2);
    karatsuba_simple(aw3, bw3, &mut w3);
    karatsuba_simple(aw4, bw4, &mut w4);
    karatsuba_simple(aw5, bw5, &mut w5);
    karatsuba_simple(aw6, bw6, &mut w6);
    karatsuba_simple(aw7, bw7, &mut w7);

    for i in 0..N_SB_RES {
        r0 = w1[i];
        r1 = w2[i];
        r2 = w3[i];
        r3 = w4[i];
        r4 = w5[i];
        r5 = w6[i];
        r6 = w7[i];

        r1 += r4;
        r5 -= r4;

        let tmp_r3 = r3.0 as i32;
        let tmp_r2 = r2.0 as i32;
        r3 = U16!(((tmp_r3 - tmp_r2) >> 1) as u16);
        r4 -= r0;
        r4 -= r6 << 6;
        r4 = (r4 << 1) + r5;
        r2 += r3;
        r1 -= (r2 << 6) + r2;

        r2 -= r6;
        r2 -= r0;
        r1 += U16!(45) * r2;

        let tmp_r4: i32 = r4.0 as i32;
        let tmp_shift: i32 = (r2.0 as i32) << 3;
        let tmp_inv3: i32 = inv3.0 as i32;
        r4 = U16!((((tmp_r4 - tmp_shift).wrapping_mul(tmp_inv3)) >> 3) as u16);

        r5 += r1;

        let tmp_r1: i32 = r1.0 as i32;
        let tmp_shift: i32 = (r3.0 as i32) << 4;
        let tmp_inv9 = inv9.0 as i32;
        r1 = U16!(((tmp_r1 + tmp_shift).wrapping_mul(tmp_inv9) >> 1) as u16);

        r3 = -(r3 + r1);

        let tmp_mul: i32 = 30 * r1.0 as i32;
        let tmp_r5: i32 = r5.0 as i32;
        let tmp_inv15: i32 = inv15.0 as i32;
        r5 = U16!(((tmp_mul - tmp_r5).wrapping_mul(tmp_inv15) >> 2) as u16);
        r2 -= r4;
        r1 -= r5;

        c[i] += r6;
        c[i + 64] += r5;
        c[i + 128] += r4;
        c[i + 192] += r3;
        c[i + 256] += r2;
        c[i + 320] += r1;
        c[i + 384] += r0;
    }
}

/// Compute polynomial multiplication accumulated.
///
/// Consider `a` and `b` as polynomials and compute the multiplication
/// of both polynomials. The result is added to `res`.
pub fn poly_mul_acc(a: [U16; SABER_N], b: [U16; SABER_N], res: &mut [U16; SABER_N]) {
    let mut c = [U16!(0); 2 * SABER_N];

    // convolution
    toom_cook_4way(a, b, &mut c);

    // polynomial reduction
    for i in SABER_N..2 * SABER_N {
        res[i - SABER_N] = res[i - SABER_N] + c[i - SABER_N] - c[i];
    }
}

#[cfg(test)]
mod tests {
    use crate::link_c_reference::poly_mul_acc as poly_mul_acc_c;
    use crate::poly_mul::*;
    use crate::saber_params::wrappedu162u16;
    use crate::U16;
    use std::num::Wrapping;

    #[test]
    fn test_poly_mul() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut a = [U16!(0); 256];
        let mut b = [U16!(0); 256];
        let mut a_c = [0u16; 256];
        let mut b_c = [0u16; 256];

        for i in 0..256 {
            let a_x: u16 = rng.gen_range(0..8192);
            let b_x: u16 = rng.gen_range(0..8192);
            a[i] = U16!(a_x);
            b[i] = U16!(b_x);
            a_c[i] = a_x;
            b_c[i] = b_x;
        }
        let mut res = [0u16; 256];
        let mut res2 = [U16!(0); 256];

        unsafe { poly_mul_acc_c(&mut a_c, &mut b_c, &mut res) };

        poly_mul_acc(a, b, &mut res2);

        let mut check = [0u16; 256];
        wrappedu162u16(&mut check[..], &res2[..]);
        assert_eq!(res, check);
    }
}
