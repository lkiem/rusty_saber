use std::num::Wrapping;

#[allow(non_snake_case)]
#[macro_export]
macro_rules! U16 {
    ($init:expr) => {
        Wrapping::<u16>($init)
    };
}
pub(crate) type U16 = Wrapping<u16>;

/// degree of the polynomial ring
pub(crate) const SABER_N: usize = 256;
/// rank of the module
pub(crate) const SABER_L: usize = if cfg!(SABER_L_IS_2) {
    2
} else if cfg!(SABER_L_IS_4) {
    4
} else if cfg!(SABER_L_IS_3) {
    3
} else {
    0
};

#[cfg(test)]
pub fn wrappedu162u16(plain_arr: &mut [u16], alias_arr: &[U16]) {
    for (i, x) in alias_arr.iter().enumerate() {
        plain_arr[i] = x.0;
    }
}
const fn params() -> (usize, usize) {
    let mut mu = 0usize;
    let mut et = 0usize;

    if SABER_L == 2 {
        mu = 10;
        et = 3;
    } else if SABER_L == 3 {
        mu = 8;
        et = 4;
    } else if SABER_L == 4 {
        mu = 6;
        et = 6;
    }
    (mu, et)
}

/// central binomial distribution parameter μ
pub(crate) const SABER_MU: usize = params().0;

/// rounding modulo ε_T
pub(crate) const SABER_ET: usize = params().1;
/// rounding modulo ε_Q
pub(crate) const SABER_EQ: usize = 13;
/// rounding modulo ε_P
pub(crate) const SABER_EP: usize = 10;

pub(crate) const SABER_SEEDBYTES: usize = 32;
pub(crate) const SABER_NOISE_SEEDBYTES: usize = 32;
pub(crate) const SABER_KEYBYTES: usize = 32;
pub(crate) const SABER_HASHBYTES: usize = 32;

pub(crate) const SABER_POLYCOINBYTES: usize = SABER_MU * SABER_N / 8;

pub(crate) const SABER_POLYBYTES: usize = SABER_EQ * SABER_N / 8;
pub(crate) const SABER_POLYVECBYTES: usize = SABER_L * SABER_POLYBYTES;

pub(crate) const SABER_POLYCOMPRESSEDBYTES: usize = SABER_EP * SABER_N / 8;
pub(crate) const SABER_POLYVECCOMPRESSEDBYTES: usize = SABER_L * SABER_POLYCOMPRESSEDBYTES;

pub(crate) const SABER_SCALEBYTES_KEM: usize = SABER_ET * SABER_N / 8;

pub(crate) const SABER_INDCPA_PUBLICKEYBYTES: usize =
    SABER_POLYVECCOMPRESSEDBYTES + SABER_SEEDBYTES;
pub(crate) const SABER_INDCPA_SECRETKEYBYTES: usize = SABER_POLYVECBYTES;

pub(crate) const SABER_PUBLICKEYBYTES: usize = SABER_INDCPA_PUBLICKEYBYTES;
pub(crate) const SABER_SECRETKEYBYTES: usize =
    SABER_INDCPA_SECRETKEYBYTES + SABER_INDCPA_PUBLICKEYBYTES + SABER_HASHBYTES + SABER_KEYBYTES;

pub(crate) const SABER_BYTES_CCA_DEC: usize = SABER_POLYVECCOMPRESSEDBYTES + SABER_SCALEBYTES_KEM;
