use crate::saber_params::{
    SABER_BYTES_CCA_DEC, SABER_KEYBYTES, SABER_L, SABER_PUBLICKEYBYTES, SABER_SECRETKEYBYTES,
};

/// Returns the name of the algorithm. Uses the global variable
/// SABER_L to detect the algorithm. Returns `""` in case of an
/// unknown configuration.
const fn algname() -> &'static str {
    match SABER_L {
        2 => "LightSaber",
        3 => "Saber",
        4 => "FireSaber",
        _ => "",
    }
}

pub const CRYPTO_ALGNAME: &str = algname();

pub const CRYPTO_SECRETKEYBYTES: usize = SABER_SECRETKEYBYTES;
pub const CRYPTO_PUBLICKEYBYTES: usize = SABER_PUBLICKEYBYTES;
pub const CRYPTO_BYTES: usize = SABER_KEYBYTES;
pub const CRYPTO_CIPHERTEXTBYTES: usize = SABER_BYTES_CCA_DEC;
