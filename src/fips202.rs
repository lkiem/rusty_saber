use sha3::digest::ExtendableOutputDirty;
use sha3::{Digest, Sha3_256, Sha3_512, Shake128};
use std::error::Error;
use std::io::{Read, Write};

/// Applies the SHAKE128 extended output function to `seed` to generate
/// pseudo-random bytes `buf`
pub(crate) fn shake_128(buf: &mut [u8], seed: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut hash = Shake128::default();

    hash.write_all(seed)?;

    let mut reader = hash.finalize_xof_dirty();
    reader.read_exact(buf)?;
    Ok(())
}

/// Applies the SHA3-256 hash function to `seed` to generate
/// pseudo-random bytes `buf`. Since, SHA3-256 with output digest 256 bits
/// is applied, necessarily 32 bytes will be written to `buf`.
pub(crate) fn sha3_256(buf: &mut [u8], seed: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut hash = Sha3_256::new();
    hash.write_all(seed)?;
    let res = hash.finalize();
    buf.copy_from_slice(&res[..]);
    Ok(())
}

/// Applies the SHA3-512 hash function to `seed` to generate
/// pseudo-random bytes `buf`. Since, SHA3-512 with output digest 512 bits
/// is applied, necessarily 64 bytes will be written to `buf`.
pub(crate) fn sha3_512(buf: &mut [u8], seed: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut hash = Sha3_512::new();
    hash.write_all(seed)?;
    let res = hash.finalize();
    buf.copy_from_slice(&res[..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::fips202::{sha3_256, sha3_512, shake_128};
    use crate::link_c_reference::{
        sha3_256 as sha3_256_c, sha3_512 as sha3_512_c, shake128 as shake128_c,
    };
    use crate::saber_params::{SABER_L, SABER_POLYVECBYTES, SABER_SEEDBYTES};
    use rand::Rng;

    #[test]
    fn test_sha3() {
        let mut buf1 = [0u8; SABER_L * SABER_POLYVECBYTES];
        let mut buf2 = [0u8; 32];
        let mut buf3 = [0u8; 64];
        let mut buf1_rs = [0u8; SABER_L * SABER_POLYVECBYTES];
        let mut buf2_rs = [0u8; 32];
        let mut buf3_rs = [0u8; 64];
        let out_len: u64 = (SABER_L * SABER_POLYVECBYTES) as u64;
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; SABER_SEEDBYTES];
        for i in 0..SABER_SEEDBYTES {
            seed[i] = rng.gen();
        }

        unsafe {
            shake128_c(&mut buf1, out_len, &mut seed, SABER_SEEDBYTES as u64);
            sha3_256_c(&mut buf2, &mut seed, SABER_SEEDBYTES as u64);
            sha3_512_c(&mut buf3, &mut seed, SABER_SEEDBYTES as u64);
        };
        shake_128(&mut buf1_rs, &seed).expect("shake_128 failed!");
        sha3_256(&mut buf2_rs, &seed).expect("sha3_256 failed!");
        sha3_512(&mut buf3_rs, &seed).expect("sha3_512 failed!");
        assert_eq!(buf1_rs, buf1);
        assert_eq!(buf2_rs, buf2);
        assert_eq!(buf3_rs, buf3);
    }
}
