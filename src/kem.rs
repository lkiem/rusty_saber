use crate::fips202::{sha3_256, sha3_512};
use crate::rng::RNGState;
use crate::saber_indcpa::{indcpa_kem_dec, indcpa_kem_enc, indcpa_kem_keypair};
use crate::saber_params::{
    SABER_BYTES_CCA_DEC, SABER_HASHBYTES, SABER_INDCPA_PUBLICKEYBYTES, SABER_INDCPA_SECRETKEYBYTES,
    SABER_KEYBYTES, SABER_NOISE_SEEDBYTES, SABER_SECRETKEYBYTES,
};
use crate::verify::{cmov, verify};
use std::convert::TryFrom;
use std::error::Error;

/// Key generation.
///
/// Given an RNG instance `rng`, compute some public and secret key (`pk` and `sk`).
/// The public key is meant to be shared with any party,
/// but access to the secret key must be limited to the generating party.
pub fn crypto_kem_keypair(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut impl RNGState,
) -> Result<(), Box<dyn Error>> {
    let tmp_pk = <&mut [u8; SABER_INDCPA_PUBLICKEYBYTES]>::try_from(
        &mut pk[0..SABER_INDCPA_PUBLICKEYBYTES],
    )?;
    let tmp_sk = <&mut [u8; SABER_INDCPA_SECRETKEYBYTES]>::try_from(
        &mut sk[0..SABER_INDCPA_SECRETKEYBYTES],
    )?;
    indcpa_kem_keypair(tmp_pk, tmp_sk, rng)?; // sk[0:SABER_INDCPA_SECRETKEYBYTES-1] <-- sk
    sk[SABER_INDCPA_SECRETKEYBYTES..(SABER_INDCPA_PUBLICKEYBYTES + SABER_INDCPA_SECRETKEYBYTES)]
        .clone_from_slice(&pk[..SABER_INDCPA_PUBLICKEYBYTES]); // sk[SABER_INDCPA_SECRETKEYBYTES:SABER_INDCPA_SECRETKEYBYTES+SABER_INDCPA_SECRETKEYBYTES-1] <-- pk

    let tmp_sk = &mut sk[(SABER_SECRETKEYBYTES - 64)..(SABER_SECRETKEYBYTES - 64) + 32]; // 32?

    sha3_256(tmp_sk, pk)?; // Then hash(pk) is appended.

    let tmp_rand_sk =
        <&mut [u8; SABER_KEYBYTES]>::try_from(&mut sk[SABER_SECRETKEYBYTES - SABER_KEYBYTES..])?;
    rng.randombytes(tmp_rand_sk)?;
    // This is output when check in crypto_kem_dec() fails.
    Ok(())
}

/// Encryption.
///
/// Given an RNG instance `rng` and a public key `pk`, sample a shared key.
/// This shared key is returned through parameter `k`
/// whereas ciphertext is returned as `c`.
pub fn crypto_kem_enc(
    c: &mut [u8],
    k: &mut [u8],
    pk: &mut [u8],
    rng: &mut impl RNGState,
) -> Result<(), Box<dyn Error>> {
    let mut kr = [0u8; 64];
    let mut buf = [0u8; 64];

    let slice_buf = &mut buf[0..32];
    rng.randombytes(slice_buf)?;

    let mut tmp_buf = [0u8; 32];
    tmp_buf.copy_from_slice(&slice_buf[0..32]);

    sha3_256(slice_buf, &tmp_buf)?; // BUF[0:31] <-- random message (will be used as the key for client) Note: hash doesnot release system RNG output

    let slice_buf = &mut buf[32..64];
    sha3_256(slice_buf, &pk[0..SABER_INDCPA_PUBLICKEYBYTES])?;

    sha3_512(&mut kr, &buf[0..64])?;

    let tmp_buf = <[u8; 32]>::try_from(&buf[0..32])?;

    let tmp_kr = <[u8; 32]>::try_from(&kr[32..64])?;

    let tmp_pk =
        <[u8; SABER_INDCPA_PUBLICKEYBYTES]>::try_from(&pk[0..SABER_INDCPA_PUBLICKEYBYTES])?;

    let tmp_c = <&mut [u8; SABER_BYTES_CCA_DEC]>::try_from(&mut c[0..SABER_BYTES_CCA_DEC])?;
    indcpa_kem_enc(tmp_buf, tmp_kr, tmp_pk, tmp_c)?;

    sha3_256(&mut kr[32..64], &c[0..SABER_BYTES_CCA_DEC])?;
    sha3_256(k, &kr[0..64])?;
    Ok(())
}

/// Decryption.
///
/// Given a secret key `sk` and a ciphertext `c`,
/// determine the shared text and return it is argument `k`.
pub fn crypto_kem_dec(k: &mut [u8], c: &[u8], sk: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut cmp = [0u8; SABER_BYTES_CCA_DEC];
    let mut buf = [0u8; 64];
    let mut kr = [0u8; 64];

    // original way
    let sized_sk =
        <[u8; SABER_INDCPA_SECRETKEYBYTES]>::try_from(&sk[0..SABER_INDCPA_SECRETKEYBYTES])?;
    let sized_c = <[u8; SABER_BYTES_CCA_DEC]>::try_from(&c[0..SABER_BYTES_CCA_DEC])?;
    let sized_buf = <&mut [u8; SABER_KEYBYTES]>::try_from(&mut buf[0..SABER_KEYBYTES])?;
    indcpa_kem_dec(sized_sk, sized_c, sized_buf)?; // buf[0:31] <-- message

    // Multitarget countermeasure for coins + contributory KEM
    for i in 0..32 {
        // Save hash by storing h(pk) in sk
        buf[32 + i] = sk[SABER_SECRETKEYBYTES - 64 + i];
    }

    sha3_512(&mut kr, &buf)?;

    let sized_buf = <[u8; SABER_KEYBYTES]>::try_from(&buf[0..SABER_KEYBYTES])?;
    let sized_kr =
        <&mut [u8; SABER_NOISE_SEEDBYTES]>::try_from(&mut kr[32..32 + SABER_NOISE_SEEDBYTES])?;
    let sized_pk = <[u8; SABER_INDCPA_PUBLICKEYBYTES]>::try_from(
        &sk[SABER_INDCPA_SECRETKEYBYTES..SABER_INDCPA_SECRETKEYBYTES + SABER_INDCPA_PUBLICKEYBYTES],
    )?;
    indcpa_kem_enc(sized_buf, *sized_kr, sized_pk, &mut cmp)?;

    let fail = verify(c, &cmp);

    sha3_256(sized_kr, &sized_c)?; // overwrite coins in kr with h(c)

    let keybytes = <[u8; SABER_KEYBYTES]>::try_from(
        &sk[(SABER_INDCPA_PUBLICKEYBYTES + SABER_HASHBYTES)
            ..(SABER_INDCPA_PUBLICKEYBYTES + SABER_HASHBYTES + SABER_KEYBYTES)],
    )?;
    cmov(&mut kr, &keybytes, fail);
    sha3_256(k, &kr)?; // hash concatenation of pre-k and h(c) to k
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
    use crate::link_c_reference::crypto_kem_dec as crypto_kem_dec_c;
    use crate::link_c_reference::crypto_kem_enc as crypto_kem_enc_c;
    use crate::link_c_reference::crypto_kem_keypair as crypto_kem_keypair_c;
    use crate::link_c_reference::initialize_c_randombytes;
    use crate::rng::AesState;
    use crate::saber_params::{
        SABER_BYTES_CCA_DEC, SABER_KEYBYTES, SABER_PUBLICKEYBYTES, SABER_SECRETKEYBYTES,
    };
    use rand::Rng;

    #[test]
    fn test_crypto_kem_keypair() {
        initialize_c_randombytes();
        let mut rng = AesState::with_increasing_seed();

        let mut pk_rs = [0u8; SABER_PUBLICKEYBYTES];
        let mut sk_rs = [0u8; SABER_SECRETKEYBYTES];
        let mut pk_c = [0u8; SABER_PUBLICKEYBYTES];
        let mut sk_c = [0u8; SABER_SECRETKEYBYTES];
        crypto_kem_keypair(&mut pk_rs, &mut sk_rs, &mut rng).expect("crypto_kem_keypair failed!");
        unsafe {
            crypto_kem_keypair_c(&mut pk_c, &mut sk_c);
        }
        assert_eq!(pk_rs, pk_c);
        assert_eq!(sk_rs, sk_c);
    }
    #[test]
    fn test_crypto_kem_enc() {
        initialize_c_randombytes();
        let mut rng_state = AesState::with_increasing_seed();

        let mut pk_rs = [0u8; SABER_PUBLICKEYBYTES];
        let mut pk_c = [0u8; SABER_PUBLICKEYBYTES];
        let mut ct = [0u8; SABER_BYTES_CCA_DEC];
        let mut k_rs = [0u8; SABER_KEYBYTES];
        let mut k_c = [0u8; SABER_KEYBYTES];

        let mut rng = rand::thread_rng();
        for i in 0..SABER_PUBLICKEYBYTES {
            let x: u8 = rng.gen();
            pk_rs[i] = x;
            pk_c[i] = x;
        }
        for i in 0..SABER_BYTES_CCA_DEC {
            ct[i] = rng.gen();
        }
        crypto_kem_enc(&mut ct, &mut k_rs, &mut pk_rs, &mut rng_state)
            .expect("crypto_kem_enc failed!");
        unsafe { crypto_kem_enc_c(&mut ct, &mut k_c, &mut pk_c) };
        assert_eq!(k_rs, k_c);
        assert_eq!(pk_c, pk_rs);
    }

    #[test]
    fn test_crypto_kem_dec() {
        initialize_c_randombytes();
        let mut k_rs = [0u8; SABER_KEYBYTES];
        let mut k_c = [0u8; SABER_KEYBYTES];
        let mut c = [0u8; SABER_BYTES_CCA_DEC];
        let mut sk = [0u8; SABER_SECRETKEYBYTES];

        let mut rng = rand::thread_rng();
        for i in 0..SABER_KEYBYTES {
            let x: u8 = rng.gen();
            k_rs[i] = x;
            k_c[i] = x;
        }

        crypto_kem_dec(&mut k_rs, &c, &sk).expect("crypto_kem_dec failed!");
        unsafe { crypto_kem_dec_c(&mut k_c, &mut c, &mut sk) };
        assert_eq!(k_rs, k_c);
    }
}
