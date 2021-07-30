use crate::fips202::shake_128;
use crate::pack_unpack::{
    bs2polmsg, bs2polt, bs2polvecp, bs2polvecq, polmsg2bs, polt2bs, polvecp2bs, polvecq2bs,
};
use crate::poly::*;
use crate::rng::RNGState;
use crate::saber_params::{
    SABER_BYTES_CCA_DEC, SABER_EP, SABER_EQ, SABER_ET, SABER_INDCPA_PUBLICKEYBYTES,
    SABER_INDCPA_SECRETKEYBYTES, SABER_KEYBYTES, SABER_L, SABER_N, SABER_NOISE_SEEDBYTES,
    SABER_POLYVECCOMPRESSEDBYTES, SABER_SCALEBYTES_KEM, SABER_SEEDBYTES, U16,
};
use crate::U16;
use std::convert::TryFrom;
use std::error::Error;
use std::mem;
use std::num::Wrapping;

const H1: U16 = U16!(1 << (SABER_EQ - SABER_EP - 1));
const H2: U16 = U16!(
    (1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1))
);

/// Key generation in the OWCPA setting.
///
/// Uses the RNG state `rng_state` to sample pseudo-random numbers
/// to derive public key `pk` and secret key `sk`. The public key can
/// be shared with any party, but the secret key must be kept secret
/// by the generating party.
pub(crate) fn indcpa_kem_keypair(
    pk: &mut [u8; SABER_INDCPA_PUBLICKEYBYTES],
    sk: &mut [u8; SABER_INDCPA_SECRETKEYBYTES],
    rng: &mut impl RNGState,
) -> Result<(), Box<dyn Error>> {
    let mut a = [[[U16!(0); SABER_N]; SABER_L]; SABER_L];
    let mut s = [[U16!(0); SABER_N]; SABER_L];
    let mut b = [[U16!(0); SABER_N]; SABER_L];

    let mut seed_a = [0u8; SABER_SEEDBYTES];
    let mut seed_s = [0u8; SABER_NOISE_SEEDBYTES];

    rng.randombytes(&mut seed_a)?;
    let seed_a_tmp = seed_a;
    shake_128(&mut seed_a, &seed_a_tmp)?; // for not revealing system RNG state
    rng.randombytes(&mut seed_s)?;

    gen_matrix(&mut a, seed_a)?;
    gen_secret(&mut s, seed_s)?;
    matrix_vector_mul(a, s, &mut b, true);

    for row in b.iter_mut().take(SABER_L) {
        for element in row.iter_mut().take(SABER_N) {
            *element = (*element + H1) >> (SABER_EQ - SABER_EP);
        }
    }

    let tmp = <&mut [u8; SABER_POLYVECCOMPRESSEDBYTES]>::try_from(
        &mut pk[0..SABER_POLYVECCOMPRESSEDBYTES],
    )?;

    polvecq2bs(sk, s)?;
    polvecp2bs(tmp, b)?;

    let pk_slice = &mut pk[SABER_POLYVECCOMPRESSEDBYTES..];
    pk_slice.copy_from_slice(&seed_a[0..mem::size_of::<[u8; SABER_SEEDBYTES]>()]);
    Ok(())
}

/// Encryption in the OWCPA setting.
///
/// Encrypts message `m` using public key `pk`. To turn this into a
/// deterministic computation, `seed_sp` is used as source of randomization.
/// The result is `ciphertext` which can be turned bach into `m` by decryption.
pub(crate) fn indcpa_kem_enc(
    m: [u8; SABER_KEYBYTES],
    seed_sp: [u8; SABER_NOISE_SEEDBYTES],
    pk: [u8; SABER_INDCPA_PUBLICKEYBYTES],
    ciphertext: &mut [u8; SABER_BYTES_CCA_DEC],
) -> Result<(), Box<dyn Error>> {
    let mut a = [[[U16!(0); SABER_N]; SABER_L]; SABER_L];
    let mut sp = [[U16!(0); SABER_N]; SABER_L];
    let mut bp = [[U16!(0); SABER_N]; SABER_L];
    let mut vp = [U16!(0); SABER_N];
    let mut mp = [U16!(0); SABER_N];
    let mut b = [[U16!(0); SABER_N]; SABER_L];

    let seed_a = <[u8; SABER_SEEDBYTES]>::try_from(
        &pk[SABER_POLYVECCOMPRESSEDBYTES..SABER_POLYVECCOMPRESSEDBYTES + SABER_SEEDBYTES],
    )?;

    gen_matrix(&mut a, seed_a)?;
    gen_secret(&mut sp, seed_sp)?;
    matrix_vector_mul(a, sp, &mut bp, false);

    for row in bp.iter_mut().take(SABER_L) {
        for element in row.iter_mut().take(SABER_N) {
            *element = (*element + H1) >> (SABER_EQ - SABER_EP);
        }
    }

    let tmp_ct = <&mut [u8; SABER_POLYVECCOMPRESSEDBYTES]>::try_from(
        &mut ciphertext[0..SABER_POLYVECCOMPRESSEDBYTES],
    )?;

    let tmp_pk =
        <[u8; SABER_POLYVECCOMPRESSEDBYTES]>::try_from(&pk[0..SABER_POLYVECCOMPRESSEDBYTES])?;

    polvecp2bs(tmp_ct, bp)?;
    bs2polvecp(tmp_pk, &mut b);
    inner_prod(b, sp, &mut vp);

    bs2polmsg(m, &mut mp);

    for j in 0..SABER_N {
        vp[j] = (vp[j] - (mp[j] << (SABER_EP - 1)) + H1) >> (SABER_EP - SABER_ET);
    }

    let ct = <&mut [u8; SABER_SCALEBYTES_KEM]>::try_from(
        &mut ciphertext[SABER_POLYVECCOMPRESSEDBYTES..],
    )?;
    polt2bs(ct, vp);
    Ok(())
}

/// Decryption in the OWCPA setting.
///
/// Decrypts `ciphertext` to message `m` by utilizing the secret key `sk`.
pub(crate) fn indcpa_kem_dec(
    sk: [u8; SABER_INDCPA_SECRETKEYBYTES],
    ciphertext: [u8; SABER_BYTES_CCA_DEC],
    m: &mut [u8; SABER_KEYBYTES],
) -> Result<(), Box<dyn Error>> {
    let mut s = [[U16!(0); SABER_N]; SABER_L];
    let mut b = [[U16!(0); SABER_N]; SABER_L];
    let mut v = [U16!(0); SABER_N];
    let mut cm = [U16!(0); SABER_N];

    bs2polvecq(sk, &mut s);

    let tmp_ct = <[u8; SABER_POLYVECCOMPRESSEDBYTES]>::try_from(
        &ciphertext[0..SABER_POLYVECCOMPRESSEDBYTES],
    )?;
    bs2polvecp(tmp_ct, &mut b);
    inner_prod(b, s, &mut v);

    let tmp_ct =
        <[u8; SABER_SCALEBYTES_KEM]>::try_from(&ciphertext[SABER_POLYVECCOMPRESSEDBYTES..])?;
    bs2polt(tmp_ct, &mut cm);

    for i in 0..SABER_N {
        v[i] = (v[i] + (H2 - (cm[i] << (SABER_EP - SABER_ET)))) >> (SABER_EP - 1);
    }

    polmsg2bs(m, v);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::link_c_reference::{
        indcpa_kem_dec, indcpa_kem_enc, indcpa_kem_keypair, initialize_c_randombytes,
    };
    use crate::rng::AesState;
    use crate::saber_indcpa::indcpa_kem_dec as indcpa_kem_dec_rs;
    use crate::saber_indcpa::indcpa_kem_enc as indcpa_kem_enc_rs;
    use crate::saber_indcpa::indcpa_kem_keypair as indcpa_kem_keypair_rs;
    use crate::saber_params::{
        SABER_BYTES_CCA_DEC, SABER_INDCPA_PUBLICKEYBYTES, SABER_INDCPA_SECRETKEYBYTES,
        SABER_KEYBYTES, SABER_NOISE_SEEDBYTES,
    };
    use rand::Rng;

    #[test]
    fn test_indcpa_kem_keypair() {
        initialize_c_randombytes();
        let mut rng = AesState::with_increasing_seed();

        let mut pk_rs = [0u8; SABER_INDCPA_PUBLICKEYBYTES];
        let mut sk_rs = [0u8; SABER_INDCPA_SECRETKEYBYTES];
        let mut pk_c = [0u8; SABER_INDCPA_PUBLICKEYBYTES];
        let mut sk_c = [0u8; SABER_INDCPA_SECRETKEYBYTES];

        indcpa_kem_keypair_rs(&mut pk_rs, &mut sk_rs, &mut rng)
            .expect("indcpa_kem_keypair failed!");
        unsafe { indcpa_kem_keypair(&mut pk_c, &mut sk_c) }

        assert_eq!(pk_rs, pk_c);
        assert_eq!(sk_rs, sk_c);
    }

    #[test]
    fn test_indcpa_kem_enc() {
        let mut m = [0u8; SABER_KEYBYTES];
        let mut seed_sp = [0u8; SABER_NOISE_SEEDBYTES];
        let mut pk = [0u8; SABER_INDCPA_PUBLICKEYBYTES];
        let mut ciphertext_rs = [0u8; SABER_BYTES_CCA_DEC];
        let mut ciphertext_c = [0u8; SABER_BYTES_CCA_DEC];
        let mut rng = rand::thread_rng();
        for i in 0..SABER_KEYBYTES {
            m[i] = rng.gen();
        }
        for i in 0..SABER_NOISE_SEEDBYTES {
            seed_sp[i] = rng.gen();
        }
        for i in 0..SABER_INDCPA_PUBLICKEYBYTES {
            pk[i] = rng.gen();
        }
        indcpa_kem_enc_rs(m, seed_sp, pk, &mut ciphertext_rs).expect("indcpa_kem_enc failed!");
        unsafe { indcpa_kem_enc(&mut m, &mut seed_sp, &mut pk, &mut ciphertext_c) }
        assert_eq!(ciphertext_rs, ciphertext_c);
    }

    #[test]
    fn test_indcpa_kem_dec() {
        let mut sk = [0u8; SABER_INDCPA_SECRETKEYBYTES];
        let mut ciphertext = [0u8; SABER_BYTES_CCA_DEC];
        let mut m_rs = [0u8; SABER_KEYBYTES];
        let mut m_c = [0u8; SABER_KEYBYTES];
        let mut rng = rand::thread_rng();
        for i in 0..SABER_INDCPA_SECRETKEYBYTES {
            sk[i] = rng.gen();
        }
        for i in 0..SABER_BYTES_CCA_DEC {
            ciphertext[i] = rng.gen();
        }
        indcpa_kem_dec_rs(sk, ciphertext, &mut m_rs).expect("indcpa_kem_dec failed!");
        unsafe { indcpa_kem_dec(&mut sk, &mut ciphertext, &mut m_c) }
        assert_eq!(m_rs, m_c);
    }
}
