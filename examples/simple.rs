//! A simple example illustrating shared key negotiation

use rusty_saber::api::CRYPTO_ALGNAME;
use rusty_saber::api::{
    CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};
use rusty_saber::kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use rusty_saber::rng::AesState;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut ss_a = [0u8; CRYPTO_BYTES];
    let mut ss_b = [0u8; CRYPTO_BYTES];
    let mut rng = AesState::new();
    //rng.randombytes_init([0u8; 48]);  // TODO use a proper seed (like bytes from /dev/urandom) here

    // Party a: generate public key `pk` and secret key `sk`
    crypto_kem_keypair(&mut pk, &mut sk, &mut rng)?;
    // Party b: generate a shared secret `ss_a` and ciphertext `ct` from the public key `pk`
    crypto_kem_enc(&mut ct, &mut ss_a, &mut pk, &mut rng)?;
    // Party a: derive the same shared secret `ss_b` from the ciphertext `ct` and the secret key `sk`
    crypto_kem_dec(&mut ss_b, &mut ct, &mut sk)?;

    // shared keys of parties a and b must match
    assert_eq!(ss_a, ss_b);
    println!("{} negotiated a key successfully.", CRYPTO_ALGNAME);
    Ok(())
}
