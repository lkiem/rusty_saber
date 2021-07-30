use criterion::{criterion_group, criterion_main, Criterion};
use criterion_cycles_per_byte::CyclesPerByte;
use rusty_saber::api::{
    CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};
use rusty_saber::kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use rusty_saber::rng::AesState;

pub fn bench_kem(criterion: &mut Criterion<CyclesPerByte>) {
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut k_a = [0u8; CRYPTO_BYTES];
    let mut k_b = [0u8; CRYPTO_BYTES];

    let mut rng = AesState::with_increasing_seed();
    criterion.bench_function("kem", |b| {
        b.iter(|| {
            crypto_kem_keypair(&mut pk, &mut sk, &mut rng).expect("crypto_kem_keypair failed!");
            crypto_kem_enc(&mut c, &mut k_a, &mut pk, &mut rng).expect("crypto_kem_enc failed!");
            crypto_kem_dec(&mut k_b, &mut c, &mut sk).expect("crypto_kem_dec failed!");
            assert_eq!(k_a, k_b);
        })
    });
}

pub fn bench_kem_keypair(criterion: &mut Criterion<CyclesPerByte>) {
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];

    let mut rng = AesState::with_increasing_seed();
    criterion.bench_function("kem_kp", |b| {
        b.iter(|| {
            crypto_kem_keypair(&mut pk, &mut sk, &mut rng).expect("crypto_kem_keypair failed!");
        })
    });
}

pub fn bench_kem_enc(criterion: &mut Criterion<CyclesPerByte>) {
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut k_a = [0u8; CRYPTO_BYTES];

    let mut rng = AesState::with_increasing_seed();
    criterion.bench_function("kem_enc", |b| {
        b.iter(|| {
            crypto_kem_enc(&mut c, &mut k_a, &mut pk, &mut rng).expect("crypto_kem_enc failed!");
        })
    });
}

pub fn bench_kem_dec(criterion: &mut Criterion<CyclesPerByte>) {
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
    let mut k_b = [0u8; CRYPTO_BYTES];

    criterion.bench_function("kem_dec", |b| {
        b.iter(|| {
            crypto_kem_dec(&mut k_b, &mut c, &mut sk).expect("crypto_kem_dec failed!");
        })
    });
}

criterion_group!(name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte); targets = bench_kem, bench_kem_keypair, bench_kem_enc, bench_kem_dec);
criterion_main!(benches);
