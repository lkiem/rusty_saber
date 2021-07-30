use crate::saber_params::*;

#[link(name = "c_reference", kind = "static")]
//pack_unpack
extern "C" {
    pub(crate) fn POLT2BS(bytes: &mut [u8; SABER_SCALEBYTES_KEM], data: &mut [u16; SABER_N]);
    pub(crate) fn BS2POLT(bytes: &mut [u8; SABER_SCALEBYTES_KEM], data: &mut [u16; SABER_N]);
    pub(crate) fn POLq2BS(bytes: &mut [u8; SABER_POLYBYTES], data: &mut [u16; SABER_N]);
    pub(crate) fn BS2POLq(bytes: &mut [u8; SABER_POLYBYTES], data: &mut [u16; SABER_N]);
    pub(crate) fn POLp2BS(bytes: &mut [u8; SABER_POLYCOMPRESSEDBYTES], data: &mut [u16; SABER_N]);
    pub(crate) fn BS2POLp(bytes: &mut [u8; SABER_POLYCOMPRESSEDBYTES], data: &mut [u16; SABER_N]);
    pub(crate) fn POLVECq2BS(
        bytes: &mut [u8; SABER_POLYVECBYTES],
        data: &mut [[u16; SABER_N]; SABER_L],
    );
    pub(crate) fn BS2POLVECq(
        bytes: &mut [u8; SABER_POLYVECBYTES],
        data: &mut [[u16; SABER_N]; SABER_L],
    );
    pub(crate) fn POLVECp2BS(
        bytes: &mut [u8; SABER_POLYVECCOMPRESSEDBYTES],
        data: &mut [[u16; SABER_N]; SABER_L],
    );
    pub(crate) fn BS2POLVECp(
        bytes: &mut [u8; SABER_POLYVECCOMPRESSEDBYTES],
        data: &mut [[u16; SABER_N]; SABER_L],
    );
    pub(crate) fn BS2POLmsg(bytes: &mut [u8; SABER_KEYBYTES], data: &mut [u16; SABER_N]);
    pub(crate) fn POLmsg2BS(bytes: &mut [u8; SABER_KEYBYTES], data: &mut [u16; SABER_N]);
}

//poly_mul
extern "C" {
    pub(crate) fn poly_mul_acc(
        a: &mut [u16; SABER_N],
        b: &mut [u16; SABER_N],
        res: &mut [u16; SABER_N],
    );
}

//cbd
extern "C" {
    pub(crate) fn cbd(s: &mut [u16; SABER_N], buf: &mut [u8; SABER_POLYCOINBYTES]);
}

//verify
extern "C" {
    pub(crate) fn verify(
        a: &[u8; SABER_BYTES_CCA_DEC],
        b: &[u8; SABER_BYTES_CCA_DEC],
        len: usize,
    ) -> u64;
    pub(crate) fn cmov(r: &mut [u8; 64], x: &[u8; SABER_SECRETKEYBYTES], len: usize, b: u8);
}

//poly
extern "C" {
    pub(crate) fn MatrixVectorMul(
        a: &[[[u16; SABER_N]; SABER_L]; SABER_L],
        s: &[[u16; SABER_N]; SABER_L],
        res: &mut [[u16; SABER_N]; SABER_L],
        transpose: i16,
    );
    pub(crate) fn InnerProd(
        b: &[[u16; SABER_N]; SABER_L],
        s: &[[u16; SABER_N]; SABER_L],
        res: &mut [u16; SABER_N],
    );
    pub(crate) fn GenMatrix(a: &[[[u16; SABER_N]; SABER_L]; SABER_L], seed: &[u8; SABER_SEEDBYTES]);
    pub(crate) fn GenSecret(s: &[[u16; SABER_N]; SABER_L], seed: &[u8; SABER_NOISE_SEEDBYTES]);
}

//fips202
extern "C" {
    pub(crate) fn shake128(
        output: &[u8; SABER_L * SABER_POLYVECBYTES],
        outlen: u64,
        input: &[u8; SABER_SEEDBYTES],
        inlen: u64,
    );
    pub(crate) fn sha3_256(output: &[u8; 32], input: &[u8; SABER_SEEDBYTES], inlen: u64);
    pub(crate) fn sha3_512(output: &[u8; 64], input: &[u8; SABER_SEEDBYTES], inlen: u64);
}

//rng
extern "C" {
    pub(crate) fn randombytes(x: &mut [u8; 32], xlen: usize);
    pub(crate) fn randombytes_init(entropy_input: &mut [u8; 48], security_strength: i32);
}

//saber_indcpa
extern "C" {
    pub(crate) fn indcpa_kem_keypair(
        pk: &mut [u8; SABER_INDCPA_PUBLICKEYBYTES],
        sk: &mut [u8; SABER_INDCPA_SECRETKEYBYTES],
    );
    pub(crate) fn indcpa_kem_enc(
        m: &mut [u8; SABER_KEYBYTES],
        seed_sp: &mut [u8; SABER_NOISE_SEEDBYTES],
        pk: &mut [u8; SABER_INDCPA_PUBLICKEYBYTES],
        ciphertext: &mut [u8; SABER_BYTES_CCA_DEC],
    );
    pub(crate) fn indcpa_kem_dec(
        sk: &mut [u8; SABER_INDCPA_SECRETKEYBYTES],
        ciphertext: &mut [u8; SABER_BYTES_CCA_DEC],
        m: &mut [u8; SABER_KEYBYTES],
    );
}

//kem
extern "C" {
    pub(crate) fn crypto_kem_keypair(
        pk: &mut [u8; SABER_PUBLICKEYBYTES],
        sk: &mut [u8; SABER_SECRETKEYBYTES],
    );
    pub(crate) fn crypto_kem_enc(
        c: &mut [u8; SABER_BYTES_CCA_DEC],
        k: &mut [u8; SABER_KEYBYTES],
        pk: &mut [u8; SABER_PUBLICKEYBYTES],
    );
    pub(crate) fn crypto_kem_dec(
        k: &mut [u8; SABER_KEYBYTES],
        c: &mut [u8; SABER_BYTES_CCA_DEC],
        sk: &mut [u8; SABER_SECRETKEYBYTES],
    );
}

pub(crate) fn initialize_c_randombytes() {
    let mut entropy_inp = [0u8; 48];
    for i in 0..48 {
        entropy_inp[i] = i as u8;
    }
    unsafe { randombytes_init(&mut entropy_inp, 256) };
}
