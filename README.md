# rusty-saber

A safe pure-rust implementation of the Saber post-quantum scheme.

* Saber is a lattice-based key encapsulation mechanism (KEM)
* The implementation is based on the Saber reference implementation of NIST round 3
* The implementation does not utilize any concurrency techniques (SIMD/threading/…, except maybe auto-vectorization for your CPU)
* It depends on `sha3` as SHA-3 implementation and `aes` as AES block cipher (used as RNG) implementation
* It passes the 100 testcases of the C reference implementation
* The C reference implementation is included in this distribution since it is used for tests
* It implements the three variants: LightSaber, Saber, FireSaber
* The KEM takes about 25 milliseconds (all three variants) to run on a modern computer
* The implementation is constant-time on software instruction level
* The random number generator is based on AES256 in counter mode

## Who should use it?

Anyone, how wants to utilize Saber to negotiate a symmetric key between two parties.

## How does one use it?

Add this to your `Cargo.toml`:
```toml
[dependencies]
rusty-saber = "1.0"
```

To use a specific Saber variant, you need to import it with the corresponding feature flag:

```toml
[dependencies]
rusty-saber = { version = "1.0", features = ["lightsaber"] }
```

Feature flags for the three variants are called `lightsaber`, `saber`, and `firesaber` respectively.

The `simple` example illustrates the API:
```rust
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

  assert_eq!(ss_a, ss_b);
  Ok(())
}
```

## How does one run it?

This library comes with two examples:

```bash
$ cargo run --example simple
```

The `pqcgenkat_kem` example implements the classic request/response file structure which is part of the NIST PQC framework.

```bash
$ cargo run --example pqcgenkat_kem
$ ls *.r??
PQCkemKAT_2304.req  PQCkemKAT_2304.rsp
$ tail -n 2 PQCkemKAT_2304.rsp
ss = E5256B4F25816367FBE235E47C25ABB78195CEF7DE3F9C77926839F209CDF652
```

The different variants can be enabled through feature flags:

```bash
$ cargo run --example pqcgenkat_kem --features lightsaber
$ ls *.r??
PQCkemKAT_1568.req  PQCkemKAT_1568.rsp
```

`saber` is the default variant. Unfortunately, you cannot enable two variants simultaneously.

## Is it correct?

Yes. You can run unittests with the following commands:

```bash
$ cargo test --features cref,lightsaber
$ cargo test --features cref
$ cargo test --features cref,firesaber
```

It compares the output of function calls with its C equivalent.
Besides unittests, you can generate the `pqcgenkat_kem` req/rsp files and compare them to the ones generated by the C reference implementation.
We verified that they are equivalent.

## Is it fast?

Yes, but it takes roughly 16.2% more runtime than the C implementation. Here, data is always mentioned with clock cycles as unit.
The rust implementation has the following clock-cycle count characteristics (the smaller the better):

<table>
  <thead>
    <tr><td></td><td>complete KEM</td><td>keypair</td><td>enc</td><td>dec</td></tr>
  </thead><tbody>
    <tr><td>lightsaber</td><td>329,964</td><td>86,665</td><td>116,139</td><td>121,433</td></tr>
    <tr><td>saber</td><td>586,544</td><td>182,183</td><td>216,528</td><td>232,882</td></tr>
    <tr><td>firesaber</td><td>923,330</td><td>282,467</td><td>318,043</td><td>335,297</td></tr>
  </tbody>
</table>

The C reference implementation has the following clock-cycle count characteristics (the smaller the better):

<table>
  <thead>
    <tr><td></td><td>complete KEM</td><td>keypair</td><td>enc</td><td>dec</td></tr>
  </thead><tbody>
    <tr><td>lightsaber</td><td>284,558</td><td>72,785</td><td>95,936</td><td>115,837</td></tr>
    <tr><td>saber</td><td>509,361</td><td>140,370</td><td>174,995</td><td>193,996</td></tr>
    <tr><td>firesaber</td><td>785,548</td><td>222,955</td><td>268,561</td><td>294,032</td></tr>
  </tbody>
</table>

The tests were done on a Lenovo Thinkpad x260 (Intel Core i5-6200U CPU @ 2.30GHz). In the case of rust, [criterion 0.3.5](https://crates.io/crates/criterion) has been used as given in `benches/` and in case of C, the rudimentary code utilizing the TSC register provided with the reference implementation is used. I disabled CPU frequency scaling before running experiments. You can run the benchmark suite yourself with the `bench` subcommand, the `cref` feature and optionally some variant feature flag:

```bash
$ cargo bench --features cref,lightsaber
$ cargo bench --features cref
$ cargo bench --features cref,firesaber
```

## Where is the source code?

On [github](https://github.com/lkiem/rusty_saber).

## What is the content's license?

[MIT License](LICENSE.txt)

## Changelog

* **Version 1.0.0:** public release

## Where can I ask you to fix a bug?

On [github](https://github.com/lkiem/rusty_saber/issues).
