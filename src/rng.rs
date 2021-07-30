//! Implementation of a pseudo-random number generator
//! based on AES256 in CTR mode.
//!
//! The implementation follows the design discussed in this blogpost:
//! <https://lukas-prokop.at/articles/2021-12-31-nists-rng-in-rust>

use aes::BlockEncrypt;
use aes::NewBlockCipher;
use std::error;
use std::fmt;

/// Trait requiring primitives to generate pseudo-random numbers.
/// `AesState` is an object implementing this trait.
pub trait RNGState {
    /// Fill the buffer `x` with pseudo-random bytes resulting from the
    /// RNG run updating the RNG state
    fn randombytes(&mut self, x: &mut [u8]) -> Result<(), Box<dyn error::Error>>;
    /// Initialize/reset the RNG state based on the seed provided as `entropy_input`
    fn randombytes_init(&mut self, entropy_input: [u8; 48]);
}

/// AesState is a struct storing data of a pseudo-random number generator.
/// Using `randombytes_init`, it can be initialized once. Using `randombytes`,
/// one can successively fetch new pseudo-random numbers.
#[derive(Clone, Debug, PartialEq)]
pub struct AesState {
    pub key: [u8; 32],
    pub v: [u8; 16],
    pub reseed_counter: i32,
}

impl AesState {
    /// Returns a fresh RNG state
    pub fn new() -> AesState {
        AesState {
            key: [0; 32],
            v: [0; 16],
            reseed_counter: 0,
        }
    }

    /// Returns an RNG state which is initialized with a seed
    /// of bytes `[0, 1, 2, 3, 4, …, 47]` which is common in the NIST framework
    pub fn with_increasing_seed() -> AesState {
        let mut state = AesState {
            key: [0; 32],
            v: [0; 16],
            reseed_counter: 0,
        };
        let mut entropy = [0u8; 48];
        for i in 0..48 {
            entropy[i] = i as u8;
        }
        state.randombytes_init(entropy);
        state
    }

    /// This runs AES256 in ECB mode. Here `key` is a 256-bit AES key,
    /// `ctr` is a 128-bit plaintext value and `buffer` is a 128-bit
    /// ciphertext value.
    fn aes256_ecb(key: &[u8; 32], ctr: &[u8; 16], buffer: &mut [u8; 16]) {
        let cipher = aes::Aes256::new(key.into());
        buffer.copy_from_slice(ctr);
        cipher.encrypt_block(buffer.into());
    }

    /// Update `key` and `v` with `provided_data` by running one round of AES in counter mode
    fn aes256_ctr_update(
        provided_data: &mut Option<[u8; 48]>,
        key: &mut [u8; 32],
        v: &mut [u8; 16],
    ) {
        let mut temp = [[0u8; 16]; 3];

        for tmp in &mut temp[0..3] {
            let count = u128::from_be_bytes(*v);
            v.copy_from_slice(&(count + 1).to_be_bytes());

            Self::aes256_ecb(key, v, tmp);
        }

        if let Some(d) = provided_data {
            for j in 0..3 {
                for i in 0..16 {
                    temp[j][i] ^= d[16 * j + i];
                }
            }
        }

        key[0..16].copy_from_slice(&temp[0]);
        key[16..32].copy_from_slice(&temp[1]);
        v.copy_from_slice(&temp[2]);
    }
}

impl RNGState for AesState {
    /// Fill the buffer `x` with pseudo-random bytes resulting from the
    /// AES run in counter mode updating the object state
    fn randombytes(&mut self, x: &mut [u8]) -> Result<(), Box<dyn error::Error>> {
        for chunk in x.chunks_mut(16) {
            let count = u128::from_be_bytes(self.v);
            self.v.copy_from_slice(&(count + 1).to_be_bytes());

            let mut block = [0u8; 16];
            Self::aes256_ecb(&self.key, &self.v, &mut block);

            (*chunk).copy_from_slice(&block[..chunk.len()]);
        }

        Self::aes256_ctr_update(&mut None, &mut self.key, &mut self.v);
        self.reseed_counter += 1;

        Ok(())
    }

    /// Initialize/reset the state based on the seed provided as `entropy_input`
    fn randombytes_init(&mut self, entropy_input: [u8; 48]) {
        self.key = [0u8; 32];
        self.v = [0u8; 16];
        self.reseed_counter = 1i32;

        Self::aes256_ctr_update(&mut Some(entropy_input), &mut self.key, &mut self.v);
        self.reseed_counter = 1;
    }
}

impl Default for AesState {
    fn default() -> Self {
        Self::new()
    }
}

impl Eq for AesState {}

impl fmt::Display for AesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "AesState {{")?;
        writeln!(f, "  key = {:?}", self.key)?;
        writeln!(f, "  v   = {:?}", self.v)?;
        writeln!(f, "  reseed_counter = {}", self.reseed_counter)?;
        writeln!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link_c_reference::initialize_c_randombytes;
    use crate::link_c_reference::randombytes as randombytes_c;

    #[test]
    fn test_rng() -> Result<(), Box<dyn error::Error>> {
        let mut data = [0u8; 256];
        let mut rng_state = AesState::with_increasing_seed();

        rng_state.randombytes(&mut data)?;
        let ref1 = [
            0x06u8, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF,
            0x7A, 0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC,
            0x9A, 0xBC, 0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85,
            0x41, 0xDB, 0xD2, 0xE1, 0xFF, 0xA1, 0x98, 0x10, 0xF5, 0x39, 0x2D, 0x07, 0x62, 0x76,
            0xEF, 0x41, 0x27, 0x7C, 0x3A, 0xB6, 0xE9, 0x4A, 0x4E, 0x3B, 0x7D, 0xCC, 0x10, 0x4A,
            0x05, 0xBB, 0x08, 0x9D, 0x33, 0x8B, 0xF5, 0x5C, 0x72, 0xCA, 0xB3, 0x75, 0x38, 0x9A,
            0x94, 0xBB, 0x92, 0x0B, 0xD5, 0xD6, 0xDC, 0x9E, 0x7F, 0x2E, 0xC6, 0xFD, 0xE0, 0x28,
            0xB6, 0xF5, 0x72, 0x4B, 0xB0, 0x39, 0xF3, 0x65, 0x2A, 0xD9, 0x8D, 0xF8, 0xCE, 0x6C,
            0x97, 0x01, 0x32, 0x10, 0xB8, 0x4B, 0xBE, 0x81, 0x38, 0x8C, 0x3D, 0x14, 0x1D, 0x61,
            0x95, 0x7C, 0x73, 0xBC, 0xDC, 0x5E, 0x5C, 0xD9, 0x25, 0x25, 0xF4, 0x6A, 0x2B, 0x75,
            0x7B, 0x03, 0xCA, 0xB5, 0xC3, 0x37, 0x00, 0x4A, 0x2D, 0xA3, 0x53, 0x24, 0xA3, 0x25,
            0x71, 0x35, 0x64, 0xDA, 0xE2, 0x8F, 0x57, 0xAC, 0xC6, 0xDB, 0xE3, 0x2A, 0x07, 0x26,
            0x19, 0x0B, 0xAA, 0x6B, 0x8A, 0x0A, 0x25, 0x5A, 0xA1, 0xAD, 0x01, 0xE8, 0xDD, 0x56,
            0x9A, 0xA3, 0x6D, 0x09, 0x62, 0x56, 0xC4, 0x20, 0x71, 0x8A, 0x69, 0xD4, 0x6D, 0x8D,
            0xB1, 0xC6, 0xDD, 0x40, 0x60, 0x6A, 0x0B, 0xE3, 0xC2, 0x35, 0xBE, 0xFE, 0x62, 0x3A,
            0x90, 0x59, 0x3F, 0x82, 0xD6, 0xA8, 0xF9, 0xF9, 0x24, 0xE4, 0x4E, 0x36, 0xBE, 0x87,
            0xF7, 0xD2, 0x6B, 0x84, 0x45, 0x96, 0x6F, 0x9E, 0xE3, 0x29, 0xC4, 0x26, 0xC1, 0x25,
            0x21, 0xE8, 0x5F, 0x6F, 0xD4, 0xEC, 0xD5, 0xD5, 0x66, 0xBA, 0x0A, 0x34, 0x87, 0x12,
            0x5D, 0x79, 0xCC, 0x64,
        ];
        assert_eq!(data, ref1);

        rng_state.randombytes(&mut data)?;
        let ref2 = [
            0xC1u8, 0x7E, 0x03, 0x40, 0x61, 0xED, 0x5E, 0xA8, 0x17, 0xC4, 0x1D, 0x61, 0x63, 0x62,
            0x81, 0xE8, 0x16, 0xF8, 0x17, 0xDC, 0xF7, 0x53, 0xA9, 0x1D, 0x97, 0xC0, 0x18, 0xFF,
            0x82, 0xFB, 0xC9, 0xB1, 0x72, 0x8F, 0xC6, 0x6A, 0xF1, 0x14, 0xB5, 0x79, 0x78, 0xFB,
            0x60, 0x82, 0xB7, 0x0D, 0x28, 0x51, 0x40, 0xB2, 0x67, 0x25, 0xAA, 0x5F, 0x7B, 0xB4,
            0x40, 0x98, 0x20, 0xF6, 0x7E, 0x2D, 0x65, 0x6E, 0xDA, 0xCA, 0x30, 0xB5, 0xBB, 0x12,
            0xEB, 0x52, 0x49, 0xCC, 0x38, 0x09, 0xB1, 0x88, 0xCF, 0x0C, 0xC9, 0x5B, 0x5A, 0xE0,
            0xEF, 0xE8, 0xFC, 0x58, 0x87, 0x15, 0x2C, 0xB6, 0x60, 0x1B, 0x4C, 0xCF, 0x9F, 0xC4,
            0x11, 0x89, 0x4F, 0xA0, 0xC0, 0x26, 0x4E, 0xB5, 0x1A, 0x48, 0x1D, 0x4D, 0x70, 0x74,
            0xFD, 0xF0, 0x65, 0x05, 0x30, 0x30, 0xC8, 0xA9, 0x2B, 0xFC, 0xDD, 0x06, 0xBF, 0x18,
            0xC8, 0x48, 0x9C, 0x38, 0xD0, 0x37, 0x84, 0xFD, 0x63, 0x00, 0x18, 0x30, 0xE5, 0xA3,
            0x85, 0xA4, 0xA3, 0x78, 0x66, 0x69, 0x3F, 0x5B, 0xDA, 0xB8, 0xA8, 0xA2, 0x5B, 0x51,
            0x9D, 0xDB, 0xF2, 0xD2, 0x82, 0x68, 0x60, 0x1D, 0x95, 0xBE, 0xED, 0x64, 0x7E, 0x43,
            0x04, 0x84, 0xA2, 0x27, 0xC0, 0x23, 0xB0, 0x29, 0x7A, 0x28, 0x2F, 0x06, 0xC9, 0x13,
            0x76, 0x43, 0x3B, 0xDE, 0x5E, 0xC3, 0xAB, 0xBA, 0x8C, 0x06, 0xB8, 0x30, 0xC2, 0x64,
            0x52, 0xEA, 0x2F, 0xA7, 0xED, 0xEA, 0x8D, 0xCF, 0xE2, 0x0E, 0xAF, 0xCF, 0x89, 0x80,
            0xB3, 0xD5, 0xAE, 0xCE, 0xF8, 0x9D, 0xD8, 0x61, 0xAC, 0xEC, 0x1F, 0x5F, 0x7C, 0xD2,
            0xAE, 0x6B, 0x3C, 0xDE, 0x3C, 0x1D, 0x80, 0xA2, 0x83, 0x0D, 0xD0, 0xB9, 0xE8, 0x46,
            0x8A, 0xFA, 0xD1, 0x61, 0x98, 0x10, 0x74, 0xBE, 0xB3, 0x3D, 0xF1, 0xCD, 0xFF, 0x9A,
            0x52, 0x14, 0xF9, 0xF0,
        ];
        assert_eq!(data, ref2);

        Ok(())
    }

    #[test]
    fn test_randombytes() {
        let mut rng_state = AesState::with_increasing_seed();
        initialize_c_randombytes();

        let mut buff1_rs = [0u8; 32];
        rng_state
            .randombytes(&mut buff1_rs)
            .expect("randombytes failed!");
        let mut buff2_rs = [0u8; 32];
        rng_state
            .randombytes(&mut buff2_rs)
            .expect("randombytes failed!");

        let mut buff1_c = [0u8; 32];
        unsafe { randombytes_c(&mut buff1_c, 32) };
        let mut buff2_c = [0u8; 32];
        unsafe { randombytes_c(&mut buff2_c, 32) };

        assert_eq!(buff1_c, buff1_rs);
        assert_eq!(buff2_c, buff2_rs);
    }
}
