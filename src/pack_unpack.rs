use crate::saber_params::*;
use crate::U16;
use std::convert::TryFrom;
use std::error::Error;
use std::num::Wrapping;

/// Serialize coefficients of polynomial `data` into bytestream `bytes`.
/// Used in Saber's encryption step.
pub(crate) fn polt2bs(bytes: &mut [u8; SABER_SCALEBYTES_KEM], data: [U16; SABER_N]) {
    let (mut offset_byte, mut offsetdata): (usize, usize);

    if cfg!(SABER_L_IS_2) {
        for j in 0..(SABER_N / 8) as usize {
            offset_byte = 3 * j;
            offsetdata = 8 * j;
            bytes[offset_byte] = ((data[offsetdata] & U16!(0x7))
                | ((data[offsetdata + 1] & U16!(0x7)) << 3)
                | ((data[offsetdata + 2] & U16!(0x3)) << 6))
                .0 as u8;
            bytes[offset_byte + 1] = (((data[offsetdata + 2] >> 2) & U16!(0x01))
                | ((data[offsetdata + 3] & U16!(0x7)) << 1)
                | ((data[offsetdata + 4] & U16!(0x7)) << 4)
                | (((data[offsetdata + 5]) & U16!(0x01)) << 7))
                .0 as u8;
            bytes[offset_byte + 2] = (((data[offsetdata + 5] >> 1) & U16!(0x03))
                | ((data[offsetdata + 6] & U16!(0x7)) << 2)
                | ((data[offsetdata + 7] & U16!(0x7)) << 5))
                .0 as u8;
        }
    } else if cfg!(SABER_L_IS_3) {
        for j in 0..(SABER_N / 2) as usize {
            offset_byte = j;
            offsetdata = 2 * j;
            bytes[offset_byte] = ((data[offsetdata] & U16!(0x0f))
                | ((data[offsetdata + 1] & U16!(0x0f)) << 4))
                .0 as u8;
        }
    } else if cfg!(SABER_L_IS_4) {
        for j in 0..(SABER_N / 4) as usize {
            offset_byte = 3 * j;
            offsetdata = 4 * j;
            bytes[offset_byte] = ((data[offsetdata] & U16!(0x3f))
                | ((data[offsetdata + 1] & U16!(0x03)) << 6))
                .0 as u8;
            bytes[offset_byte + 1] = (((data[offsetdata + 1] >> 2) & U16!(0x0f))
                | ((data[offsetdata + 2] & U16!(0x0f)) << 4))
                .0 as u8;
            bytes[offset_byte + 2] = (((data[offsetdata + 2] >> 4) & U16!(0x03))
                | ((data[offsetdata + 3] & U16!(0x3f)) << 2))
                .0 as u8;
        }
    }
}

/// Deserialize bytestream `bytes` into polynomial coefficients `data`.
/// Used during Saber's decryption step.
pub(crate) fn bs2polt(bytes: [u8; SABER_SCALEBYTES_KEM], data: &mut [U16; SABER_N]) {
    let (mut offset_byte, mut offsetdata): (usize, usize);

    if cfg!(SABER_L_IS_2) {
        for j in 0..(SABER_N / 8) as usize {
            offset_byte = 3 * j;
            offsetdata = 8 * j;
            data[offsetdata] = U16!((bytes[offset_byte]) as u16 & 0x07);
            data[offsetdata + 1] = U16!(((bytes[offset_byte]) as u16 >> 3) & 0x07);
            data[offsetdata + 2] = U16!(
                (((bytes[offset_byte]) as u16 >> 6) & 0x03)
                    | (((bytes[offset_byte + 1]) as u16 & 0x01) << 2)
            );
            data[offsetdata + 3] = U16!(((bytes[offset_byte + 1]) as u16 >> 1) & 0x07);
            data[offsetdata + 4] = U16!(((bytes[offset_byte + 1]) as u16 >> 4) & 0x07);
            data[offsetdata + 5] = U16!(
                (((bytes[offset_byte + 1]) as u16 >> 7) & 0x01)
                    | (((bytes[offset_byte + 2]) as u16 & 0x03) << 1)
            );
            data[offsetdata + 6] = U16!((bytes[offset_byte + 2] as u16 >> 2) & 0x07);
            data[offsetdata + 7] = U16!((bytes[offset_byte + 2] as u16 >> 5) & 0x07);
        }
    } else if cfg!(SABER_L_IS_3) {
        for j in 0..(SABER_N / 2) as usize {
            offset_byte = j;
            offsetdata = 2 * j;
            data[offsetdata] = U16!((bytes[offset_byte] & 0x0f) as u16);
            data[offsetdata + 1] = U16!(((bytes[offset_byte] >> 4) & 0x0f) as u16);
        }
    } else if cfg!(SABER_L_IS_4) {
        for j in 0..(SABER_N / 4) as usize {
            offset_byte = 3 * j;
            offsetdata = 4 * j;
            data[offsetdata] = U16!((bytes[offset_byte] & 0x3f) as u16);
            data[offsetdata + 1] = U16!(
                (((bytes[offset_byte] >> 6) & 0x03) | ((bytes[offset_byte + 1] & 0x0f) << 2))
                    as u16
            );
            data[offsetdata + 2] = U16!(
                ((bytes[offset_byte + 1] >> 4) | ((bytes[offset_byte + 2] & 0x03) << 4)) as u16
            );
            data[offsetdata + 3] = U16!((bytes[offset_byte + 2] >> 2) as u16);
        }
    }
}

/// Serialize coefficients of polynomial `data` into bytestream `bytes`.
/// Used during Saber's key generation step.
fn polq2bs(bytes: &mut [u8; SABER_POLYBYTES], data: [U16; SABER_N]) {
    let (mut offset_byte, mut offsetdata): (usize, usize);

    for j in 0..(SABER_N / 8) as usize {
        offset_byte = 13 * j;
        offsetdata = 8 * j;
        bytes[offset_byte] = (data[offsetdata] & U16!(0xff)).0 as u8;
        bytes[offset_byte + 1] = (((data[offsetdata] >> 8) & U16!(0x1f))
            | ((data[offsetdata + 1] & U16!(0x07)) << 5))
            .0 as u8;
        bytes[offset_byte + 2] = ((data[offsetdata + 1] >> 3) & U16!(0xff)).0 as u8;
        bytes[offset_byte + 3] = (((data[offsetdata + 1] >> 11) & U16!(0x03))
            | ((data[offsetdata + 2] & U16!(0x3f)) << 2))
            .0 as u8;
        bytes[offset_byte + 4] = (((data[offsetdata + 2] >> 6) & U16!(0x7f))
            | ((data[offsetdata + 3] & U16!(0x01)) << 7))
            .0 as u8;
        bytes[offset_byte + 5] = ((data[offsetdata + 3] >> 1) & U16!(0xff)).0 as u8;
        bytes[offset_byte + 6] = (((data[offsetdata + 3] >> 9) & U16!(0x0f))
            | ((data[offsetdata + 4] & U16!(0x0f)) << 4))
            .0 as u8;
        bytes[offset_byte + 7] = ((data[offsetdata + 4] >> 4) & U16!(0xff)).0 as u8;
        bytes[offset_byte + 8] = (((data[offsetdata + 4] >> 12) & U16!(0x01))
            | ((data[offsetdata + 5] & U16!(0x7f)) << 1))
            .0 as u8;
        bytes[offset_byte + 9] = (((data[offsetdata + 5] >> 7) & U16!(0x3f))
            | ((data[offsetdata + 6] & U16!(0x03)) << 6))
            .0 as u8;
        bytes[offset_byte + 10] = ((data[offsetdata + 6] >> 2) & U16!(0xff)).0 as u8;
        bytes[offset_byte + 11] = (((data[offsetdata + 6] >> 10) & U16!(0x07))
            | ((data[offsetdata + 7] & U16!(0x1f)) << 3))
            .0 as u8;
        bytes[offset_byte + 12] = ((data[offsetdata + 7] >> 5) & U16!(0xff)).0 as u8;
    }
}

/// Deserialize bytestream `bytes` into polynomial coefficients `data`.
/// Used during Saber's key generation step.
fn bs2polq(bytes: [u8; SABER_POLYBYTES], data: &mut [U16; SABER_N]) {
    let (mut offset_byte, mut offsetdata): (usize, usize);

    for j in 0..(SABER_N / 8) as usize {
        offset_byte = 13 * j;
        offsetdata = 8 * j;
        data[offsetdata] = U16!(
            (bytes[offset_byte] as u16 & (0xff)) | ((bytes[offset_byte + 1] as u16 & 0x1f) << 8)
        );
        data[offsetdata + 1] = U16!(
            (bytes[offset_byte + 1] as u16 >> 5 & (0x07))
                | ((bytes[offset_byte + 2] as u16 & 0xff) << 3)
                | ((bytes[offset_byte + 3] as u16 & 0x03) << 11)
        );
        data[offsetdata + 2] = U16!(
            (bytes[offset_byte + 3] as u16 >> 2 & (0x3f))
                | ((bytes[offset_byte + 4] as u16 & 0x7f) << 6)
        );
        data[offsetdata + 3] = U16!(
            (bytes[offset_byte + 4] as u16 >> 7 & (0x01))
                | ((bytes[offset_byte + 5] as u16 & 0xff) << 1)
                | ((bytes[offset_byte + 6] as u16 & 0x0f) << 9)
        );
        data[offsetdata + 4] = U16!(
            (bytes[offset_byte + 6] as u16 >> 4 & (0x0f))
                | ((bytes[offset_byte + 7] as u16 & 0xff) << 4)
                | ((bytes[offset_byte + 8] as u16 & 0x01) << 12)
        );
        data[offsetdata + 5] = U16!(
            (bytes[offset_byte + 8] as u16 >> 1 & (0x7f))
                | ((bytes[offset_byte + 9] as u16 & 0x3f) << 7)
        );
        data[offsetdata + 6] = U16!(
            (bytes[offset_byte + 9] as u16 >> 6 & (0x03))
                | ((bytes[offset_byte + 10] as u16 & 0xff) << 2)
                | ((bytes[offset_byte + 11] as u16 & 0x07) << 10)
        );
        data[offsetdata + 7] = U16!(
            (bytes[offset_byte + 11] as u16 >> 3 & (0x1f))
                | ((bytes[offset_byte + 12] as u16 & 0xff) << 5)
        );
    }
}

/// Serialize coefficients of polynomial `data` into bytestream `bytes`.
/// Used during Saber's key generation and encryption step.
fn polp2bs(bytes: &mut [u8; SABER_POLYCOMPRESSEDBYTES], data: [U16; SABER_N]) {
    let (mut offset_byte, mut offsetdata): (usize, usize);

    for j in 0..(SABER_N / 4) as usize {
        offset_byte = 5 * j;
        offsetdata = 4 * j;
        bytes[offset_byte] = (data[offsetdata] & U16!(0xff)).0 as u8;
        bytes[offset_byte + 1] = (((data[offsetdata] >> 8) & U16!(0x03))
            | ((data[offsetdata + 1] & U16!(0x3f)) << 2))
            .0 as u8;
        bytes[offset_byte + 2] = (((data[offsetdata + 1] >> 6) & U16!(0x0f))
            | ((data[offsetdata + 2] & U16!(0x0f)) << 4))
            .0 as u8;
        bytes[offset_byte + 3] = (((data[offsetdata + 2] >> 4) & U16!(0x3f))
            | ((data[offsetdata + 3] & U16!(0x03)) << 6))
            .0 as u8;
        bytes[offset_byte + 4] = ((data[offsetdata + 3] >> 2) & U16!(0xff)).0 as u8;
    }
}

/// Deserialize bytestream `bytes` into polynomial coefficients `data`.
/// Used during Saber's decryption step.
fn bs2polp(bytes: [u8; SABER_POLYCOMPRESSEDBYTES], data: &mut [U16; SABER_N]) {
    let (mut offset_byte, mut offsetdata): (usize, usize);

    for j in 0..(SABER_N / 4) as usize {
        offset_byte = 5 * j;
        offsetdata = 4 * j;
        data[offsetdata] = U16!(
            (bytes[offset_byte] as u16 & (0xff)) | ((bytes[offset_byte + 1] as u16 & 0x03) << 8)
        );
        data[offsetdata + 1] = U16!(
            ((bytes[offset_byte + 1] as u16 >> 2) & (0x3f))
                | ((bytes[offset_byte + 2] as u16 & 0x0f) << 6)
        );
        data[offsetdata + 2] = U16!(
            ((bytes[offset_byte + 2] as u16 >> 4) & (0x0f))
                | ((bytes[offset_byte + 3] as u16 & 0x3f) << 4)
        );
        data[offsetdata + 3] = U16!(
            ((bytes[offset_byte + 3] as u16 >> 6) & (0x03))
                | ((bytes[offset_byte + 4] as u16 & 0xff) << 2)
        );
    }
}

/// Applies `polq2bs` to a vector (i.e. module).
/// Takes a vector of polynomials `data` and returns the serialized `bytes`.
pub(crate) fn polvecq2bs(
    bytes: &mut [u8; SABER_POLYVECBYTES],
    data: [[U16; SABER_N]; SABER_L],
) -> Result<(), Box<dyn Error>> {
    for j in 0..SABER_L {
        let tmp = <&mut [u8; SABER_POLYBYTES]>::try_from(
            &mut bytes[(j * SABER_POLYBYTES)..((j + 1) * SABER_POLYBYTES)],
        )?;

        polq2bs(tmp, data[j]);
    }
    Ok(())
}

/// Applies `bs2polq` to a vector (i.e. module).
/// Takes serialized `bytes` and deserializes them to a vector of polynomials `data`.
pub(crate) fn bs2polvecq(bytes: [u8; SABER_POLYVECBYTES], data: &mut [[U16; SABER_N]; SABER_L]) {
    for j in 0..SABER_L {
        let mut tmp: [u8; SABER_POLYBYTES] = [0; SABER_POLYBYTES];
        tmp.copy_from_slice(&bytes[(j * SABER_POLYBYTES)..((j + 1) * SABER_POLYBYTES)]);
        bs2polq(tmp, &mut data[j]);
    }
}

/// Applies `polp2bs` to a vector (i.e. module).
/// Takes a vector of polynomials `data` and returns the serialized `bytes`.
pub(crate) fn polvecp2bs(
    bytes: &mut [u8; SABER_POLYVECCOMPRESSEDBYTES],
    data: [[U16; SABER_N]; SABER_L],
) -> Result<(), Box<dyn Error>> {
    for j in 0..SABER_L {
        let tmp = <&mut [u8; SABER_POLYCOMPRESSEDBYTES]>::try_from(
            &mut bytes[(j * SABER_POLYCOMPRESSEDBYTES)..((j + 1) * SABER_POLYCOMPRESSEDBYTES)],
        )?;
        polp2bs(tmp, data[j]);
    }
    Ok(())
}

/// Applies `bs2polp` to a vector (i.e. module).
/// Takes serialized `bytes` and deserializes them to a vector of polynomials `data`.
pub(crate) fn bs2polvecp(
    bytes: [u8; SABER_POLYVECCOMPRESSEDBYTES],
    data: &mut [[U16; SABER_N]; SABER_L],
) {
    for j in 0..SABER_L {
        let mut tmp: [u8; SABER_POLYCOMPRESSEDBYTES] = [0; SABER_POLYCOMPRESSEDBYTES];
        tmp.copy_from_slice(
            &bytes[(j * SABER_POLYCOMPRESSEDBYTES)..((j + 1) * SABER_POLYCOMPRESSEDBYTES)],
        );
        bs2polp(tmp, &mut data[j]);
    }
}

/// Serializes the message-to-encrypt `data` to a bytestream `bytes`.
/// Used in Saber's decryption step.
pub(crate) fn polmsg2bs(bytes: &mut [u8; SABER_KEYBYTES], data: [U16; SABER_N]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }

    for j in 0..SABER_KEYBYTES {
        for i in 0..8 {
            bytes[j] |= ((data[j * 8 + i] & U16!(0x01)) << i).0 as u8;
        }
    }
}

/// Deserializes bytestream `bytes` to the message-to-encrypt `data`.
/// Used in Saber's encryption step.
pub(crate) fn bs2polmsg(bytes: [u8; SABER_KEYBYTES], data: &mut [U16; SABER_N]) {
    for j in 0..SABER_KEYBYTES {
        for i in 0..8 {
            data[j * 8 + i] = U16!(((bytes[j] >> i) & 0x01) as u16);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::link_c_reference::{
        BS2POLVECp, BS2POLVECq, BS2POLmsg, BS2POLp, BS2POLq, POLVECp2BS, POLVECq2BS, POLmsg2BS,
        POLp2BS, POLq2BS, BS2POLT, POLT2BS,
    };
    use crate::pack_unpack::*;
    use rand::Rng;

    #[test]
    fn test_polt2bs() {
        const SIZE_BYTES: usize = SABER_SCALEBYTES_KEM;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        wrappedu162u16(&mut copy_data[..], &data[..]);

        unsafe {
            POLT2BS(&mut copy_bytes, &mut copy_data);
        };

        polt2bs(&mut bytes, data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check, &data[..]);
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_bs2polt() {
        const SIZE_BYTES: usize = SABER_SCALEBYTES_KEM;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        wrappedu162u16(&mut copy_data[..], &data[..]);
        unsafe {
            BS2POLT(&mut copy_bytes, &mut copy_data);
        };

        bs2polt(bytes, &mut data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check[..], &data[..]);
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_polq2bs() {
        const SIZE_BYTES: usize = SABER_POLYBYTES;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        //copy_data.copy_from_slice(&data[..]);
        wrappedu162u16(&mut copy_data[..], &data[..]);
        unsafe {
            POLq2BS(&mut copy_bytes, &mut copy_data);
        };

        polq2bs(&mut bytes, data);
        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check[..], &data[..]);
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_bs2polq() {
        const SIZE_BYTES: usize = SABER_POLYBYTES;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        wrappedu162u16(&mut copy_data[..], &data[..]);
        unsafe {
            BS2POLq(&mut copy_bytes, &mut copy_data);
        };

        bs2polq(bytes, &mut data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check[..], &data[..]);
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_polp2bs() {
        const SIZE_BYTES: usize = SABER_POLYCOMPRESSEDBYTES;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        wrappedu162u16(&mut copy_data[..], &data[..]);
        unsafe {
            POLp2BS(&mut copy_bytes, &mut copy_data);
        };

        polp2bs(&mut bytes, data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check[..], &data[..]);
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_bs2polp() {
        const SIZE_BYTES: usize = SABER_POLYCOMPRESSEDBYTES;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        wrappedu162u16(&mut copy_data[..], &data[..]);
        unsafe {
            BS2POLp(&mut copy_bytes, &mut copy_data);
        };

        bs2polp(bytes, &mut data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check[..], &data[..]);
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_polvecq2bs() {
        const SIZE_BYTES: usize = SABER_POLYVECBYTES;
        const SIZE_DATA: usize = SABER_N;
        const SIZE_DATA2: usize = SABER_L;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [[U16!(0); SIZE_DATA]; SIZE_DATA2];

        let mut ind = 0;
        while ind < data.len() {
            let mut ind2 = 0;
            while ind2 < data[ind].len() {
                data[ind][ind2] = rng.gen();
                ind2 += 1;
            }
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [[u16; SIZE_DATA]; SIZE_DATA2] = [[0; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut copy_data[i][..], &data[i][..]);
        }
        unsafe {
            POLVECq2BS(&mut copy_bytes, &mut copy_data);
        };

        polvecq2bs(&mut bytes, data).expect("polvecq2bs failed!");

        assert_eq!(copy_bytes, bytes);
        let mut check = [[0u16; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut check[i][..], &data[i][..]);
        }
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_bs2polvecq() {
        const SIZE_BYTES: usize = SABER_POLYVECBYTES;
        const SIZE_DATA: usize = SABER_N;
        const SIZE_DATA2: usize = SABER_L;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [[U16!(0); SIZE_DATA]; SIZE_DATA2];

        let mut ind = 0;
        while ind < data.len() {
            let mut ind2 = 0;
            while ind2 < data[ind].len() {
                data[ind][ind2] = rng.gen();
                ind2 += 1;
            }
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [[u16; SIZE_DATA]; SIZE_DATA2] = [[0; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut copy_data[i][..], &data[i][..]);
        }
        unsafe {
            BS2POLVECq(&mut copy_bytes, &mut copy_data);
        };

        bs2polvecq(bytes, &mut data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [[0u16; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut check[i][..], &data[i][..]);
        }
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_polvecp2bs() {
        const SIZE_BYTES: usize = SABER_POLYVECCOMPRESSEDBYTES;
        const SIZE_DATA: usize = SABER_N;
        const SIZE_DATA2: usize = SABER_L;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [[U16!(0); SIZE_DATA]; SIZE_DATA2];

        let mut ind = 0;
        while ind < data.len() {
            let mut ind2 = 0;
            while ind2 < data[ind].len() {
                data[ind][ind2] = rng.gen();
                ind2 += 1;
            }
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [[u16; SIZE_DATA]; SIZE_DATA2] = [[0; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut copy_data[i][..], &data[i][..]);
        }
        unsafe {
            POLVECp2BS(&mut copy_bytes, &mut copy_data);
        };

        polvecp2bs(&mut bytes, data).expect("polvecp2bs failed!");

        assert_eq!(copy_bytes, bytes);
        let mut check = [[0u16; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut check[i][..], &data[i][..]);
        }
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_bs2polvecp() {
        const SIZE_BYTES: usize = SABER_POLYVECCOMPRESSEDBYTES;
        const SIZE_DATA: usize = SABER_N;
        const SIZE_DATA2: usize = SABER_L;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [[U16!(0); SIZE_DATA]; SIZE_DATA2];

        let mut ind = 0;
        while ind < data.len() {
            let mut ind2 = 0;
            while ind2 < data[ind].len() {
                data[ind][ind2] = rng.gen();
                ind2 += 1;
            }
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [[u16; SIZE_DATA]; SIZE_DATA2] = [[0; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut copy_data[i][..], &data[i][..]);
        }
        unsafe {
            BS2POLVECp(&mut copy_bytes, &mut copy_data);
        };

        bs2polvecp(bytes, &mut data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [[0u16; SIZE_DATA]; SIZE_DATA2];
        for i in 0..SIZE_DATA2 {
            wrappedu162u16(&mut check[i][..], &data[i][..]);
        }
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_bs2polmsg() {
        const SIZE_BYTES: usize = SABER_KEYBYTES;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        wrappedu162u16(&mut copy_data[..], &data[..]);
        unsafe {
            BS2POLmsg(&mut copy_bytes, &mut copy_data);
        };

        bs2polmsg(bytes, &mut data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check[..], &data[..]);
        assert_eq!(copy_data, check);
    }

    #[test]
    fn test_polmsg2bs() {
        const SIZE_BYTES: usize = SABER_KEYBYTES;
        const SIZE_DATA: usize = SABER_N;

        let mut rng = rand::thread_rng();
        let mut bytes = [0; SIZE_BYTES];

        let mut data = [U16!(0); SIZE_DATA];

        let mut ind = 0;
        while ind < data.len() {
            data[ind] = rng.gen();
            ind += 1;
        }
        ind = 0;
        while ind < bytes.len() {
            bytes[ind] = rng.gen();
            ind += 1;
        }

        //to check if equal
        let mut copy_bytes: [u8; SIZE_BYTES] = [0; SIZE_BYTES];
        copy_bytes.copy_from_slice(&bytes[..]);
        let mut copy_data: [u16; SIZE_DATA] = [0; SIZE_DATA];
        wrappedu162u16(&mut copy_data[..], &data[..]);
        unsafe {
            POLmsg2BS(&mut copy_bytes, &mut copy_data);
        };

        polmsg2bs(&mut bytes, data);

        assert_eq!(copy_bytes, bytes);
        let mut check = [0u16; SIZE_DATA];
        wrappedu162u16(&mut check[..], &data[..]);
        assert_eq!(copy_data, check);
    }
}
