//! Implementation of the Gemina format.
//!
//! For more information see the [specification].
//!
//! [specification]: https://github.com/andreas19/gemina-spec#specification-of-the-gemina-format

use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes128, Aes192, Aes256,
};
use anyhow::{anyhow, bail, Result};
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const IV_LEN: usize = 16; // bytes
const BLOCK_LEN: usize = 16; // bytes
const MAC_LEN: usize = 32; // bytes
const SALT_LEN: usize = 16; // bytes
const VERSION_LEN: usize = 1; // byte
const MIN_LEN: usize = VERSION_LEN + 2 * BLOCK_LEN + MAC_LEN;
const ITERATIONS: u32 = 100_000;

type HmacSha256 = Hmac<Sha256>;

/// Version enum.
#[derive(Clone, Copy)]
pub enum Version {
    /// Version 1
    V1,
    /// Version 2
    V2,
    /// Version 3
    V3,
    /// Version 4
    V4,
}

struct VersionProperties {
    version: Version,
    version_byte: u8,
    enc_key_len: usize, // bytes
    mac_key_len: usize, // bytes
}

const VERSION_PROPS: [VersionProperties; 4] = [
    VersionProperties {
        version: Version::V1,
        version_byte: 0x8a,
        enc_key_len: 16,
        mac_key_len: 16,
    },
    VersionProperties {
        version: Version::V2,
        version_byte: 0x8b,
        enc_key_len: 16,
        mac_key_len: 32,
    },
    VersionProperties {
        version: Version::V3,
        version_byte: 0x8c,
        enc_key_len: 24,
        mac_key_len: 32,
    },
    VersionProperties {
        version: Version::V4,
        version_byte: 0x8d,
        enc_key_len: 32,
        mac_key_len: 32,
    },
];

/// Creates a secret key.
pub fn create_secret_key(version: Version) -> Result<Vec<u8>> {
    let props = &VERSION_PROPS[version as usize];
    let mut key = vec![0u8; props.enc_key_len + props.mac_key_len];
    getrandom::getrandom(&mut key)?;
    Ok(key)
}

/// Decrypts data using a secret key.
pub fn decrypt_with_key(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let props = version_properties(data, false)?;
    decrypt(key, data, props, false)
}

/// Decrypts data using a password.
pub fn decrypt_with_password(password: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let props = version_properties(data, true)?;
    let (key, _) = derive_key(password, &data[VERSION_LEN..VERSION_LEN + SALT_LEN], props)?;
    decrypt(&key, data, props, true)
}

/// Encrypts data using a secret key.
pub fn encrypt_with_key(key: &[u8], data: &[u8], version: Version) -> Result<Vec<u8>> {
    let props = &VERSION_PROPS[version as usize];
    encrypt(key, &[], data, props)
}

/// Encrypts data using a password.
pub fn encrypt_with_password(password: &[u8], data: &[u8], version: Version) -> Result<Vec<u8>> {
    let props = &VERSION_PROPS[version as usize];
    let (key, salt) = derive_key(password, &[], props)?;
    encrypt(&key, &salt, data, props)
}

/// Verifies encrypted data using a secret key.
pub fn verify_with_key(key: &[u8], data: &[u8]) -> bool {
    if let Ok(props) = version_properties(data, false) {
        verify(key, data, props)
    } else {
        false
    }
}

/// Verifies encrypted data using a password.
pub fn verify_with_password(password: &[u8], data: &[u8]) -> bool {
    if let Ok(props) = version_properties(data, true) {
        if let Ok((key, _)) =
            derive_key(password, &data[VERSION_LEN..VERSION_LEN + SALT_LEN], props)
        {
            return verify(&key, data, props);
        }
    }
    false
}

fn decrypt(key: &[u8], data: &[u8], props: &VersionProperties, with_salt: bool) -> Result<Vec<u8>> {
    let (enc_key, mac_key) = split_key(key, props)?;
    if !verify2(mac_key, data) {
        bail!("signature could not be verified")
    }
    let iv_start_pos = if with_salt {
        VERSION_LEN + SALT_LEN
    } else {
        VERSION_LEN
    };
    let ct_start_pos = iv_start_pos + IV_LEN;
    let iv = &data[iv_start_pos..ct_start_pos];
    let ct = &data[ct_start_pos..data.len() - MAC_LEN];
    let res =
        match props.version {
            Version::V1 | Version::V2 => Decryptor::<Aes128>::new(enc_key.into(), iv.into())
                .decrypt_padded_vec_mut::<Pkcs7>(ct),
            Version::V3 => Decryptor::<Aes192>::new(enc_key.into(), iv.into())
                .decrypt_padded_vec_mut::<Pkcs7>(ct),
            Version::V4 => Decryptor::<Aes256>::new(enc_key.into(), iv.into())
                .decrypt_padded_vec_mut::<Pkcs7>(ct),
        };
    Ok(res?)
}

fn encrypt(key: &[u8], salt: &[u8], data: &[u8], props: &VersionProperties) -> Result<Vec<u8>> {
    let (enc_key, mac_key) = split_key(key, props)?;
    let mut vec = vec![props.version_byte];
    vec.extend_from_slice(salt);
    let mut iv = [0u8; IV_LEN];
    getrandom::getrandom(&mut iv)?;
    vec.extend_from_slice(&iv[..]);
    let mut ct = match props.version {
        Version::V1 | Version::V2 => Encryptor::<Aes128>::new(enc_key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(data),
        Version::V3 => Encryptor::<Aes192>::new(enc_key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(data),
        Version::V4 => Encryptor::<Aes256>::new(enc_key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(data),
    };
    vec.append(&mut ct);
    let mut mac = HmacSha256::new_from_slice(mac_key).unwrap();
    mac.update(&vec);
    vec.extend_from_slice(mac.finalize().into_bytes().as_slice());
    Ok(vec)
}

fn verify(key: &[u8], data: &[u8], props: &VersionProperties) -> bool {
    if let Ok((_, mac_key)) = split_key(key, props) {
        verify2(mac_key, data)
    } else {
        false
    }
}

fn verify2(mac_key: &[u8], data: &[u8]) -> bool {
    let pos = data.len() - MAC_LEN;
    let mut mac = HmacSha256::new_from_slice(mac_key).unwrap();
    mac.update(&data[..pos]);
    mac.verify_slice(&data[pos..]).is_ok()
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    props: &VersionProperties,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut key = vec![0u8; props.enc_key_len + props.mac_key_len];
    let salt_vec = if salt.is_empty() {
        let mut buf = [0u8; SALT_LEN];
        getrandom::getrandom(&mut buf)?;
        Vec::from(buf)
    } else {
        Vec::from(salt)
    };

    pbkdf2::pbkdf2::<HmacSha256>(password, &salt_vec, ITERATIONS, &mut key);
    Ok((key, salt_vec))
}

fn split_key<'a>(key: &'a [u8], props: &VersionProperties) -> Result<(&'a [u8], &'a [u8])> {
    if key.len() == props.enc_key_len + props.mac_key_len {
        Ok((&key[..props.enc_key_len], &key[props.enc_key_len..]))
    } else {
        Err(anyhow!("incorrect secret key size"))
    }
}

fn version_properties(data: &[u8], with_salt: bool) -> Result<&VersionProperties> {
    let min_len = if with_salt {
        MIN_LEN + SALT_LEN
    } else {
        MIN_LEN
    };
    if data.len() < min_len {
        bail!("not enough data");
    }
    for props in &VERSION_PROPS {
        if props.version_byte == data[0] {
            return Ok(props);
        }
    }
    Err(anyhow!("unknown version"))
}
