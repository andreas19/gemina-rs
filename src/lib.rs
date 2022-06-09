#![allow(unused_variables, dead_code)] // XXX

pub enum Version { V1, V2, V3, V4 }

struct VersionProp {
    version_byte: u8,
    enc_key_len: u8, // bytes
    mac_key_len: u8, // bytes
}

const VERSION_PROPS: [VersionProp; 4] = [
    VersionProp { version_byte: 0x8a, enc_key_len: 16, mac_key_len: 16 },
    VersionProp { version_byte: 0x8b, enc_key_len: 16, mac_key_len: 32 },
    VersionProp { version_byte: 0x8c, enc_key_len: 24, mac_key_len: 32 },
    VersionProp { version_byte: 0x8d, enc_key_len: 32, mac_key_len: 32 },
];

pub fn create_secret_key(version: Version) -> () { // TODO
    
}

pub fn decrypt_with_key(key: &[u8], data: &[u8]) -> () { // TODO
    
}

pub fn decrypt_with_password(password: &[u8], data: &[u8]) -> () { // TODO
    
}

pub fn encrypt_with_key(key: &[u8], data: &[u8], version: Version) -> () { // TODO
    
}

pub fn encrypt_with_password(password: &[u8], data: &[u8], version: Version) -> () { // TODO
    
}

pub fn verify_with_key(key: &[u8], data: &[u8]) -> bool { // TODO
    false
}

pub fn verify_with_password(password: &[u8], data: &[u8]) -> bool { // TODO
    false
}



#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
