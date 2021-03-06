const VERSION: gemina::Version = gemina::Version::V4;
const PASSWORD: &str = "secret1234";
const TEXT: &str = "abcdeABCDE01234äöüßÄÖÜ";
// the following data has been created with PyGemina (https://pypi.org/project/pygemina/)
const KEY: &[u8] = &[
    50, 200, 14, 253, 108, 252, 42, 29, 41, 102, 69, 70, 106, 66, 164, 226, 130, 243, 169, 1, 70,
    214, 114, 133, 29, 168, 33, 28, 51, 58, 114, 65, 14, 244, 245, 64, 26, 143, 148, 247, 99, 230,
    181, 174, 242, 124, 107, 243, 224, 183, 31, 188, 129, 158, 138, 41, 41, 76, 135, 22, 176, 193,
    173, 164,
];
const DATA_K: &[u8] = &[
    141, 195, 137, 39, 18, 219, 146, 189, 198, 72, 8, 228, 26, 248, 174, 240, 239, 43, 102, 187,
    40, 111, 17, 233, 144, 121, 187, 245, 155, 50, 163, 31, 67, 244, 164, 237, 123, 146, 215, 187,
    238, 250, 157, 164, 255, 123, 1, 198, 112, 154, 109, 153, 238, 56, 168, 189, 52, 167, 207, 22,
    244, 151, 231, 115, 250, 204, 30, 39, 70, 189, 165, 120, 45, 39, 149, 176, 84, 223, 146, 69,
    225,
];
const DATA_P: &[u8] = &[
    141, 3, 186, 229, 230, 251, 96, 239, 32, 141, 237, 202, 182, 55, 121, 77, 45, 22, 49, 75, 2,
    249, 164, 114, 208, 148, 28, 110, 185, 48, 66, 79, 159, 19, 67, 116, 50, 203, 16, 35, 190, 209,
    130, 120, 60, 34, 64, 46, 90, 18, 71, 140, 227, 88, 58, 167, 128, 227, 44, 66, 31, 143, 124,
    131, 147, 65, 61, 39, 180, 117, 204, 160, 102, 29, 153, 196, 79, 40, 98, 215, 238, 176, 22, 41,
    103, 236, 136, 116, 92, 97, 112, 117, 222, 31, 252, 199, 12,
];
const DATA_E: &[u8] = &[
    141, 138, 201, 163, 133, 120, 141, 69, 194, 13, 220, 205, 178, 14, 112, 163, 92, 112, 185, 119,
    0, 9, 233, 206, 253, 148, 114, 210, 144, 222, 166, 236, 19, 219, 218, 97, 244, 113, 72, 104,
    174, 19, 138, 250, 192, 177, 195, 173, 141, 30, 2, 73, 53, 148, 139, 21, 82, 77, 94, 192, 29,
    90, 176, 208, 137,
];
// keys with errors
const KEY_E: &[u8] = &[
    0, 200, 14, 253, 108, 252, 42, 29, 41, 102, 69, 70, 106, 66, 164, 226, 130, 243, 169, 1, 70,
    214, 114, 133, 29, 168, 33, 28, 51, 58, 114, 65, 14, 244, 245, 64, 26, 143, 148, 247, 99, 230,
    181, 174, 242, 124, 107, 243, 224, 183, 31, 188, 129, 158, 138, 41, 41, 76, 135, 22, 176, 193,
    173, 164,
];
const KEY_M: &[u8] = &[
    50, 200, 14, 253, 108, 252, 42, 29, 41, 102, 69, 70, 106, 66, 164, 226, 130, 243, 169, 1, 70,
    214, 114, 133, 29, 168, 33, 28, 51, 58, 114, 65, 14, 244, 245, 64, 26, 143, 148, 247, 99, 230,
    181, 174, 242, 124, 107, 243, 224, 183, 31, 188, 129, 158, 138, 41, 41, 76, 135, 22, 176, 193,
    173, 0,
];
// data with errors
const DATA_D: &[u8] = &[
    141, 195, 137, 39, 18, 219, 146, 189, 198, 72, 8, 228, 26, 248, 174, 240, 239, 43, 102, 0, 40,
    111, 17, 233, 144, 121, 187, 245, 155, 50, 163, 31, 67, 244, 164, 237, 123, 146, 215, 187, 238,
    250, 157, 164, 255, 123, 1, 198, 112, 154, 109, 153, 238, 56, 168, 189, 52, 167, 207, 22, 244,
    151, 231, 115, 250, 204, 30, 39, 70, 189, 165, 120, 45, 39, 149, 176, 84, 223, 146, 69, 225,
];
const DATA_M: &[u8] = &[
    141, 195, 137, 39, 18, 219, 146, 189, 198, 72, 8, 228, 26, 248, 174, 240, 239, 43, 102, 187,
    40, 111, 17, 233, 144, 121, 187, 245, 155, 50, 163, 31, 67, 244, 164, 237, 123, 146, 215, 187,
    238, 250, 157, 164, 255, 123, 1, 198, 112, 154, 109, 153, 238, 56, 168, 189, 52, 167, 207, 22,
    244, 151, 231, 115, 250, 204, 30, 39, 70, 189, 165, 120, 45, 39, 149, 176, 84, 223, 146, 69, 0,
];

#[test]
fn test_decrypt_with_key() {
    let data = gemina::decrypt_with_key(KEY, DATA_K).unwrap();
    assert_eq!(String::from_utf8(data).unwrap(), TEXT);
}

#[test]
fn test_with_key() {
    let key = gemina::create_secret_key(VERSION).unwrap();
    let data = gemina::encrypt_with_key(&key, TEXT.as_bytes(), VERSION).unwrap();
    assert!(gemina::verify_with_key(&key, &data));
    let data = gemina::decrypt_with_key(&key, &data).unwrap();
    assert_eq!(String::from_utf8(data).unwrap(), TEXT);
}

#[test]
fn test_decrypt_with_password() {
    let data = gemina::decrypt_with_password(PASSWORD.as_bytes(), DATA_P).unwrap();
    assert_eq!(String::from_utf8(data).unwrap(), TEXT);
}

#[test]
fn test_with_password() {
    let pass = PASSWORD.as_bytes();
    let data = gemina::encrypt_with_password(pass, TEXT.as_bytes(), VERSION).unwrap();
    assert!(gemina::verify_with_password(pass, &data));
    let data = gemina::decrypt_with_password(pass, &data).unwrap();
    assert_eq!(String::from_utf8(data).unwrap(), TEXT);
}

#[test]
fn test_decrypt_empty() {
    let data = gemina::decrypt_with_key(KEY, DATA_E).unwrap();
    assert_eq!(String::from_utf8(data).unwrap(), "");
}

#[test]
fn test_empty() {
    let key = gemina::create_secret_key(VERSION).unwrap();
    let data = gemina::encrypt_with_key(&key, "".as_bytes(), VERSION).unwrap();
    assert!(gemina::verify_with_key(&key, &data));
    let data = gemina::decrypt_with_key(&key, &data).unwrap();
    assert_eq!(String::from_utf8(data).unwrap(), "");
}

#[test]
fn test_wrong_key() {
    assert!(gemina::verify_with_key(KEY_E, DATA_K));
    assert!(!gemina::verify_with_key(KEY_M, DATA_K));
    assert_ne!(
        gemina::decrypt_with_key(KEY_E, DATA_K)
            .unwrap_err()
            .to_string(),
        "signature could not be verified".to_string()
    );
    assert_eq!(
        gemina::decrypt_with_key(KEY_M, DATA_K)
            .unwrap_err()
            .to_string(),
        "signature could not be verified".to_string()
    );
    assert_eq!(
        gemina::encrypt_with_key(&KEY[1..], TEXT.as_bytes(), VERSION)
            .unwrap_err()
            .to_string(),
        "incorrect secret key size".to_string()
    );
}

#[test]
fn test_data_error() {
    assert!(!gemina::verify_with_key(KEY, DATA_D));
    assert_eq!(
        gemina::decrypt_with_key(KEY, DATA_D)
            .unwrap_err()
            .to_string(),
        "signature could not be verified".to_string()
    );
}

#[test]
fn test_mac_error() {
    assert!(!gemina::verify_with_key(KEY, DATA_M));
    assert_eq!(
        gemina::decrypt_with_key(KEY, DATA_M)
            .unwrap_err()
            .to_string(),
        "signature could not be verified".to_string()
    );
}
