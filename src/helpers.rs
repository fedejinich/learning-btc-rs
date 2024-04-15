use hex::decode;

pub fn hex_decode(s: &str) -> Vec<u8> {
    let d = match decode(s) {
        Ok(bytes) => bytes,
        Err(_) => panic!("invalid hex string"),
    };

    d
}
