pub fn poly1305aes_clamp(kr: &mut [u8; 32]) {
    kr[19] = kr[19] & 15;  // r[3]
    kr[20] = kr[20] & 252; // r[4]
    kr[21] = kr[21] & 15;  // r[5]
    kr[23] = kr[23] & 15;  // r[7]
    kr[24] = kr[24] & 252; // r[8]
    kr[27] = kr[27] & 15;  // r[11]
    kr[28] = kr[28] & 252; // r[13]
}

pub fn poly1305aes_authenticate(kr: [u8; 32],
                                n: [u8; 16],
                                _m: &[u8]) -> [u8; 16] {
    let k = &kr[0..16];
    let r = &kr[16..32];

    println!("k: {:?}", k);
    println!("r: {:?}", r);
    println!("n: {:?}", n);
    [0; 16]
}

#[cfg(test)]
mod test {
    use poly1305aes::{poly1305aes_authenticate,poly1305aes_clamp};
    use rand::{OsRng,Rng};

    fn bottom_two_bits_zeroed(val: u8) -> bool {
        val % 4 == 0
    }

    fn top_four_bits_zeroed(val: u8) -> bool {
        val < 16
    }

    #[test]
    fn test_clamp() {
        let mut k: [u8; 32] = [0; 32];

        let mut rng = match OsRng::new() {
            Ok(rng) => rng,
            Err(e)  => panic!("Failed to create rng! {}", e),
        };

        rng.fill_bytes(&mut k);
        poly1305aes_clamp(&mut k);

        assert!(top_four_bits_zeroed(k[19]));
        assert!(bottom_two_bits_zeroed(k[20]));
        assert!(top_four_bits_zeroed(k[21]));
        assert!(top_four_bits_zeroed(k[23]));
        assert!(bottom_two_bits_zeroed(k[24]));
        assert!(bottom_two_bits_zeroed(k[28]));
    }

    #[test]
    fn test_authenticate() {
        let mut k: [u8; 32] = [0; 32];
        let m = b"This is a test";
        let mut rng = match OsRng::new() {
            Ok(rng) => rng,
            Err(e)  => panic!("Failed to create rng! {}", e),
        };

        rng.fill_bytes(&mut k);
        poly1305aes_clamp(&mut k);
        let _ = poly1305aes_authenticate(k, [0; 16], &m[..]);
    }
}
