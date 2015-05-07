use aessafe;
use mac::Mac;
use poly1305;
use serialize::hex::ToHex;
use symmetriccipher::BlockEncryptor;

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
                                m: &[u8],
                                out: &mut [u8; 16]) {
    let k = &kr[0..16];
    let r = &kr[16..32];
    let mut pk = [0; 32];

    for i in 0..16 {
        pk[i] = r[i];
    }

    let mut aeskn = [0; 16];
    let aes_enc = aessafe::AesSafe128Encryptor::new(k);
    aes_enc.encrypt_block(&n[..], &mut aeskn);

    for i in 16..32 {
        pk[i] = aeskn[i-16];
    }

    let mut poly = poly1305::Poly1305::new(&pk);
    poly.input(m);
    println!("k: {:?}", k.to_hex());
    println!("r: {:?}", r.to_hex());
    println!("n: {:?}", n.to_hex());
    println!("aeskn: {:?}", aeskn.to_hex());
    poly.raw_result(out);
    println!("out: {:?}", out.to_hex());
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
        let mut out: [u8; 16] = [0; 16];
        let m = b"This is a test";
        let mut rng = match OsRng::new() {
            Ok(rng) => rng,
            Err(e)  => panic!("Failed to create rng! {}", e),
        };

        rng.fill_bytes(&mut k);
        poly1305aes_clamp(&mut k);
        poly1305aes_authenticate(k, [0; 16], &m[..], &mut out);

        let mut out1: [u8; 16] = [0; 16];
        let kr: [u8; 32] = [0xec, 0x07, 0x4c, 0x83, 0x55, 0x80, 0x74, 0x17,
                            0x01, 0x42, 0x5b, 0x62, 0x32, 0x35, 0xad, 0xd6,
                            0x85, 0x1f, 0xc4, 0x0c, 0x34, 0x67, 0xac, 0x0b,
                            0xe0, 0x5c, 0xc2, 0x04, 0x04, 0xf3, 0xf7, 0x00];
        let n: [u8; 16] = [0xfb, 0x44, 0x73, 0x50, 0xc4, 0xe8, 0x68, 0xc5,
                           0x2a, 0xc3, 0x27, 0x5c, 0xf9, 0xd4, 0x32, 0x7e];

        poly1305aes_authenticate(kr, n, &[0xf3, 0xf6], &mut out1);

        let mut out2: [u8; 16] = [0; 16];
        let kr: [u8; 32] = [0x75, 0xde, 0xaa, 0x25, 0xc0, 0x9f, 0x20, 0x8e,
                            0x1d, 0xc4, 0xce, 0x6b, 0x5c, 0xad, 0x3f, 0xbf,
                            0xa0, 0xf3, 0x08, 0x00, 0x00, 0xf4, 0x64, 0x00,
                            0xd0, 0xc7, 0xe9, 0x07, 0x6c, 0x83, 0x44, 0x03];
        let n: [u8; 16] = [0x61, 0xee, 0x09, 0x21, 0x8d, 0x29, 0xb0, 0xaa,
                           0xed, 0x7e, 0x15, 0x4a, 0x2c, 0x55, 0x09, 0xcc];

        poly1305aes_authenticate(kr, n, &[], &mut out2);
    }
}
