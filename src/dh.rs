use rand;

use num::{BigUint, Zero, One};
use num::bigint::RandBigInt;
use num::cast::FromPrimitive;

// From rfc 2409 (https://tools.ietf.org/html/rfc2409).
pub const RFC2409_PRIME_768: [u8; 96] = [
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
        0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
        0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
        0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
        0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
        0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
        0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
        0xA6,0x3A,0x36,0x20,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    ];

pub const RFC2409_GENERATOR_768: u64 = 2;

pub const RFC2409_PRIME_1024: [u8; 128] = [
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
        0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
        0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
        0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
        0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
        0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
        0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
        0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
        0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
        0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE6,0x53,0x81,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    ];

pub const RFC2409_GENERATOR_1024: u64 = 2;



fn modular_power(mut base: BigUint, mut exponent: BigUint, modulos: &BigUint) -> BigUint {
    let one = BigUint::one();
    if modulos == &one {
        return one;
    }
    let mut result = BigUint::one();
    base = base % modulos;
    while exponent > BigUint::zero() {
        if &exponent % BigUint::from_u32(2 as u32).expect("Could not convert 2") == one {
            result = (&result * &base) % modulos;
        }
        exponent = exponent >> 1;
        base = (&base * &base) % modulos;
    }

    result
}

pub struct DHPublicKey {
    pub_key: BigUint,
}

impl DHPublicKey {
    pub fn new(pub_key: &[u8]) -> DHPublicKey {
        DHPublicKey {
            pub_key: BigUint::from_bytes_be(pub_key)
        }
    }
}

pub struct DHPrivateKey<'a> {
    params: &'a DHParameters,
    priv_key: BigUint,
}

impl DHPublicKey {
    pub fn key(&self) -> Vec<u8> {
        self.pub_key.to_bytes_be()
    }
}

impl<'a> DHPrivateKey<'a> {
    pub fn key(&self) -> Vec<u8> {
        self.priv_key.to_bytes_be()
    }

    pub fn public_key(&self) -> DHPublicKey {
        let pub_key = modular_power(self.params.g.clone(), self.priv_key.clone(), &self.params.p);

        DHPublicKey {
            pub_key: pub_key
        }
    }

    pub fn exchange(&self, pub_key: &DHPublicKey) -> Vec<u8> {
        let shared_key = modular_power(pub_key.pub_key.clone(), self.priv_key.clone(), &self.params.p);
        shared_key.to_bytes_be()
    }
}

pub struct DHParameters {
    p: BigUint,
    g: BigUint,
}

impl DHParameters {
    pub fn new(p: &[u8], g: u64) -> DHParameters {
        DHParameters {
            p: BigUint::from_bytes_be(p),
            g: BigUint::from_u64(g).expect("Could not convert g")
        }
    }

    pub fn key_length(&self) -> usize {
        self.p.bits()
    }

    pub fn private_key(&self) -> DHPrivateKey {
        let mut rng = match rand::OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Could not load the OS' RNG! Error: {}", e)
        };

        let mut priv_key = rng.gen_biguint(self.key_length());
        while (priv_key == BigUint::one()) || (priv_key == BigUint::zero()) {
            priv_key = rng.gen_biguint(self.key_length());
        }

        DHPrivateKey {
            params: self,
            priv_key: priv_key
        }
    }
}


#[cfg(test)]
mod tests {
    use dh::{DHParameters, modular_power, RFC2409_PRIME_768, RFC2409_GENERATOR_768,
        RFC2409_PRIME_1024, RFC2409_GENERATOR_1024};
    use num::{BigUint};
    use num::cast::{FromPrimitive};

    #[test]
    fn test_modular_power() {
        let base = BigUint::from_u32(4 as u32).expect("Could not convert base");
        let exp = BigUint::from_u32(13 as u32).expect("Could not convert exp");
        let modulos = BigUint::from_u32(497 as u32).expect("Could not convert modulos");
        assert_eq!(modular_power(base, exp, &modulos), BigUint::from_u32(445 as u32).
            expect("Could not convert result"))
    }

    fn test_exhange_with_params(params: &DHParameters) {
        let priv_key1 = params.private_key();
        let priv_key2 = params.private_key();
        let pub_key1 = priv_key1.public_key();
        let pub_key2 = priv_key2.public_key();
        let shared_key1 = priv_key2.exchange(&pub_key1);
        let shared_key2 = priv_key1.exchange(&pub_key2);
        assert!(shared_key1 == shared_key2);
    }

    #[test]
    fn test_exchange() {
        test_exhange_with_params(&DHParameters::new(&[0x17], 5));
        test_exhange_with_params(&DHParameters::new(&RFC2409_PRIME_768, RFC2409_GENERATOR_768));
        test_exhange_with_params(&DHParameters::new(&RFC2409_PRIME_1024, RFC2409_GENERATOR_1024));
    }

}
