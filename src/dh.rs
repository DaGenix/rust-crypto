use rand;

use num::{BigUint, Zero};
use num::bigint::RandBigInt;
use num::cast::FromPrimitive;


fn modular_power(mut base: BigUint, mut exponent: BigUint, modulos: &BigUint) -> BigUint {
    let one = BigUint::from_u32(1 as u32).expect("Could not convert 1");
    if modulos == &one {
        return one;
    }
    let mut result = one.clone();
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

    pub fn private_key(&self) -> DHPrivateKey {
        let mut rng = match rand::OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Could not load the OS' RNG! Error: {}", e)
        };

        let priv_key = rng.gen_biguint_below(&self.p);
        DHPrivateKey {
            params: self,
            priv_key: priv_key
        }
    }
}


#[cfg(test)]
mod tests {
    use dh::{DHParameters, modular_power};
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

    #[test]
    fn test_exchange(){
        let params = DHParameters::new(&[0x17], 5);
        let priv_key1 = params.private_key();
        let priv_key2 = params.private_key();
        let pub_key1 = priv_key1.public_key();
        let pub_key2 = priv_key2.public_key();
        let shared_key1 = priv_key2.exchange(&pub_key1);
        let shared_key2 = priv_key1.exchange(&pub_key2);
        assert!(shared_key1 == shared_key2);
    }

}
