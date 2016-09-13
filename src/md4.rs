use digest::Digest;
use cryptoutil::{write_u32_le, read_u32v_le, FixedBuffer, FixedBuffer64, StandardPadding};
use step_by::RangeExt;

// initial values for Md4State
const I0: u32 = 0x67452301;
const I1: u32 = 0xefcdab89;
const I2: u32 = 0x98badcfe;
const I3: u32 = 0x10325476;

struct Md4State {
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32
}

pub struct Md4 {
    length_bytes: u64,
    buffer: FixedBuffer64,
    state: Md4State,
    finished: bool,
}


impl Md4State {
    fn new() -> Md4State {
        Md4State {
            s0: I0,
            s1: I1,
            s2: I2,
            s3: I3
        }
    }

    fn reset(&mut self) {
        self.s0 = I0;
        self.s1 = I1;
        self.s2 = I2;
        self.s3 = I3;
    }

    fn process_block(&mut self, input: &[u8]) {
        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }

        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }
 
        fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
        }

        fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(g(b, c, d)).wrapping_add(k).wrapping_add(0x5a827999).rotate_left(s)
        }

        fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d)).wrapping_add(k).wrapping_add(0x6ED9EBA1).rotate_left(s)
        }

        let mut a = self.s0;
        let mut b = self.s1;
        let mut c = self.s2;
        let mut d = self.s3;

        // load block to data
        let mut data = [0u32; 16];
        read_u32v_le(&mut data, input);

        // round 1
        // maybe disclose loop for performance ?
        for i in (0..16).step_up(4) {
            a = op1(a, b, c, d, data[i], 3);
            d = op1(d, a, b, c, data[i + 1], 7);
            c = op1(c, d, a, b, data[i + 2], 11);
            b = op1(b, c, d, a, data[i + 3], 19);
        }


        // round 2
        for i in 0..4 {
            a = op2(a, b, c, d, data[i], 3);
            d = op2(d, a, b, c, data[i + 4], 5);
            c = op2(c, d, a, b, data[i + 8], 9);
            b = op2(b, c, d, a, data[i + 12], 13);
        }

        // round 3
        for &i in [0, 2, 1, 3].iter() {
            a = op3(a, b, c, d, data[i], 3);
            d = op3(d, a, b, c, data[i + 8], 9);
            c = op3(c, d, a, b, data[i + 4], 11);
            b = op3(b, c, d, a, data[i + 12], 15);
        }

        self.s0 = self.s0.wrapping_add(a);
        self.s1 = self.s1.wrapping_add(b);
        self.s2 = self.s2.wrapping_add(c);
        self.s3 = self.s3.wrapping_add(d);
    }
}

impl Md4 {
    pub fn new() -> Md4 {
        Md4 {
            length_bytes: 0,
            buffer: FixedBuffer64::new(),
            state: Md4State::new(),
            finished: false
        }
    }
}

impl Digest for Md4 {
    fn input(&mut self, input: &[u8]) {
        assert!(!self.finished);
        // 2^64 - ie: integer overflow is OK.
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &[u8]| { self_state.process_block(d);}
        );
    }

    fn reset(&mut self) {
        self.length_bytes = 0;
        self.buffer.reset();
        self.state.reset();
        self.finished = false;
    }

    fn result(&mut self, out: &mut [u8]) {
        if !self.finished {
            let self_state = &mut self.state;
            self.buffer.standard_padding(8, |d: &[u8]| { self_state.process_block(d); });
            write_u32_le(self.buffer.next(4), (self.length_bytes << 3) as u32);
            write_u32_le(self.buffer.next(4), (self.length_bytes >> 29) as u32);
            self_state.process_block(self.buffer.full_buffer());
            self.finished = true;
        }

        write_u32_le(&mut out[0..4], self.state.s0);
        write_u32_le(&mut out[4..8], self.state.s1);
        write_u32_le(&mut out[8..12], self.state.s2);
        write_u32_le(&mut out[12..16], self.state.s3);
    }

    fn output_bits(&self) -> usize { 128 }

    fn block_size(&self) -> usize { 64 }
}


#[cfg(test)]
mod tests {
    use cryptoutil::test::test_digest_1million_random;
    use digest::Digest;
    use md4::Md4;

    struct Test {
        input: &'static str,
        output_str: &'static str,
    }

    #[test]
    fn test_md4() {
        let wiki_tests = vec![
            Test {
                input: "",
                output_str: "31d6cfe0d16ae931b73c59d7e0c089c0"
            },
            Test {
                input: "a",
                output_str: "bde52cb31de33e46245e05fbdbd6fb24"
            },
            Test {
                input: "abc",
                output_str: "a448017aaf21d8525fc10ae87aa6729d"
            },
            Test {
                input: "message digest",
                output_str: "d9130a8164549fe818874806e1c7014b"
            },
            Test {
                input: "abcdefghijklmnopqrstuvwxyz",
                output_str: "d79e1c308aa5bbcdeea8ed63df412da9"
            },
            Test {
                input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                output_str: "043f8582f241db351ce627e153e7f0e4"
            },
            Test {
                input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                output_str: "e33b4ddc9c38f2199c3e7b164fcc0536"
            }
        ];
        let mut sh = Md4::new();

        for t in wiki_tests.iter() {
            sh.input_str(t.input);
            let out_str = sh.result_str();
            assert_eq!(out_str, t.output_str);
            sh.reset();
        }

        // Test that it works when accepting the message in pieces
        for t in wiki_tests.iter() {
            let len = t.input.len();
            let mut left = len;
            while left > 0 {
                let take = (left + 1) / 2;
                sh.input_str(&t.input[len - left..take + len - left]);
                left = left - take;
            }

            let out_str = sh.result_str();
            assert_eq!(out_str, t.output_str);
            sh.reset();
        }
    }

    #[test]
    fn test_1million_a() {
        // test with 1 millon string with 'a'
        let mut sh = Md4::new();
        test_digest_1million_random(&mut sh, 64,
            "bbce80cc6bb65e5c6745e30d4eeca9a4");
    }
}


#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;
    use digest::Digest;
    use md4::Md4;

    #[bench]
    pub fn md4_10(bh: & mut Bencher) {
        let mut sh = Md4::new();
        let bytes = [1u8; 10];
        bh.iter( || {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn md4_1k(bh: & mut Bencher) {
        let mut sh = Md4::new();
        let bytes = [1u8; 1024];
        bh.iter( || {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn md4_64k(bh: & mut Bencher) {
        let mut sh = Md4::new();
        let bytes = [1u8; 65536];
        bh.iter( || {
            sh.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
