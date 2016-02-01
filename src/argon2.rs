//extern crate blake2;

use std::mem;
use blake2b::Blake2b;
use digest::Digest;
use std::iter::FromIterator;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Variant {
    Argon2d = 0,
    Argon2i = 1,
}

const ARGON2_BLOCK_BYTES: usize = 1024;
const ARGON2_VERSION: u32 = 0x10;
const DEF_B2HASH_LEN: usize = 64;
const SLICES_PER_LANE: u32 = 4;
const DEF_HASH_LEN: usize = 64;
// from run.c
const T_COST_DEF: u32 = 3;
const LOG_M_COST_DEF: u32 = 12;
const LANES_DEF: u32 = 1;

macro_rules! per_block {
    (u8) => { ARGON2_BLOCK_BYTES };
    (u64) => { ARGON2_BLOCK_BYTES / 8 };
}

fn split_u64(n: u64) -> (u32, u32) {
    ((n & 0xffffffff) as u32, (n >> 32) as u32)
}

type Block = [u64; per_block!(u64)];

fn zero() -> Block { [0; per_block!(u64)] }

fn xor_all(blocks: &Vec<&Block>) -> Block {
    let mut rv: Block = zero();
    for (idx, d) in rv.iter_mut().enumerate() {
        *d = blocks.iter().fold(0, |n, &&blk| n ^ blk[idx]);
    }
    rv
}

fn as32le(k: u32) -> [u8; 4] { unsafe { mem::transmute(k.to_le()) } }

fn len32(t: &[u8]) -> [u8; 4] { as32le(t.len() as u32) }

fn as_u8_mut(b: &mut Block) -> &mut [u8] {
    let rv: &mut [u8; per_block!(u8)] = unsafe { mem::transmute(b) };
    rv
}

fn as_u8(b: &Block) -> &[u8] {
    let rv: &[u8; per_block!(u8)] = unsafe { mem::transmute(b) };
    rv
}

macro_rules! b2hash {
    ($($bytes: expr),*) => {
        {
            let mut out: [u8; DEF_B2HASH_LEN] = unsafe { mem::uninitialized() };
            b2hash!(&mut out; $($bytes),*);
            out
        }
    };
    ($out: expr; $($bytes: expr),*) => {
        {
            let mut b = Blake2b::new($out.len());
            $(b.input($bytes));*;
            b.result($out);
        }
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
fn h0(lanes: u32, hash_length: u32, memory_kib: u32, passes: u32, version: u32,
      variant: Variant, p: &[u8], s: &[u8], k: &[u8], x: &[u8])
      -> [u8; 72] {
    let mut rv = [0 as u8; 72];
    b2hash!(&mut rv[0..DEF_B2HASH_LEN];
            &as32le(lanes), &as32le(hash_length), &as32le(memory_kib),
            &as32le(passes), &as32le(version), &as32le(variant as u32),
            &len32(p), p,
            &len32(s), s,
            &len32(k), k,
            &len32(x), x);
    rv
}

pub struct Argon2 {
    blocks: Vec<Block>,
    passes: u32,
    lanelen: u32,
    lanes: u32,
    origkib: u32,
    variant: Variant,
}

impl Argon2 {
    pub fn new(passes: u32, lanes: u32, memory_kib: u32, variant: Variant)
               -> Argon2 {
        assert!(lanes >= 1 && memory_kib >= 8 * lanes && passes >= 1);
        let lanelen = memory_kib / (4 * lanes) * 4;
        Argon2 {
            blocks: (0..lanelen * lanes).map(|_| zero()).collect(),
            passes: passes,
            lanelen: lanelen,
            lanes: lanes,
            origkib: memory_kib,
            variant: variant,
        }
    }

    pub fn hash(&mut self, out: &mut [u8], p: &[u8], s: &[u8], k: &[u8],
                x: &[u8]) {
        let h0 = self.h0(out.len() as u32, p, s, k, x);

        // TODO: parallelize
        for l in 0..self.lanes {
            self.fill_first_slice(h0, l);
        }

        // finish first pass. slices have to be filled in sync.
        for slice in 1..4 {
            for l in 0..self.lanes {
                self.fill_slice(0, l, slice, 0);
            }
        }

        for p in 1..self.passes {
            for s in 0..SLICES_PER_LANE {
                for l in 0..self.lanes {
                    self.fill_slice(p, l, s, 0);
                }
            }
        }

        let lastcol: Vec<&Block> = Vec::from_iter((0..self.lanes).map(|l| {
            &self.blocks[self.blkidx(l, self.lanelen - 1)]
        }));

        h_prime(out, as_u8(&xor_all(&lastcol)));
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn h0(&self, tau: u32, p: &[u8], s: &[u8], k: &[u8], x: &[u8]) -> [u8; 72] {
        h0(self.lanes, tau, self.origkib, self.passes, ARGON2_VERSION,
           self.variant, p, s, k, x)
    }

    fn blkidx(&self, row: u32, col: u32) -> usize {
        (self.lanelen * row + col) as usize
    }

    fn fill_first_slice(&mut self, mut h0: [u8; 72], lane: u32) {
        // fill the first (of four) slice
        h0[68..72].clone_from_slice(&as32le(lane));

        h0[64..68].clone_from_slice(&as32le(0));
        let zeroth = self.blkidx(lane, 0);
        h_prime(as_u8_mut(&mut self.blocks[zeroth]), &h0);

        h0[64..68].clone_from_slice(&as32le(1));
        let first = self.blkidx(lane, 1);
        h_prime(as_u8_mut(&mut self.blocks[first]), &h0);

        // finish rest of first slice
        self.fill_slice(0, lane, 0, 2);
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn fill_slice(&mut self, pass: u32, lane: u32, slice: u32, offset: u32) {
        let mut jgen = Gen2i::new(offset as usize, pass, lane, slice,
                                  self.blocks.len() as u32, self.passes);
        let slicelen = self.lanelen / SLICES_PER_LANE;

        for idx in offset..slicelen {
            let (j1, j2) = if self.variant == Variant::Argon2i {
                jgen.nextj()
            } else {
                let i = self.prev(self.blkidx(lane, slice * slicelen + idx));
                split_u64((self.blocks[i])[0])
            };
            self.fill_block(pass, lane, slice, idx, j1, j2);
        }
    }

    fn fill_block(&mut self, pass: u32, lane: u32, slice: u32, idx: u32,
                  j1: u32, j2: u32) {
        let slicelen = self.lanelen / SLICES_PER_LANE;
        let ls = self.lanes;
        let z = index_alpha(pass, lane, slice, ls, idx, slicelen, j1, j2);

        let zth = match (pass, slice) {
            (0, 0) => self.blkidx(lane, z),
            _ => self.blkidx(j2 % self.lanes, z),
        };

        let cur = self.blkidx(lane, slice * slicelen + idx);
        let pre = self.prev(cur);
        let (wr, rd, refblk) = get3(&mut self.blocks, cur, pre, zth);
        g(wr, rd, refblk);
    }

    fn prev(&self, block_index: usize) -> usize {
        match block_index % self.lanelen as usize {
            0 => block_index + self.lanelen as usize - 1,
            _ => block_index - 1,
        }
    }
}

pub fn simple2i(password: &str, salt: &str) -> [u8; DEF_HASH_LEN] {
    let var = Variant::Argon2i;
    let mut out = [0; DEF_HASH_LEN];
    let mut a2 = Argon2::new(T_COST_DEF, LANES_DEF, 1 << LOG_M_COST_DEF, var);
    a2.hash(&mut out, password.as_bytes(), salt.as_bytes(), &[], &[]);
    out
}

pub fn simple2d(password: &str, salt: &str) -> [u8; DEF_HASH_LEN] {
    let var = Variant::Argon2d;
    let mut out = [0; DEF_HASH_LEN];
    let mut a2 = Argon2::new(T_COST_DEF, LANES_DEF, 1 << LOG_M_COST_DEF, var);
    a2.hash(&mut out, password.as_bytes(), salt.as_bytes(), &[], &[]);
    out
}

fn get3<T>(vector: &mut Vec<T>, wr: usize, rd0: usize, rd1: usize)
           -> (&mut T, &T, &T) {
    assert!(wr != rd0 && wr != rd1 && wr < vector.len() &&
            rd0 < vector.len() && rd1 < vector.len());
    let p: *mut [T] = &mut vector[..];
    let rv = unsafe { (&mut (*p)[wr], &(*p)[rd0], &(*p)[rd1]) };
    rv
}

fn h_prime(out: &mut [u8], input: &[u8]) {
    if out.len() <= DEF_B2HASH_LEN {
        b2hash!(out; &len32(out), input);
    } else {
        let mut tmp = b2hash!(&len32(out), input);
        out[0..DEF_B2HASH_LEN].clone_from_slice(&tmp);
        let mut wr_at: usize = 32;

        while out.len() - wr_at > DEF_B2HASH_LEN {
            b2hash!(&mut tmp; &tmp);
            out[wr_at..wr_at + DEF_B2HASH_LEN].clone_from_slice(&tmp);
            wr_at += DEF_B2HASH_LEN / 2;
        }

        let len = out.len() - wr_at;
        b2hash!(&mut out[wr_at..wr_at + len]; &tmp);
    }
}

// from opt.c
fn index_alpha(pass: u32, lane: u32, slice: u32, lanes: u32, sliceidx: u32,
               slicelen: u32, j1: u32, j2: u32)
               -> u32 {
    let lanelen = slicelen * 4;
    let r: u32 = match (pass, slice, j2 % lanes == lane) {
        (0, 0, _) => sliceidx - 1,
        (0, _, false) => slice * slicelen - if sliceidx == 0 { 1 } else { 0 },
        (0, _, true) => slice * slicelen + sliceidx - 1,
        (_, _, false) => lanelen - slicelen - if sliceidx == 0 { 1 } else { 0 },
        (_, _, true) => lanelen - slicelen + sliceidx - 1,
    };

    let (r_, j1_) = (r as u64, j1 as u64);
    let relpos: u32 = (r_ - 1 - (r_ * (j1_ * j1_ >> 32) >> 32)) as u32;

    match (pass, slice) {
        (0, _) | (_, 3) => relpos % lanelen,
        _ => (slicelen * (slice + 1) + relpos) % lanelen,
    }
}

struct Gen2i {
    arg: Block,
    pseudos: Block,
    idx: usize,
}

impl Gen2i {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn new(start_at: usize, pass: u32, lane: u32, slice: u32, totblocks: u32,
           totpasses: u32)
           -> Gen2i {
        let mut rv = Gen2i { arg: zero(), pseudos: zero(), idx: start_at };
        let args = [pass, lane, slice, totblocks, totpasses,
                    Variant::Argon2i as u32];
        for (k, v) in rv.arg.iter_mut().zip(args.into_iter()) {
            *k = *v as u64;
        }
        rv.more();
        rv
    }

    fn more(&mut self) {
        self.arg[6] += 1;
        g_two(&mut self.pseudos, &self.arg);
    }

    fn nextj(&mut self) -> (u32, u32) {
        let rv = split_u64(self.pseudos[self.idx]);
        self.idx = (self.idx + 1) % per_block!(u64);
        if self.idx == 0 {
            self.more();
        }
        rv
    }
}

// g x y = let r = x `xor` y in p_col (p_row r) `xor` r,
// very simd-able.
fn g(dest: &mut Block, lhs: &Block, rhs: &Block) {
    for (d, (l, r)) in dest.iter_mut().zip(lhs.iter().zip(rhs.iter())) {
        *d = *l ^ *r;
    }

    for row in 0..8 {
        p_row(row, dest);
    }
    // column-wise, 2x u64 groups
    for col in 0..8 {
        p_col(col, dest);
    }

    for (d, (l, r)) in dest.iter_mut().zip(lhs.iter().zip(rhs.iter())) {
        *d = *d ^ *l ^ *r;
    }
}

// g2 y = g 0 (g 0 y). used for data-independent index generation.
fn g_two(dest: &mut Block, src: &Block) {
    *dest = *src;

    for row in 0..8 {
        p_row(row, dest);
    }
    for col in 0..8 {
        p_col(col, dest);
    }

    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d = *d ^ *s;
    }

    let tmp: Block = *dest;

    for row in 0..8 {
        p_row(row, dest);
    }
    for col in 0..8 {
        p_col(col, dest);
    }

    for (d, s) in dest.iter_mut().zip(tmp.iter()) {
        *d = *d ^ *s;
    }
}

macro_rules! p {
    ($v0: expr, $v1: expr, $v2: expr, $v3: expr,
     $v4: expr, $v5: expr, $v6: expr, $v7: expr,
     $v8: expr, $v9: expr, $v10: expr, $v11: expr,
     $v12: expr, $v13: expr, $v14: expr, $v15: expr) => {
        g_blake2b!($v0, $v4, $v8, $v12); g_blake2b!($v1, $v5, $v9, $v13);
        g_blake2b!($v2, $v6, $v10, $v14); g_blake2b!($v3, $v7, $v11, $v15);
        g_blake2b!($v0, $v5, $v10, $v15); g_blake2b!($v1, $v6, $v11, $v12);
        g_blake2b!($v2, $v7, $v8, $v13); g_blake2b!($v3, $v4, $v9, $v14);
    };
}

macro_rules! g_blake2b {
    ($a: expr, $b: expr, $c: expr, $d: expr) => {
        $a = $a.wrapping_add($b).wrapping_add(lower_mult($a, $b));
        $d = ($d ^ $a).rotate_right(32);
        $c = $c.wrapping_add($d).wrapping_add(lower_mult($c, $d));
        $b = ($b ^ $c).rotate_right(24);
        $a = $a.wrapping_add($b).wrapping_add(lower_mult($a, $b));
        $d = ($d ^ $a).rotate_right(16);
        $c = $c.wrapping_add($d).wrapping_add(lower_mult($c, $d));
        $b = ($b ^ $c).rotate_right(63);

    }
}

fn p_row(row: usize, b: &mut Block) {
    p!(b[16 * row + 0],
       b[16 * row + 1],
       b[16 * row + 2],
       b[16 * row + 3],
       b[16 * row + 4],
       b[16 * row + 5],
       b[16 * row + 6],
       b[16 * row + 7],
       b[16 * row + 8],
       b[16 * row + 9],
       b[16 * row + 10],
       b[16 * row + 11],
       b[16 * row + 12],
       b[16 * row + 13],
       b[16 * row + 14],
       b[16 * row + 15]);
}

fn p_col(col: usize, b: &mut Block) {
    p!(b[2 * col + 16 * 0],
       b[2 * col + 16 * 0 + 1],
       b[2 * col + 16 * 1],
       b[2 * col + 16 * 1 + 1],
       b[2 * col + 16 * 2],
       b[2 * col + 16 * 2 + 1],
       b[2 * col + 16 * 3],
       b[2 * col + 16 * 3 + 1],
       b[2 * col + 16 * 4],
       b[2 * col + 16 * 4 + 1],
       b[2 * col + 16 * 5],
       b[2 * col + 16 * 5 + 1],
       b[2 * col + 16 * 6],
       b[2 * col + 16 * 6 + 1],
       b[2 * col + 16 * 7],
       b[2 * col + 16 * 7 + 1]);
}

fn lower_mult(a: u64, b: u64) -> u64 {
    fn lower32(k: u64) -> u64 { k & 0xffffffff }
    lower32(a).wrapping_mul(lower32(b)).wrapping_mul(2)
}

#[cfg(test)]
mod kat_tests {
    use std::fs::File;
    use std::iter::FromIterator;
    use std::io::Read;

    // from genkat.c
    const TEST_OUTLEN: usize = 32;
    const TEST_PWDLEN: usize = 32;
    const TEST_SALTLEN: usize = 16;
    const TEST_SECRETLEN: usize = 8;
    const TEST_ADLEN: usize = 12;

    fn u8info(prefix: &str, bytes: &[u8], print_length: bool) -> String {
        let bs = bytes.iter()
                      .fold(String::new(), |xs, b| xs + &format!("{:02x} ", b));
        let len = match print_length {
            false => ": ".to_string(),
            true => format!("[{}]: ", bytes.len()),
        };
        prefix.to_string() + &len + &bs

    }

    fn block_info(i: usize, b: &super::Block) -> String {
        b.iter().enumerate().fold(String::new(), |xs, (j, octword)| {
            xs + "Block " + &format!("{:004} ", i) + &format!("[{:>3}]: ", j) +
            &format!("{:0016x}", octword) + "\n"
        })
    }

    fn gen_kat(a: &mut super::Argon2, tau: u32, p: &[u8], s: &[u8], k: &[u8],
               x: &[u8])
               -> String {
        let eol = "\n";
        let mut rv = format!("======================================={:?}",
                             a.variant) + eol +
                     &format!("Memory: {} KiB, ", a.origkib) +
                     &format!("Iterations: {}, ", a.passes) +
                     &format!("Parallelism: {} lanes, ", a.lanes) +
                     &format!("Tag length: {} bytes", tau) +
                     eol + &u8info("Password", p, true) +
                     eol +
                     &u8info("Salt", s, true) +
                     eol + &u8info("Secret", k, true) +
                     eol +
                     &u8info("Associated data", x, true) +
                     eol;

        let h0 = a.h0(tau, p, s, k, x);
        rv = rv +
             &u8info("Pre-hashing digest",
                     &h0[..super::DEF_B2HASH_LEN],
                     false) + eol;

        // first pass
        for l in 0..a.lanes {
            a.fill_first_slice(h0, l);
        }
        for slice in 1..4 {
            for l in 0..a.lanes {
                a.fill_slice(0, l, slice, 0);
            }
        }

        rv = rv + eol + " After pass 0:" + eol;
        for (i, block) in a.blocks.iter().enumerate() {
            rv = rv + &block_info(i, block);
        }

        for p in 1..a.passes {
            for s in 0..super::SLICES_PER_LANE {
                for l in 0..a.lanes {
                    a.fill_slice(p, l, s, 0);
                }
            }

            rv = rv + eol + &format!(" After pass {}:", p) + eol;
            for (i, block) in a.blocks.iter().enumerate() {
                rv = rv + &block_info(i, block);
            }
        }

        let lastcol: Vec<&super::Block> =
            Vec::from_iter((0..a.lanes)
                               .map(|l| &a.blocks[a.blkidx(l, a.lanelen - 1)]));

        let mut out = vec![0; tau as usize];
        super::h_prime(&mut out, super::as_u8(&super::xor_all(&lastcol)));
        rv + &u8info("Tag", &out, false)
    }

    fn compare_kats(fexpected: &str, variant: super::Variant) {
        let mut f = File::open(fexpected).unwrap();
        let mut expected = String::new();
        f.read_to_string(&mut expected).unwrap();

        let mut a = super::Argon2::new(3, 4, 32, variant);
        let actual = gen_kat(&mut a,
                             TEST_OUTLEN as u32,
                             &[1; TEST_PWDLEN],
                             &[2; TEST_SALTLEN],
                             &[3; TEST_SECRETLEN],
                             &[4; TEST_ADLEN]);
        if expected.trim() != actual.trim() {
            println!("{}", actual);
            assert!(false);
        }
    }

    #[test]
    fn test_argon2i() { compare_kats("kats/argon2i", super::Variant::Argon2i); }

    #[test]
    fn test_argon2d() { compare_kats("kats/argon2d", super::Variant::Argon2d); }
}
