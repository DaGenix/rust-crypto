pub enum Argon2Variant {
    Argon2d = 0,
    Argon2i = 1,
}

struct Argon2Params {
    parallelism : u32,  // 1..1 << 24 - 1
    memory_kib : u32, // >= 8 * parallelism
    passes : u32,
    hash_length : u32,  // >= 4
    variant : Argon2Variant
}
