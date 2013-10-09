// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::num::{cast, Zero};
use std::sys::size_of;

/// Cast from one machine scalar to another, checking that the value to be cast fits into the result
/// type.
#[inline]
pub fn checked_cast<T: CheckedNumCast, U: CheckedNumCast>(n: T) -> Option<U> {
    CheckedNumCast::checked_from(n)
}

pub trait CheckedNumCast {
    fn checked_from<T: CheckedNumCast>(n: T) -> Option<Self>;

    fn checked_to_u8(&self) -> Option<u8>;
    fn checked_to_u16(&self) -> Option<u16>;
    fn checked_to_u32(&self) -> Option<u32>;
    fn checked_to_u64(&self) -> Option<u64>;
    fn checked_to_uint(&self) -> Option<uint>;

    fn checked_to_i8(&self) -> Option<i8>;
    fn checked_to_i16(&self) -> Option<i16>;
    fn checked_to_i32(&self) -> Option<i32>;
    fn checked_to_i64(&self) -> Option<i64>;
    fn checked_to_int(&self) -> Option<int>;
}

fn checked_cast_u_to_u<T: Integer + Unsigned + NumCast, O: Unsigned + Bounded + NumCast>(input: T)
        -> Option<O> {
    if size_of::<T>() <= size_of::<O>() {
        Some(cast(input))
    } else {
        let out_max: O = Bounded::max_value();
        if input <= cast(out_max) {
            Some(cast(input))
        } else {
            None
        }
    }
}

fn checked_cast_i_to_u<T: Integer + Signed + NumCast, O: Unsigned + Bounded + NumCast>(input: T)
         -> Option<O> {
    if input < Zero::zero() {
        None
    } else if size_of::<T>() <= size_of::<O>() {
        Some(cast(input))
    } else {
        let out_max: O = Bounded::max_value();
        if input <= cast(out_max) {
            Some(cast(input))
        } else {
            None
        }
    }
}

fn checked_cast_u_to_i<T: Integer + Unsigned + NumCast, O: Signed + Bounded + NumCast>(input: T)
        -> Option<O> {
    if size_of::<T>() < size_of::<O>() {
        Some(cast(input))
    } else {
        let out_max: O = Bounded::max_value();
        if input <= cast(out_max) {
            Some(cast(input))
        } else {
            None
        }
    }
}

fn checked_cast_i_to_i<T: Integer + Signed + NumCast, O: Signed + Bounded + NumCast>(input: T)
        -> Option<O> {
    if size_of::<T>() <= size_of::<O>() {
        Some(cast(input))
    } else {
        let out_max: O = Bounded::max_value();
        let out_min: O = Bounded::min_value();
        if input >= cast(out_min) && input <= cast(out_max) {
            Some(cast(input))
        } else {
            None
        }
    }
}

macro_rules! impl_checked_num_cast_u_to_x(
    ($T:ty, $conv:ident) => (
        impl CheckedNumCast for $T {
            #[inline]
            fn checked_from<N: CheckedNumCast>(n: N) -> Option<$T> {
                // `$conv` could be generated using `concat_idents!`, but that
                // macro seems to be broken at the moment
                n.$conv()
            }

            #[inline] fn checked_to_u8(&self)   -> Option<u8>    { checked_cast_u_to_u(*self) }
            #[inline] fn checked_to_u16(&self)  -> Option<u16>   { checked_cast_u_to_u(*self) }
            #[inline] fn checked_to_u32(&self)  -> Option<u32>   { checked_cast_u_to_u(*self) }
            #[inline] fn checked_to_u64(&self)  -> Option<u64>   { checked_cast_u_to_u(*self) }
            #[inline] fn checked_to_uint(&self) -> Option<uint>  { checked_cast_u_to_u(*self) }

            #[inline] fn checked_to_i8(&self)   -> Option<i8>    { checked_cast_u_to_i(*self) }
            #[inline] fn checked_to_i16(&self)  -> Option<i16>   { checked_cast_u_to_i(*self) }
            #[inline] fn checked_to_i32(&self)  -> Option<i32>   { checked_cast_u_to_i(*self) }
            #[inline] fn checked_to_i64(&self)  -> Option<i64>   { checked_cast_u_to_i(*self) }
            #[inline] fn checked_to_int(&self)  -> Option<int>   { checked_cast_u_to_i(*self) }
        }
    )
)

macro_rules! impl_checked_num_cast_i_to_x(
    ($T:ty, $conv:ident) => (
        impl CheckedNumCast for $T {
            #[inline]
            fn checked_from<N: CheckedNumCast>(n: N) -> Option<$T> {
                // `$conv` could be generated using `concat_idents!`, but that
                // macro seems to be broken at the moment
                n.$conv()
            }

            #[inline] fn checked_to_u8(&self)   -> Option<u8>    { checked_cast_i_to_u(*self) }
            #[inline] fn checked_to_u16(&self)  -> Option<u16>   { checked_cast_i_to_u(*self) }
            #[inline] fn checked_to_u32(&self)  -> Option<u32>   { checked_cast_i_to_u(*self) }
            #[inline] fn checked_to_u64(&self)  -> Option<u64>   { checked_cast_i_to_u(*self) }
            #[inline] fn checked_to_uint(&self) -> Option<uint>  { checked_cast_i_to_u(*self) }

            #[inline] fn checked_to_i8(&self)   -> Option<i8>    { checked_cast_i_to_i(*self) }
            #[inline] fn checked_to_i16(&self)  -> Option<i16>   { checked_cast_i_to_i(*self) }
            #[inline] fn checked_to_i32(&self)  -> Option<i32>   { checked_cast_i_to_i(*self) }
            #[inline] fn checked_to_i64(&self)  -> Option<i64>   { checked_cast_i_to_i(*self) }
            #[inline] fn checked_to_int(&self)  -> Option<int>   { checked_cast_i_to_i(*self) }
        }
    )
)

impl_checked_num_cast_u_to_x!(u8,   checked_to_u8)
impl_checked_num_cast_u_to_x!(u16,  checked_to_u16)
impl_checked_num_cast_u_to_x!(u32,  checked_to_u32)
impl_checked_num_cast_u_to_x!(u64,  checked_to_u64)
impl_checked_num_cast_u_to_x!(uint, checked_to_uint)

impl_checked_num_cast_i_to_x!(i8,   checked_to_i8)
impl_checked_num_cast_i_to_x!(i16,  checked_to_i16)
impl_checked_num_cast_i_to_x!(i32,  checked_to_i32)
impl_checked_num_cast_i_to_x!(i64,  checked_to_i64)
impl_checked_num_cast_i_to_x!(int,  checked_to_int)

#[test]
fn test_checked_cast() {
    assert_eq!(checked_cast(255u16), Some(255u8));
    assert!(256u16.checked_to_u8().is_none());

    assert_eq!(checked_cast(127u8), Some(127i8));
    assert!(128u8.checked_to_i8().is_none());

    assert_eq!(checked_cast(127i8), Some(127u8));
    assert!((-1i8).checked_to_u8().is_none());

    assert_eq!(checked_cast(-128i16), Some(-128i8));
    assert!((-129i16).checked_to_i8().is_none());
}
