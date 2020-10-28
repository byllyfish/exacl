//! Implements a generic bit iterator.

use std::cmp::PartialEq;
use std::default::Default;
use std::ops::{BitAnd, BitXorAssign};

pub trait BitIterable:
    Sized + Copy + Default + BitXorAssign + BitAnd<Output = Self> + PartialEq
{
    fn overflowing_neg(&self) -> (Self, bool);
}

pub struct BitIter<T: BitIterable>(pub T);

impl<T: BitIterable> Iterator for BitIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.0 == Default::default() {
            return None;
        }

        // (value & -value) gives you just the lowest bit.
        let bit = self.0 & self.0.overflowing_neg().0;
        self.0 ^= bit;
        Some(bit)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod bititer_tests {
    use super::*;
    use bitflags::bitflags;

    impl BitIterable for u32 {
        #[inline]
        fn overflowing_neg(&self) -> (Self, bool) {
            <u32>::overflowing_neg(*self)
        }
    }
    #[test]
    fn test_bititer_u32() {
        assert_eq!(BitIter(0).collect::<Vec<u32>>(), vec![]);
        let v = BitIter(1).collect::<Vec<u32>>();
        assert_eq!(v, vec![1]);
        let v = BitIter(1 << 31).collect::<Vec<u32>>();
        assert_eq!(v, vec![1 << 31]);
        let v = BitIter(2 + 4 + 16 + 64).collect::<Vec<u32>>();
        assert_eq!(v, vec![2, 4, 16, 64]);
        let v = BitIter(u32::MAX).collect::<Vec<u32>>();
        assert_eq!(v.len(), 32);
        assert_eq!(
            v,
            vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
                131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432,
                67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648
            ]
        );
    }
    bitflags! {
        #[derive(Default)]
        struct TestBit: u32 {
            const BIT1 = 1 << 0;
            const BIT2 = 1 << 1;
            const BIT3 = 1 << 5;
        }
    }

    impl BitIterable for TestBit {
        #[inline]
        fn overflowing_neg(&self) -> (Self, bool) {
            let (bits, overflow) = <u32>::overflowing_neg(self.bits);
            (TestBit { bits }, overflow)
        }
    }

    #[test]
    fn test_bititer_bitflags() {
        let bits = TestBit::BIT1 | TestBit::BIT2 | TestBit::BIT3;

        let v = BitIter(bits.bits).collect::<Vec<u32>>();
        assert_eq!(v, vec![1, 2, 32]);

        let v = BitIter(bits).collect::<Vec<TestBit>>();
        assert_eq!(
            v,
            vec![
                TestBit { bits: 1 },
                TestBit { bits: 2 },
                TestBit { bits: 32 }
            ]
        );
    }
}
