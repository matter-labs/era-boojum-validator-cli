use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::boojum::field::U64Representable;

pub struct ParametersRangeHolder<T: 'static + Clone> {
    pub historical: Vec<(std::ops::Range<usize>, T)>,
    pub current: (usize, T),
}

impl<T: 'static + Clone> ParametersRangeHolder<T> {
    pub fn get_for_index(&self, index: usize) -> Option<T> {
        if index >= self.current.0 {
            return Some(self.current.1.clone());
        }
        // walk over
        for (range, value) in self.historical.iter() {
            if range.contains(&index) {
                return Some(value.clone());
            }
        }

        None
    }
}

/// Holds the Leaf and Node verification keys that were used in a given range of blocks.
pub type CommitsHolder = ParametersRangeHolder<[[GoldilocksField; 4]; 2]>;

pub fn get_mainnet_params_holder() -> CommitsHolder {
    ParametersRangeHolder {
        historical: vec![
            (
                // 74249..109816,
                106971..109816,
                [
                    [
                        GoldilocksField::from_u64_unchecked(0xb4338bf5dd05f4bc),
                        GoldilocksField::from_u64_unchecked(0x2df17763b445b8e0),
                        GoldilocksField::from_u64_unchecked(0xb7b7138fdf1d981c),
                        GoldilocksField::from_u64_unchecked(0xe9792eb109ab8db7),
                    ],
                    [
                        GoldilocksField::from_u64_unchecked(0x5a3ef282b21e12fe),
                        GoldilocksField::from_u64_unchecked(0x1f4438e5bb158fc5),
                        GoldilocksField::from_u64_unchecked(0x060b160559c5158c),
                        GoldilocksField::from_u64_unchecked(0x6389d62d9fe3d080),
                    ],
                ],
            ),
            (
                109816..115165,
                [
                    [
                        GoldilocksField::from_u64_unchecked(0x4f07753d1ab098f9),
                        GoldilocksField::from_u64_unchecked(0xb5d6ba747d3b4716),
                        GoldilocksField::from_u64_unchecked(0x4721dd0dc2ee4d9e),
                        GoldilocksField::from_u64_unchecked(0xe6c8227e3d87b6e6),
                    ],
                    [
                        GoldilocksField::from_u64_unchecked(0x5a3ef282b21e12fe),
                        GoldilocksField::from_u64_unchecked(0x1f4438e5bb158fc5),
                        GoldilocksField::from_u64_unchecked(0x060b160559c5158c),
                        GoldilocksField::from_u64_unchecked(0x6389d62d9fe3d080),
                    ],
                ],
            ),
        ],

        current: (
            115165,
            [
                [
                    GoldilocksField::from_u64_unchecked(0x06babae433cab419),
                    GoldilocksField::from_u64_unchecked(0x798a8e063042acb9),
                    GoldilocksField::from_u64_unchecked(0xaa74e3e826a89da6),
                    GoldilocksField::from_u64_unchecked(0x496869d04d28460e),
                ],
                [
                    GoldilocksField::from_u64_unchecked(0x5a3ef282b21e12fe),
                    GoldilocksField::from_u64_unchecked(0x1f4438e5bb158fc5),
                    GoldilocksField::from_u64_unchecked(0x060b160559c5158c),
                    GoldilocksField::from_u64_unchecked(0x6389d62d9fe3d080),
                ],
            ],
        ),
    }
}

pub fn get_testnet_params_holder() -> CommitsHolder {
    ParametersRangeHolder {
        historical: vec![(
            98767..120081,
            [
                [
                    GoldilocksField::from_u64_unchecked(0xb4338bf5dd05f4bc),
                    GoldilocksField::from_u64_unchecked(0x2df17763b445b8e0),
                    GoldilocksField::from_u64_unchecked(0xb7b7138fdf1d981c),
                    GoldilocksField::from_u64_unchecked(0xe9792eb109ab8db7),
                ],
                [
                    GoldilocksField::from_u64_unchecked(0x5a3ef282b21e12fe),
                    GoldilocksField::from_u64_unchecked(0x1f4438e5bb158fc5),
                    GoldilocksField::from_u64_unchecked(0x060b160559c5158c),
                    GoldilocksField::from_u64_unchecked(0x6389d62d9fe3d080),
                ],
            ],
        )],
        current: (
            120081,
            [
                [
                    GoldilocksField::from_u64_unchecked(0x4f07753d1ab098f9),
                    GoldilocksField::from_u64_unchecked(0xb5d6ba747d3b4716),
                    GoldilocksField::from_u64_unchecked(0x4721dd0dc2ee4d9e),
                    GoldilocksField::from_u64_unchecked(0xe6c8227e3d87b6e6),
                ],
                [
                    GoldilocksField::from_u64_unchecked(0x5a3ef282b21e12fe),
                    GoldilocksField::from_u64_unchecked(0x1f4438e5bb158fc5),
                    GoldilocksField::from_u64_unchecked(0x060b160559c5158c),
                    GoldilocksField::from_u64_unchecked(0x6389d62d9fe3d080),
                ],
            ],
        ),
    }
}
