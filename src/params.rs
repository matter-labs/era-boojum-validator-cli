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

// These CIRCUIT_XX objects contain the commitment to the verification key for Leaf and Node circuits.
// The Scheduler circuit verification key is separate (and currently hardcoded in keys/verification_scheduler_key.json file).
const CIRCUIT_V1: [[u64; 4]; 2] = [
    [
        0xb4338bf5dd05f4bc,
        0x2df17763b445b8e0,
        0xb7b7138fdf1d981c,
        0xe9792eb109ab8db7,
    ],
    [
        0x5a3ef282b21e12fe,
        0x1f4438e5bb158fc5,
        0x060b160559c5158c,
        0x6389d62d9fe3d080,
    ],
];

const CIRCUIT_V2: [[u64; 4]; 2] = [
    [
        0x4f07753d1ab098f9,
        0xb5d6ba747d3b4716,
        0x4721dd0dc2ee4d9e,
        0xe6c8227e3d87b6e6,
    ],
    [
        0x5a3ef282b21e12fe,
        0x1f4438e5bb158fc5,
        0x060b160559c5158c,
        0x6389d62d9fe3d080,
    ],
];

const CIRCUIT_V3: [[u64; 4]; 2] = [
    [
        0x06babae433cab419,
        0x798a8e063042acb9,
        0xaa74e3e826a89da6,
        0x496869d04d28460e,
    ],
    [
        0x5a3ef282b21e12fe,
        0x1f4438e5bb158fc5,
        0x060b160559c5158c,
        0x6389d62d9fe3d080,
    ],
];

const CIRCUIT_V4: [[u64; 4]; 2] = [
    [
        0x924fff6035db1447,
        0x08ade2ca87966171,
        0x9bcd16e9c356374f,
        0x73166fe5eeade0f0,
    ],
    [
        0x5a3ef282b21e12fe,
        0x1f4438e5bb158fc5,
        0x060b160559c5158c,
        0x6389d62d9fe3d080,
    ],
];

pub fn to_goldilocks(circuit: [[u64; 4]; 2]) -> [[GoldilocksField; 4]; 2] {
    circuit.map(|x| x.map(|y| GoldilocksField::from_u64_unchecked(y)))
}

/// Holds the Leaf and Node verification keys that were used in a given range of blocks.
pub type CommitsHolder = ParametersRangeHolder<[[GoldilocksField; 4]; 2]>;

pub fn get_mainnet_params_holder() -> CommitsHolder {
    ParametersRangeHolder {
        historical: vec![
            (
                // 74249..109816,
                106971..109816,
                to_goldilocks(CIRCUIT_V1),
            ),
            (109816..115165, to_goldilocks(CIRCUIT_V2)),
            (115165..141335, to_goldilocks(CIRCUIT_V3)),
        ],

        current: (141335, to_goldilocks(CIRCUIT_V4)),
    }
}

pub fn get_testnet_params_holder() -> CommitsHolder {
    ParametersRangeHolder {
        historical: vec![(98767..120081, to_goldilocks(CIRCUIT_V1))],
        current: (120081, to_goldilocks(CIRCUIT_V2)),
    }
}
