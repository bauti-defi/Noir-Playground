use std::collections::map::HashMap;
use std::hash::BuildHasherDefault;
use std::hash::keccak256;
use std::hash::poseidon2::Poseidon2Hasher;

struct Call {
    operator: Field,
    target: Field,
    beforeTrxHook: Field,
    afterTrxHook: Field,
    operation: Field,
    targetSelector: Field,
}

impl Call {

    fn keccak256(self) -> [u8; 32] {
        self.operator.assert_max_bit_size(160);
        self.target.assert_max_bit_size(160);
        self.beforeTrxHook.assert_max_bit_size(160);
        self.afterTrxHook.assert_max_bit_size(160);
        self.operation.assert_max_bit_size(8);
        self.targetSelector.assert_max_bit_size(32);

        let operatorBytes = self.operator.to_be_bytes(32);
        let targetBytes = self.target.to_be_bytes(32);
        let beforeTrxHookBytes = self.beforeTrxHook.to_be_bytes(32);
        let afterTrxHookBytes = self.afterTrxHook.to_be_bytes(32);
        let operationBytes = self.operation.to_be_bytes(32);
        let targetSelectorBytes = self.targetSelector.to_be_bytes(4);

        let mut callBytes: [u8; 192] = [0; 192];

        for i in 0..32 {
            callBytes[i] = operatorBytes[i];
            callBytes[i + 32] = targetBytes[i];
            callBytes[i + 64] = beforeTrxHookBytes[i];
            callBytes[i + 96] = afterTrxHookBytes[i];
            callBytes[i + 128] = operationBytes[i];
        }

        for i in 0..4 {
            callBytes[i + 160] = targetSelectorBytes[i];
        }

        let hash = keccak256(callBytes, 192);

        hash
    }
}

fn main(callWhitelist: [Call; 3], call: pub Call) {
    // @notice defaults to max size of 3
    let mut mapping: HashMap<[u8 ; 32], bool, 3, BuildHasherDefault<Poseidon2Hasher>> = HashMap::default();

    for _call in callWhitelist {
        let hash = _call.keccak256();
        assert(!mapping.contains_key(hash), "Duplicate call");
        mapping.insert(hash, true);
    }

    assert(mapping.contains_key(call.keccak256()), "Call not whitelisted");
}

#[test]
fn test_call_config_map() {
    let call1 = Call {
        operator: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf,
        target: 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF,
        beforeTrxHook: 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69,
        afterTrxHook: 0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718,
        operation: 1,
        targetSelector: 0x11999999
    };

    let call2 = Call {
        operator: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf,
        target: 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF,
        beforeTrxHook: 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69,
        afterTrxHook: 0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718,
        operation: 0,
        targetSelector: 0x32145678
    };

    let call3 = Call {
        operator: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf,
        target: 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF,
        beforeTrxHook: 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69,
        afterTrxHook: 0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718,
        operation: 0,
        targetSelector: 0x12345678
    };

    main([call1, call2, call3], call1);
}

#[test]
fn test_keccak256_call() {
    let call = Call {
        operator: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf,
        target: 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF,
        beforeTrxHook: 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69,
        afterTrxHook: 0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718,
        operation: 0,
        targetSelector: 0x12345678
    };

    let hash = call.keccak256();

    /// calculated using foundry 
    assert_eq(
        hash, [
        106, 92, 193, 49, 255, 11, 208, 131, 14, 216, 191, 169, 68, 118, 133, 96, 95, 247, 140, 151, 150, 43, 18, 111, 155, 205, 180, 94, 51, 3, 35, 204
    ]
    );
}
