use dep::std;
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

fn keccak256_call(call: Call) -> [u8; 32] {
    call.operator.assert_max_bit_size(160);
    call.target.assert_max_bit_size(160);
    call.beforeTrxHook.assert_max_bit_size(160);
    call.afterTrxHook.assert_max_bit_size(160);
    call.operation.assert_max_bit_size(8);
    call.targetSelector.assert_max_bit_size(32);

    let operatorBytes = call.operator.to_be_bytes(32);
    let targetBytes = call.target.to_be_bytes(32);
    let beforeTrxHookBytes = call.beforeTrxHook.to_be_bytes(32);
    let afterTrxHookBytes = call.afterTrxHook.to_be_bytes(32);
    let operationBytes = call.operation.to_be_bytes(32);
    let targetSelectorBytes = call.targetSelector.to_be_bytes(4);

    /// solidity left aligns selectors so we need to pad it with 0s
    let targetSelectorPaddingBytes = [0; 28];

    let mut callBytes: [u8; 192] = [0; 192];

    for i in 0..32 {
        callBytes[i] = operatorBytes[i];
    }

    for i in 0..32 {
        callBytes[i + 32] = targetBytes[i];
    }

    for i in 0..32 {
        callBytes[i + 64] = beforeTrxHookBytes[i];
    }

    for i in 0..32 {
        callBytes[i + 96] = afterTrxHookBytes[i];
    }

    for i in 0..32 {
        callBytes[i + 128] = operationBytes[i];
    }

    for i in 0..4 {
        callBytes[i + 160] = targetSelectorBytes[i];
    }

    for i in 0..28 {
        callBytes[i + 164] = targetSelectorPaddingBytes[i];
    }

    let hash = keccak256(callBytes, 192);

    hash
}

pub fn call_config_map(calls: [Call; 3]) -> HashMap<[u8 ; 32], bool, 3, BuildHasherDefault<Poseidon2Hasher>> {
    // @notice defaults to max size of 3
    let mut mapping: HashMap<[u8 ; 32], bool, 3, BuildHasherDefault<Poseidon2Hasher>> = HashMap::default();

    for call in calls {
        assert(!mapping.contains_key(keccak256_call(call)), "Duplicate call");
        mapping.insert(keccak256_call(call), true);
    }

    mapping
}

fn main(callWhitelist: [Call; 3], call: pub Call) {
    // @notice defaults to max size of 3
    let mut mapping: HashMap<[u8 ; 32], bool, 3, BuildHasherDefault<Poseidon2Hasher>> = HashMap::default();

    for call in callWhitelist {
        let hash = keccak256_call(call);
        assert(!mapping.contains_key(hash), "Duplicate call");
        mapping.insert(hash, true);
    }

    assert(mapping.contains_key(keccak256_call(call)), "Call not whitelisted");
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

    let hash = keccak256_call(call);

    /// calculated using foundry 
    assert_eq(
        hash, [
        106, 92, 193, 49, 255, 11, 208, 131, 14, 216, 191, 169, 68, 118, 133, 96, 95, 247, 140, 151, 150, 43, 18, 111, 155, 205, 180, 94, 51, 3, 35, 204
    ]
    );
}
