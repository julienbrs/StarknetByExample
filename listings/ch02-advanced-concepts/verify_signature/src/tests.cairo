mod tests {
    use starknet::{
        deploy_syscall, ContractAddress, EthAddress, SyscallResultTrait, 
        secp256_trait::{Signature, Secp256Trait, Secp256PointTrait}
    };
    use starknet::class_hash::Felt252TryIntoClassHash;
    use verify_signature::contract::{
        EthSignatureVerifier, IEthSignatureVerifierDispatcher, IEthSignatureVerifierDispatcherTrait
    };

    fn deploy() -> IEthSignatureVerifierDispatcher {
        let calldata: Array<felt252> = array![];
        let (address0, _) = deploy_syscall(
            EthSignatureVerifier::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false
        )
            .unwrap();
        IEthSignatureVerifierDispatcher { contract_address: address0 }
    }

    #[test]
    #[available_gas(2000000000)]
    fn should_verify_valid_signature() {
        let contract = deploy();
        let msg: felt252 = 'I am 0x1a737A9eA21f6E087c2e74a0c620f81dA76bf49E';
        let msg_hash: u256 = '0x696f7b330f3630cac1999ec5b9c4a2e2aa30db640702b8a8a605bb1305819797'; 
        let signature: Signature = '0x776038715080d4d08417b7a62a4fa390cc476eed90fafb043a30a77a3f54914f397685de38c50e3f38e90d717202423c154ff86dac0ab34b71247da91317b4471b';
        let eth_address: EthAddress = ...;

        let is_valid = contract.verify_signature(msg_hash, signature, eth_address);
        assert(is_valid == true, 'Signature should be valid');
    }

    #[test]
    #[available_gas(2000000000)]
    fn should_reject_invalid_signature() {
        let contract = deploy();
        
        let msg_hash: u256 = ...; 
        let signature: Signature = ...;
        let eth_address: EthAddress = ...;

        let is_valid = contract.verify_signature(msg_hash, signature, eth_address);
        assert(is_valid == false, 'Signature should be invalid');
    }
}
