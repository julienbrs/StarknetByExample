use starknet::{ContractAddress, SyscallResultTrait, eth_address::EthAddress};
use core::result::ResultTrait;
use starknet::secp256_trait::{Signature, Secp256Trait, Secp256PointTrait};

#[starknet::interface]
trait IEthSignatureVerifier<TContractState> {
    fn verify_signature(
        ref self: TContractState, msg_hash: u256, signature: Signature, eth_address: EthAddress
    ) -> bool;
}

#[starknet::contract]
mod EthSignatureVerifier {
    use starknet::eth_signature::is_eth_signature_valid;
    use super::{
        Signature, Secp256Trait, Secp256PointTrait, ContractAddress, IEthSignatureVerifier,
        EthAddress
    };
    
    #[storage]
    struct Storage {}

    #[abi(embed_v0)]    //TODO: should use verify_eth_signature instead of is_eth_signature_valid
    impl EthSignatureVerifier of super::IEthSignatureVerifier<ContractState> {
        fn verify_signature(
            ref self: ContractState, msg_hash: u256, signature: Signature, eth_address: EthAddress
        ) -> bool {
            let res: Result = is_eth_signature_valid(msg_hash, signature, eth_address);
            match res {
                Result::Ok => true,
                Result::Err => false
            }
        }
    }
}
