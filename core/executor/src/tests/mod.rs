mod system_script;

use std::collections::BTreeMap;
use std::str::FromStr;

use ethers::abi::{AbiDecode, AbiEncode};
use evm::backend::{MemoryAccount, MemoryBackend, MemoryVicinity};
use evm::Config;

use protocol::types::{
    ApplyBackend, Bytes, Eip1559Transaction, ExitReason, ExitSucceed, Public, SignatureComponents,
    SignedTransaction, TransactionAction, UnsignedTransaction, UnverifiedTransaction, H160, H256,
    MAX_BLOCK_GAS_LIMIT, U256,
};
use protocol::{codec::hex_decode, traits::Executor};

use crate::system_contract::gasless;
use crate::{precompiles::build_precompile_set, vm::EvmExecutor, AxonExecutor};

fn gen_vicinity() -> MemoryVicinity {
    MemoryVicinity {
        gas_price:              U256::zero(),
        origin:                 H160::default(),
        block_hashes:           Vec::new(),
        block_number:           Default::default(),
        block_coinbase:         Default::default(),
        block_timestamp:        Default::default(),
        block_difficulty:       Default::default(),
        block_gas_limit:        Default::default(),
        chain_id:               U256::one(),
        block_base_fee_per_gas: U256::zero(),
    }
}

fn gen_tx(sender: H160, addr: H160, value: u64, data: Vec<u8>) -> SignedTransaction {
    SignedTransaction {
        transaction: UnverifiedTransaction {
            unsigned:  UnsignedTransaction::Eip1559(Eip1559Transaction {
                nonce:                    U256::default(),
                max_priority_fee_per_gas: U256::default(),
                gas_price:                U256::default(),
                gas_limit:                U256::from_str("0x1000000000").unwrap(),
                action:                   TransactionAction::Call(addr),
                value:                    value.into(),
                data:                     data.into(),
                access_list:              Vec::new(),
            }),
            signature: Some(SignatureComponents {
                standard_v: 0,
                r:          Bytes::default(),
                s:          Bytes::default(),
            }),
            chain_id:  0u64,
            hash:      H256::default(),
        },
        sender,
        public: Some(Public::default()),
    }
}

#[test]
fn test_ackermann31() {
    let mut state = BTreeMap::new();
    state.insert(
		H160::from_str("0x1000000000000000000000000000000000000000").unwrap(),
		MemoryAccount {
			nonce: U256::one(),
			balance: U256::max_value(),
			storage: BTreeMap::new(),
			code: hex_decode("60e060020a6000350480632839e92814601e57806361047ff414603457005b602a6004356024356047565b8060005260206000f35b603d6004356099565b8060005260206000f35b600082600014605457605e565b8160010190506093565b81600014606957607b565b60756001840360016047565b90506093565b609060018403608c85600186036047565b6047565b90505b92915050565b6000816000148060a95750816001145b60b05760b7565b81905060cf565b60c1600283036099565b60cb600184036099565b0190505b91905056").unwrap(),
		}
	);
    state.insert(
        H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
        MemoryAccount {
            nonce:   U256::one(),
            balance: U256::max_value(),
            storage: BTreeMap::new(),
            code:    Vec::new(),
        },
    );

    let vicinity = gen_vicinity();
    let mut backend = MemoryBackend::new(&vicinity, state);
    let executor = EvmExecutor::default();
    let tx = gen_tx(
        H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
        H160::from_str("0x1000000000000000000000000000000000000000").unwrap(),
        0,
        hex_decode("2839e92800000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001").unwrap()
    );
    let config = Config::london();
    let precompiles = build_precompile_set();
    let r = executor.inner_exec(&mut backend, &config, MAX_BLOCK_GAS_LIMIT, &precompiles, tx);

    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    assert_eq!(r.ret, vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 13
    ]);
    assert_eq!(r.remain_gas, 29966841);
}

#[test]
fn test_simplestorage() {
    let mut state = BTreeMap::new();
    state.insert(
        H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
        MemoryAccount {
            nonce:   U256::one(),
            balance: U256::max_value(),
            storage: BTreeMap::new(),
            code:    Vec::new(),
        },
    );
    let vicinity = gen_vicinity();
    let mut backend = MemoryBackend::new(&vicinity, state);

    let executor = EvmExecutor::default();
    let config = Config::london();
    let precompiles = build_precompile_set();

    // pragma solidity ^0.4.24;
    //
    // contract SimpleStorage {
    //     uint storedData;
    //
    //     function set(uint x) public {
    //         storedData = x;
    //     }
    //
    //     function get() view public returns (uint) {
    //         return storedData;
    //     }
    // }
    //
    // simplestorage_create_code created from above solidity
    let simplestorage_create_code = "608060405234801561001057600080fd5b5060df8061001f6000396000f3006080604052600436106049576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806360fe47b114604e5780636d4ce63c146078575b600080fd5b348015605957600080fd5b5060766004803603810190808035906020019092919050505060a0565b005b348015608357600080fd5b50608a60aa565b6040518082815260200191505060405180910390f35b8060008190555050565b600080549050905600a165627a7a7230582099c66a25d59f0aa78f7ebc40748fa1d1fbc335d8d780f284841b30e0365acd960029";
    let mut tx = gen_tx(
        H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
        H160::from_str("0x1000000000000000000000000000000000000000").unwrap(),
        0,
        hex_decode(simplestorage_create_code).unwrap(),
    );
    tx.transaction
        .unsigned
        .set_action(TransactionAction::Create);
    let r = executor.inner_exec(&mut backend, &config, MAX_BLOCK_GAS_LIMIT, &precompiles, tx);
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    assert!(r.ret.is_empty());
    assert_eq!(r.remain_gas, 29898759);

    // Thr created contract's address is
    // 0xc15d2ba57d126e6603240e89437efd419ce329d2, you can get the address by
    // `println!("{:?}", backend.state().keys());`

    // let's call SimpleStorage.set(42)
    let tx = gen_tx(
        H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
        H160::from_str("0xc15d2ba57d126e6603240e89437efd419ce329d2").unwrap(),
        0,
        hex_decode("60fe47b1000000000000000000000000000000000000000000000000000000000000002a")
            .unwrap(),
    );
    let r = executor.inner_exec(&mut backend, &config, MAX_BLOCK_GAS_LIMIT, &precompiles, tx);
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Stopped));
    assert!(r.ret.is_empty());
    assert_eq!(r.remain_gas, 29956491);

    // let's call SimpleStorage.get() by exec
    let tx = gen_tx(
        H160::from_str("0xf000000000000000000000000000000000000000").unwrap(),
        H160::from_str("0xc15d2ba57d126e6603240e89437efd419ce329d2").unwrap(),
        0,
        hex_decode("6d4ce63c").unwrap(),
    );
    let r = executor.inner_exec(&mut backend, &config, MAX_BLOCK_GAS_LIMIT, &precompiles, tx);
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    // assert_eq!(r.ret, vec![
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0, 0, 0, 0, 0, 0,     0, 42
    // ]);
    assert_eq!(r.remain_gas, 29976612);

    // let's call SimpleStorage.get() by call
    let executor = AxonExecutor::default();
    let r = executor.call(
        &backend,
        u64::MAX,
        None,
        Some(H160::from_str("0xc15d2ba57d126e6603240e89437efd419ce329d2").unwrap()),
        U256::default(),
        hex_decode("6d4ce63c").unwrap(),
    );
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    // assert_eq!(r.ret, vec![
    //     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 0, 0, 0, 0, 0, 0, 0,     0, 42
    // ]);
}

fn deploy_sponsor_contract(backend: &mut MemoryBackend) {
    let sender = H160::from_str("0xf000000000000000000000000000000000000000").unwrap();
    let executor = EvmExecutor::default();
    let config = Config::london();
    let precompiles = build_precompile_set();

    // core/executor/src/system_contract/gasless/contract/contracts/
    // SponsorWhitelistControl.sol gasless_create_code created from above
    // solidity
    let gasless_create_code = "0x608060405234801561001057600080fd5b50611093806100206000396000f3fe6080604052600436106100705760003560e01c8063b3b28fac1161004e578063b3b28fac146100f7578063b6b3527214610134578063d2932db614610171578063d665f9dd1461019a57610070565b806310128d3e1461007557806333a1af311461009e5780633e3e6428146100db575b600080fd5b34801561008157600080fd5b5061009c60048036038101906100979190610b74565b6101d7565b005b3480156100aa57600080fd5b506100c560048036038101906100c09190610bbd565b6102af565b6040516100d29190610bf9565b60405180910390f35b6100f560048036038101906100f09190610c4a565b61031d565b005b34801561010357600080fd5b5061011e60048036038101906101199190610bbd565b6105b6565b60405161012b9190610c99565b60405180910390f35b34801561014057600080fd5b5061015b60048036038101906101569190610cb4565b610604565b6040516101689190610d0f565b60405180910390f35b34801561017d57600080fd5b5061019860048036038101906101939190610b74565b61069a565b005b3480156101a657600080fd5b506101c160048036038101906101bc9190610bbd565b610769565b6040516101ce9190610c99565b60405180910390f35b600033905060005b82518110156102aa5760016000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160008584815181106102405761023f610d2a565b5b602002602001015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff021916908315150217905550806102a390610d88565b90506101df565b505050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b60003490506103e8821015610367576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161035e90610e53565b60405180910390fd5b818110156103aa576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103a190610ee5565b60405180910390fd5b60008060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160010154111561049b576103ff610972565b8181604001818152505033816000019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff1681525050828160200181815250506104956000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600001826107b7565b506105b1565b806000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160020181905550336000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600001600101819055505b505050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600001600201549050919050565b60008060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16905092915050565b600033905060005b8251811015610764576000808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600301600084838151811061070157610700610d2a565b5b602002602001015173ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81549060ff02191690558061075d90610d88565b90506106a2565b505050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600001600101549050919050565b806000015173ffffffffffffffffffffffffffffffffffffffff168260000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff160361085457806040015182600201600082825461082a9190610f05565b9250508190555080602001518260010154101561084f57806020015182600101819055505b61096e565b81600201548160400151101561089f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161089690610fab565b60405180910390fd5b81600101548260020154106108fa578160010154816020015110156108f9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108f09061103d565b60405180910390fd5b5b80604001518260020160008282546109129190610f05565b9250508190555080600001518260000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550806020015182600101819055505b5050565b6040518060600160405280600073ffffffffffffffffffffffffffffffffffffffff16815260200160008152602001600081525090565b6000604051905090565b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b610a0b826109c2565b810181811067ffffffffffffffff82111715610a2a57610a296109d3565b5b80604052505050565b6000610a3d6109a9565b9050610a498282610a02565b919050565b600067ffffffffffffffff821115610a6957610a686109d3565b5b602082029050602081019050919050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610aaa82610a7f565b9050919050565b610aba81610a9f565b8114610ac557600080fd5b50565b600081359050610ad781610ab1565b92915050565b6000610af0610aeb84610a4e565b610a33565b90508083825260208201905060208402830185811115610b1357610b12610a7a565b5b835b81811015610b3c5780610b288882610ac8565b845260208401935050602081019050610b15565b5050509392505050565b600082601f830112610b5b57610b5a6109bd565b5b8135610b6b848260208601610add565b91505092915050565b600060208284031215610b8a57610b896109b3565b5b600082013567ffffffffffffffff811115610ba857610ba76109b8565b5b610bb484828501610b46565b91505092915050565b600060208284031215610bd357610bd26109b3565b5b6000610be184828501610ac8565b91505092915050565b610bf381610a9f565b82525050565b6000602082019050610c0e6000830184610bea565b92915050565b6000819050919050565b610c2781610c14565b8114610c3257600080fd5b50565b600081359050610c4481610c1e565b92915050565b60008060408385031215610c6157610c606109b3565b5b6000610c6f85828601610ac8565b9250506020610c8085828601610c35565b9150509250929050565b610c9381610c14565b82525050565b6000602082019050610cae6000830184610c8a565b92915050565b60008060408385031215610ccb57610cca6109b3565b5b6000610cd985828601610ac8565b9250506020610cea85828601610ac8565b9150509250929050565b60008115159050919050565b610d0981610cf4565b82525050565b6000602082019050610d246000830184610d00565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000610d9382610c14565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610dc557610dc4610d59565b5b600182019050919050565b600082825260208201905092915050565b7f53706f6e736f7220757070657220626f756e64206c657373207468616e206d6960008201527f6e696d756d000000000000000000000000000000000000000000000000000000602082015250565b6000610e3d602583610dd0565b9150610e4882610de1565b604082019050919050565b60006020820190508181036000830152610e6c81610e30565b9050919050565b7f53706f6e736f722062616c616e6365206c657373207468616e2075707065722060008201527f626f756e64000000000000000000000000000000000000000000000000000000602082015250565b6000610ecf602583610dd0565b9150610eda82610e73565b604082019050919050565b60006020820190508181036000830152610efe81610ec2565b9050919050565b6000610f1082610c14565b9150610f1b83610c14565b9250828201905080821115610f3357610f32610d59565b5b92915050565b7f4e65772053706f6e736f722062616c616e6365206c657373207468616e206f6c60008201527f6400000000000000000000000000000000000000000000000000000000000000602082015250565b6000610f95602183610dd0565b9150610fa082610f39565b604082019050919050565b60006020820190508181036000830152610fc481610f88565b9050919050565b7f4e65772053706f6e736f722067617320626f756e64206c657373207468616e2060008201527f6f6c640000000000000000000000000000000000000000000000000000000000602082015250565b6000611027602383610dd0565b915061103282610fcb565b604082019050919050565b600060208201905081810360008301526110568161101a565b905091905056fea2646970667358221220278eaf5a7fafa126cca485e1e4b3327d733ea1e814b61c753d05a843a5ba88d664736f6c63430008110033";
    let mut tx = gen_tx(
        sender,
        H160::from_str("0x1000000000000000000000000000000000000000").unwrap(),
        0,
        hex_decode(gasless_create_code).unwrap(),
    );
    tx.transaction
        .unsigned
        .set_action(TransactionAction::Create);
    let r = executor.inner_exec(backend, &config, MAX_BLOCK_GAS_LIMIT, &precompiles, tx);
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    assert!(r.ret.is_empty());
    // assert_eq!(r.remain_gas, 29898759);

    // Thr created contract's address is
    // 0xc15d2ba57d126e6603240e89437efd419ce329d2, you can get the address by
    // `println!("{:?}", backend.state().keys());`
    println!("{:?}", backend.state().keys());
}

#[test]
fn test_gasless_set_sponsor_for_gas() {
    let sender = H160::from_str("0xf000000000000000000000000000000000000000").unwrap();
    let sponsor_contract_addr =
        H160::from_str("0xc15d2ba57d126e6603240e89437efd419ce329d2").unwrap();
    // let's call isWhitelisted(address contractAddr, address user) by exec
    let contract_addr = H160::from_str("0xff00000000000000000000000000000000000000").unwrap();
    let user = H160::from_str("0xff00000000000000000000000000000000000001").unwrap();

    let mut state = BTreeMap::new();
    state.insert(sender, MemoryAccount {
        nonce:   U256::one(),
        balance: U256::max_value(),
        storage: BTreeMap::new(),
        code:    Vec::new(),
    });
    let vicinity = gen_vicinity();
    let mut backend = MemoryBackend::new(&vicinity, state);

    deploy_sponsor_contract(&mut backend);

    let call_data = gasless::abi::sponsor_whitelist_control_abi::IsWhitelistedCall {
        contract_addr,
        user,
    };
    let call_data: Vec<u8> = AbiEncode::encode(call_data).into();

    let executor = AxonExecutor::default();
    let r = executor.call(
        &backend,
        u64::MAX,
        Some(sender),
        Some(sponsor_contract_addr),
        U256::default(),
        call_data,
    );
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    let is_sponsored: bool = AbiDecode::decode(r.ret).unwrap();
    assert_eq!(false, is_sponsored);

    // let's call setSponsorForGas(address contractAddr, uint upperBound) by exec
    let sponsor_upper_bound = U256::from(10000);
    let call_data = gasless::abi::sponsor_whitelist_control_abi::SetSponsorForGasCall {
        contract_addr,
        upper_bound: sponsor_upper_bound,
    };
    let call_data: Vec<u8> = AbiEncode::encode(call_data).into();
    let executor = AxonExecutor::default();
    let r = executor.call(
        &backend,
        u64::MAX,
        Some(sender),
        Some(sponsor_contract_addr),
        U256::from(100000),
        call_data.clone(),
    );
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Stopped));

    let (exit, values, logs) = executor.call2(
        &backend,
        u64::MAX,
        Some(sender),
        Some(sponsor_contract_addr),
        U256::from(100000),
        call_data,
    );
    if exit.is_succeed() {
        println!("setSponsorForGas success");
        backend.apply(values, logs, true);
    }

    // let's call getSponsoredGasFeeUpperBound(address contractAddr) by exec
    let call_data = gasless::abi::sponsor_whitelist_control_abi::GetSponsoredGasFeeUpperBoundCall {
        contract_addr,
    };
    let call_data: Vec<u8> = AbiEncode::encode(call_data).into();
    // let executor = AxonExecutor::default();
    let r = executor.call(
        &backend,
        u64::MAX,
        Some(contract_addr),
        Some(sponsor_contract_addr),
        U256::default(),
        call_data.clone(),
    );
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    let upper_bound: U256 = AbiDecode::decode(r.ret).unwrap();
    println!("upper_bound: {}", upper_bound);
    assert_eq!(upper_bound, sponsor_upper_bound);
}

#[test]
fn test_gasless_add_privilege() {
    let sender = H160::from_str("0xf000000000000000000000000000000000000000").unwrap();
    let sponsor_contract_addr =
        H160::from_str("0xc15d2ba57d126e6603240e89437efd419ce329d2").unwrap();
    let contract_addr = H160::from_str("0xff00000000000000000000000000000000000000").unwrap();
    let user = H160::from_str("0xff00000000000000000000000000000000000001").unwrap();

    let mut state = BTreeMap::new();
    state.insert(sender, MemoryAccount {
        nonce:   U256::one(),
        balance: U256::max_value(),
        storage: BTreeMap::new(),
        code:    Vec::new(),
    });
    let vicinity = gen_vicinity();
    let mut backend = MemoryBackend::new(&vicinity, state);

    deploy_sponsor_contract(&mut backend);

    // let's call addPrivilege(address[] memory users) by exec
    let call_data =
        gasless::abi::sponsor_whitelist_control_abi::AddPrivilegeCall { users: vec![user] };
    let call_data: Vec<u8> = AbiEncode::encode(call_data).into();
    let executor = AxonExecutor::default();
    let r = executor.call(
        &backend,
        u64::MAX,
        Some(contract_addr),
        Some(sponsor_contract_addr),
        U256::default(),
        call_data.clone(),
    );
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Stopped));

    // let (exit, values, logs) = executor.call2(
    //     &backend,
    //     u64::MAX,
    //     Some(sender),
    //     Some(sponsor_contract_addr),
    //     U256::from(100000),
    //     call_data,
    // );
    // // assert_eq!(exit, ExitReason::Succeed(ExitSucceed::Stopped));
    // if exit.is_succeed() {
    //     println!("addPrivilege");
    //     backend.apply(values, logs, true);
    // } else {
    //     println!("addPrivilege fail, exit: {:?}", exit);
    // }

    // let's call isWhitelisted(address contractAddr, address user) by exec
    let call_data = gasless::abi::sponsor_whitelist_control_abi::IsWhitelistedCall {
        contract_addr,
        user,
    };
    let call_data: Vec<u8> = AbiEncode::encode(call_data).into();

    // let executor = AxonExecutor::default();
    let r = executor.call(
        &backend,
        u64::MAX,
        Some(contract_addr),
        Some(sponsor_contract_addr),
        U256::default(),
        call_data,
    );
    assert_eq!(r.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
    let is_sponsored: bool = AbiDecode::decode(r.ret).unwrap();
    assert_eq!(false, is_sponsored);
}

// #[test]
// fn test_out_of_gas() {
//     let to_address =
// H160::from_str("0x1000000000000000000000000000000000000000").unwrap();
//     let from_address =
// H160::from_str("0xf000000000000000000000000000000000000000").unwrap();

//     let mut state = BTreeMap::new();
//     state.insert(
// 		to_address,
// 		MemoryAccount {
// 			nonce: U256::one(),
// 			balance: U256::max_value(),
// 			storage: BTreeMap::new(),
// 			code: hex_decode("60e060020a6000350480632839e92814601e57806361047ff414603457005b602a6004356024356047565b8060005260206000f35b603d6004356099565b8060005260206000f35b600082600014605457605e565b8160010190506093565b81600014606957607b565b60756001840360016047565b90506093565b609060018403608c85600186036047565b6047565b90505b92915050565b6000816000148060a95750816001145b60b05760b7565b81905060cf565b60c1600283036099565b60cb600184036099565b0190505b91905056").unwrap(),
// 		}
// 	);
//     state.insert(from_address, MemoryAccount {
//         nonce:   U256::one(),
//         balance: U256::max_value(),
//         storage: BTreeMap::new(),
//         code:    Vec::new(),
//     });

//     let vicinity = gen_vicinity();
//     let mut backend = MemoryBackend::new(&vicinity, state);
//     let executor = EvmExecutor::default();

//     let tx = SignedTransaction {
//         transaction: UnverifiedTransaction {
//             unsigned:  UnsignedTransaction::Eip1559(Eip1559Transaction {
//                 nonce:                    U256::default(),
//                 max_priority_fee_per_gas: U256::default(),
//                 gas_price:                U256::default(),
//                 gas_limit:                U256::from(10),
//                 action:
// TransactionAction::Call(to_address),                 value:
// U256::zero(),                 data:
// hex_decode("
// 2839e92800000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001"
// ).unwrap().into(),                 access_list:              Vec::new(),
//             }),
//             signature: Some(SignatureComponents {
//                 standard_v: 0,
//                 r:          Bytes::default(),
//                 s:          Bytes::default(),
//             }),
//             chain_id:  0u64,
//             hash:      H256::default(),
//         },
//         sender: from_address,
//         public: Some(Public::default()),
//     };

//     let config = Config::london();
//     let precompiles = build_precompile_set();
//     let r = executor.inner_exec(&mut backend, &config, 10, &precompiles, tx);

//     assert_eq!(r.exit_reason, ExitReason::Error(ExitError::OutOfGas));
//     assert_eq!(
//         backend.state().get(&from_address).unwrap().nonce,
//         U256::from(2)
//     );
// }

// #[test]
// fn test_out_of_balance() {
//     let to_address =
// H160::from_str("0x1000000000000000000000000000000000000000").unwrap();
//     let from_address =
// H160::from_str("0xf000000000000000000000000000000000000000").unwrap();

//     let mut state = BTreeMap::new();
//     state.insert(to_address, MemoryAccount {
//         nonce:   U256::one(),
//         balance: U256::zero(),
//         storage: BTreeMap::new(),
//         code:    vec![],
//     });
//     state.insert(from_address, MemoryAccount {
//         nonce:   U256::one(),
//         balance: U256::one(),
//         storage: BTreeMap::new(),
//         code:    Vec::new(),
//     });

//     let vicinity = gen_vicinity();
//     let mut backend = MemoryBackend::new(&vicinity, state);
//     let executor = EvmExecutor::default();
//     let tx = gen_tx(from_address, to_address, 10, vec![]);
//     let config = Config::london();
//     let precompiles = build_precompile_set();
//     let r = executor.inner_exec(&mut backend, &config, u64::MAX,
// &precompiles, tx);     assert_eq!(r.exit_reason,
// ExitReason::Error(ExitError::OutOfFund));     assert_eq!(
//         backend.state().get(&from_address).unwrap().nonce,
//         U256::from(2)
//     );
// }
