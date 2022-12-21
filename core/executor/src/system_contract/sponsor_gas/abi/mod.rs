use std::{collections::HashMap, borrow::BorrowMut, cell::RefCell};

use protocol::types::{
    ApplyBackend, Backend, ExitReason, ExitRevert, ExitSucceed, SignedTransaction, TxResp, H160,
    U256, Apply, Basic, H256,
};

use crate::system_contract::{system_contract_address, SystemContract};
use ethers::abi::AbiDecode;
pub mod sponsor_whitelist_control_abi;

#[derive(Debug)]
pub struct SponsorInfo {
    /// This is the address of the sponsor for gas cost of the contract.
    pub sponsor_for_gas:         H160,
    /// This is the upper bound of sponsor gas cost per tx.
    pub sponsor_gas_bound:       U256,
    /// This is the amount of tokens sponsor for gas cost to the contract.
    pub sponsor_balance_for_gas: U256,
}

pub struct GaslessContract {
    // HashMap key is the address of the contract to be sponsored
    pub sponsor_infos: RefCell<HashMap<H160, SponsorInfo>>,
}

impl GaslessContract {
    pub fn new() -> Self {
        GaslessContract {
            sponsor_infos: RefCell::new(HashMap::new()),
        }
    }
}

pub fn set_sponsor_for_gas(
    sponsor_infos: & mut HashMap<H160, SponsorInfo>,
    sponsor: H160,
    balance: &U256,
    data: sponsor_whitelist_control_abi::SetSponsorForGasCall,
) -> Result<(), String> {
    let sponsor_info = SponsorInfo{
        sponsor_for_gas: sponsor,
        sponsor_gas_bound: data.upper_bound,
        sponsor_balance_for_gas: *balance,
    };
    sponsor_infos.insert(data.contract_addr, sponsor_info);
    Ok(())
}

impl SystemContract for GaslessContract {
    const ADDRESS: H160 = system_contract_address(0x2);

    fn exec_<B: Backend + ApplyBackend>(&self, backend: &mut B, tx: &SignedTransaction) -> TxResp {
        let sender = tx.sender;
        let tx = &tx.transaction.unsigned;
        let tx_data = tx.data();

        match sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::decode(tx_data) {
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::AddPrivilege(_)) => {
                // todo
            }
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::GetSponsorForGas(_)) => {
                // todo
            }
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::GetSponsoredBalanceForGas(_)) => {
                // todo
            }
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::GetSponsoredGasFeeUpperBound(_)) => {
                // todo
            }
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::IsAllWhitelisted(_)) => {
                // todo
            }
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::IsWhitelisted(_)) => {
                // todo
            }
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::RemovePrivilege(_)) => {
                // todo
            }
            Ok(sponsor_whitelist_control_abi::SponsorWhitelistControlCalls::SetSponsorForGas(data)) => {
                // todo
                let mut sponsor_infos = self.sponsor_infos.borrow_mut();
                set_sponsor_for_gas(&mut sponsor_infos , sender, tx.value(), data);
            }
            Err(_) => {
                return revert_resp(*tx.gas_limit());
            }
        }

        TxResp {
            exit_reason:  ExitReason::Succeed(ExitSucceed::Returned),
            ret:          vec![],
            gas_used:     0u64,
            remain_gas:   tx.gas_limit().as_u64(),
            fee_cost:     U256::zero(),
            logs:         vec![],
            code_address: None,
            removed:      false,
        }
    }
}

impl GaslessContract {
    fn update_sponsor_infos<B: Backend + ApplyBackend>(
        &self,
        backend: &mut B,
        sponsor_infos: HashMap<H160, SponsorInfo>
    ) -> Result<(), String> {
        let account = backend.basic(GaslessContract::ADDRESS);

        backend.apply(
            vec![Apply::Modify {
                address:       GaslessContract::ADDRESS,
                basic:         Basic {
                    balance: account.balance,
                    nonce:   account.nonce + U256::one(),
                },
                code:          None,
                storage:       vec![(H256::default(), H256::default())],
                reset_storage: false,
            }],
            vec![],
            false,
        );
        Ok(())
    }

}

fn revert_resp(gas_limit: U256) -> TxResp {
    TxResp {
        exit_reason:  ExitReason::Revert(ExitRevert::Reverted),
        ret:          vec![],
        gas_used:     1u64,
        remain_gas:   (gas_limit - 1).as_u64(),
        fee_cost:     U256::one(),
        logs:         vec![],
        code_address: None,
        removed:      false,
    }
}
