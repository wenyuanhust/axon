mod image_cell;
mod native_token;
mod sponsor_gas;

pub use crate::system_contract::native_token::NativeTokenContract;

use protocol::traits::{ApplyBackend, Backend};
use protocol::types::{SignedTransaction, TxResp, H160};

pub const fn system_contract_address(addr: u8) -> H160 {
    H160([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, addr,
    ])
}

pub trait SystemContract {
    const ADDRESS: H160;

    fn exec_<B: Backend + ApplyBackend>(&self, backend: &mut B, tx: &SignedTransaction) -> TxResp;
}

pub fn system_contract_dispatch<B: Backend + ApplyBackend>(
    backend: &mut B,
    tx: &SignedTransaction,
) -> Option<TxResp> {
    let native_token_address = NativeTokenContract::ADDRESS;
    let gasless_address = sponsor_gas::abi::ADDRESS;
    if let Some(addr) = tx.get_to() {
        if addr == native_token_address {
            return Some(NativeTokenContract::default().exec_(backend, tx));
        } else if addr == gasless_address {
            return Some(sponsor_gas::abi::GaslessContract::new().exec_(backend, tx));
        }
    }

    None
}
