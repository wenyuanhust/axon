pub mod sponsor_whitelist_control_abi;

use crate::system_contract::system_contract_address;
use protocol::types::H160;
pub const GASLESS_ADDRESS: H160 = system_contract_address(0x1);
