use core::cmp::Ordering;
use alloc::vec::Vec;
use bytes::Bytes;
pub use ethereum_types::{Bloom, H160, H256, H64, U256};
// #[cfg(feature = "impl-rlp")]
// use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

pub const MAX_BLOCK_GAS_LIMIT: u64 = 30_000_000;
pub const MAX_RPC_GAS_CAP: u64 = 50_000_000;
pub const BASE_FEE_PER_GAS: u64 = 0x539;

pub type Hash = H256;
pub type MerkleRoot = Hash;
pub type BlockNumber = u64;

#[derive(Debug)]
pub enum TypesError {
    InvalidBlockVersion(u8),
}

// impl std::error::Error for TypesError {}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Deserialize))]
pub enum BlockVersion {
    #[default]
    V0,
}

impl From<BlockVersion> for u8 {
    fn from(value: BlockVersion) -> Self {
        match value {
            BlockVersion::V0 => 0,
        }
    }
}

impl TryFrom<u8> for BlockVersion {
    type Error = TypesError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BlockVersion::V0),
            _ => Err(TypesError::InvalidBlockVersion(value)),
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "impl-rlp",
    derive(rlp_derive::RlpEncodable, rlp_derive::RlpDecodable)
)]
#[cfg_attr(feature = "impl-serde", derive(serde::Deserialize))]
pub struct ExtraData {
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "withpfx_lowercase::deserialize")
    )]
    pub inner: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "impl-rlp",
    derive(rlp_derive::RlpEncodable, rlp_derive::RlpDecodable)
)]
#[cfg_attr(feature = "impl-serde", derive(serde::Deserialize))]
pub struct AxonHeader {
    pub version:                  BlockVersion,
    pub prev_hash:                Hash,
    pub proposer:                 H160,
    pub state_root:               MerkleRoot,
    pub transactions_root:        MerkleRoot,
    pub signed_txs_hash:          Hash,
    pub receipts_root:            MerkleRoot,
    pub log_bloom:                Bloom,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub timestamp:                u64,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub number:                   BlockNumber,
    pub gas_used:                 U256,
    pub gas_limit:                U256,
    /// Extra data for the block header
    /// The first index of extra_data is used to store hardfork information:
    /// `HardforkInfoInner`
    pub extra_data:               Vec<ExtraData>,
    pub base_fee_per_gas:         U256,
    pub proof:                    Proof,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u32")
    )]
    pub call_system_script_count: u32,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub chain_id:                 u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "impl-rlp",
    derive(rlp_derive::RlpEncodable, rlp_derive::RlpDecodable)
)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AxonBlock {
    pub header:    AxonHeader,
    pub tx_hashes: Vec<H256>,
}

#[cfg(feature = "proof")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(doc_cfg, doc(cfg(feature = "proof")))]
#[cfg_attr(feature = "impl-serde", derive(serde::Deserialize))]
pub struct Proposal {
    pub version:                  BlockVersion,
    pub prev_hash:                Hash,
    pub proposer:                 H160,
    pub prev_state_root:          MerkleRoot,
    pub transactions_root:        MerkleRoot,
    pub signed_txs_hash:          Hash,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub timestamp:                u64,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub number:                   BlockNumber,
    pub gas_limit:                U256,
    pub extra_data:               Vec<ExtraData>,
    pub base_fee_per_gas:         U256,
    pub proof:                    Proof,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub chain_id:                 u64,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u32")
    )]
    pub call_system_script_count: u32,
    pub tx_hashes:                Vec<Hash>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "impl-rlp",
    derive(rlp_derive::RlpEncodable, rlp_derive::RlpDecodable)
)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Proof {
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub number:     u64,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u64")
    )]
    pub round:      u64,
    pub block_hash: Hash,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "withpfx_lowercase::deserialize")
    )]
    pub signature:  Bytes,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "withpfx_lowercase::deserialize")
    )]
    pub bitmap:     Bytes,
}

#[cfg(feature = "proof")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(doc_cfg, doc(cfg(feature = "proof")))]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Validator {
    pub bls_pub_key:    Bytes,
    pub address:        H160,
    pub propose_weight: u32,
    pub vote_weight:    u32,
}

#[cfg(feature = "proof")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "proof")))]
impl core::cmp::PartialOrd for Validator {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "proof")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "proof")))]
impl core::cmp::Ord for Validator {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

#[cfg(feature = "proof")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(doc_cfg, doc(cfg(feature = "proof")))]
#[cfg_attr(
    feature = "impl-rlp",
    derive(rlp_derive::RlpEncodable, rlp_derive::RlpDecodable)
)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Vote {
    pub height:     u64,
    pub round:      u64,
    pub vote_type:  u8,
    pub block_hash: Bytes,
}

#[cfg(test)]
impl Vote {
    fn random() -> Self {
        Self {
            height:     rand::random(),
            round:      rand::random(),
            vote_type:  2,
            block_hash: tests::random_bytes(32),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Metadata {
    pub version:         MetadataVersion,
    pub epoch:           u64,
    pub gas_limit:       u64,
    pub gas_price:       u64,
    pub interval:        u64,
    pub verifier_list:   Vec<ValidatorExtend>,
    pub propose_ratio:   u64,
    pub prevote_ratio:   u64,
    pub precommit_ratio: u64,
    pub brake_ratio:     u64,
    pub tx_num_limit:    u64,
    pub max_tx_size:     u64,
    #[cfg_attr(feature = "impl-serde", serde(skip_deserializing))]
    pub propose_counter: Vec<ProposeCount>,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MetadataVersion {
    pub start: u64,
    pub end:   u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProposeCount {
    pub address: H160,
    pub count:   u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
// #[cfg(feature = "impl-rlp")]
// #[derive(RlpEncodable, RlpDecodable)]
pub struct Hex(Bytes);

// #[cfg(feature = "impl-rlp")]
impl Hex {
    pub fn as_bytes(&self) -> Bytes {
        self.0.clone()
    }
}

impl From<Vec<u8>> for Hex {
    fn from(bytes: Vec<u8>) -> Self {
        let bytes = Bytes::from(bytes);
        Hex(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidatorExtend {
    pub bls_pub_key:    Hex,
    pub pub_key:        Hex,
    pub address:        H160,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u32")
    )]
    pub propose_weight: u32,
    #[cfg_attr(
        feature = "impl-serde",
        serde(deserialize_with = "decode::deserialize_hex_u32")
    )]
    pub vote_weight:    u32,
}

impl PartialOrd for ValidatorExtend {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for ValidatorExtend {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NodePubKey {
    pub bls_pub_key: Bytes,
    pub pub_key:     Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "impl-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CkbRelatedInfo {
    pub metadata_type_id:     H256,
    pub checkpoint_type_id:   H256,
    pub xudt_args:            H256,
    pub stake_smt_type_id:    H256,
    pub delegate_smt_type_id: H256,
    pub reward_smt_type_id:   H256,
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn random_bytes(len: usize) -> Bytes {
        (0..len).map(|_| rand::random()).collect::<Vec<u8>>().into()
    }

    #[test]
    fn test_vote_codec() {
        let vote = Vote::random();
        let raw = rlp::encode(&vote);
        let decoded: overlord::types::Vote = rlp::decode(&raw).unwrap();
        assert_eq!(vote.height, decoded.height);
        assert_eq!(vote.round, decoded.round);
        assert_eq!(vote.block_hash, decoded.block_hash);
    }
}
