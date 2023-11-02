use tiny_keccak::{Hasher, Keccak};

#[cfg(feature = "hash")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hash")))]
pub fn keccak_256(data: &[u8]) -> [u8; 32] {
    let mut ret = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut ret);
    ret
}
