use std::fmt::Display;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[rustfmt::skip]
#[derive(
    Clone, Copy, Zeroize, Default,
    Deserialize, Serialize,
    PartialEq, Eq, Hash,
    PartialOrd, Ord,
    Debug,
)]
/// ID of vss shard
pub struct ShardId(u32);

impl ShardId {
    /// High 16 bits
    #[inline]
    pub fn group_id(&self) -> u16 {
        (self.0 >> 16).try_into().unwrap()
    }

    /// Low 16 bits
    pub fn member_id(&self) -> u16 {
        (self.0 & 0xFFFF).try_into().unwrap()
    }

    /// Create a new MpcPeerId from group and member id
    pub fn new(group_id: u16, member_id: u16) -> Self {
        let val = (u32::from(group_id) << 16) | u32::from(member_id);
        ShardId(val)
    }

    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn bcast_id() -> Self {
        ShardId(0) // group 0, member 0
    }

    pub fn gcast_id(group_id: u16) -> Self {
        Self::new(group_id, 0)
    }

    pub fn as_primitive(&self) -> u32 {
        self.0
    }
}

impl From<u32> for ShardId {
    fn from(x: u32) -> Self {
        ShardId(x)
    }
}
impl From<ShardId> for u32 {
    fn from(x: ShardId) -> Self {
        x.0
    }
}

impl Display for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.group_id(), self.member_id())
    }
}
