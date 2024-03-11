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
pub struct MpcAddr(u32);

impl MpcAddr {
    /// High 16 bits
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
        MpcAddr(val)
    }

    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn bcast_id() -> Self {
        MpcAddr(0) // group 0, member 0
    }

    pub fn gcast_id(group_id: u16) -> Self {
        Self::new(group_id, 0)
    }

    pub fn as_primitive(&self) -> u32 {
        self.0
    }

    pub fn from_text(s: impl AsRef<str>) -> Result<Self, &'static str> {
        let s = s.as_ref();
        let items = s.split('.').collect::<Vec<_>>();
        if items.len() != 2 {
            return Err("ShardID is not '%d.%d' format");
        }
        let gid: u16 = items[0].parse().map_err(|_| "Invalid group id")?;
        let mid: u16 = items[1].parse().map_err(|_| "Invalid member id")?;
        Ok(MpcAddr::new(gid, mid))
    }
}

impl From<u32> for MpcAddr {
    fn from(x: u32) -> Self {
        MpcAddr(x)
    }
}
impl From<MpcAddr> for u32 {
    fn from(x: MpcAddr) -> Self {
        x.0
    }
}

impl Display for MpcAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.group_id(), self.member_id())
    }
}
