use std::collections::HashMap;
use std::ops::{Add, Mul};

use serde::{Deserialize, Serialize};

use crate::ShardId;

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Shard<ScalarType, PointType>
where
    ScalarType: Clone
        + Default // Zero
        + Add<Output = ScalarType>
        + Mul<Output = ScalarType>
        + Mul<PointType, Output = PointType>,
    PointType: Clone
        + Default // Identity
        + std::ops::Add<Output = PointType>
        + std::ops::Mul<ScalarType, Output = PointType>,
{
    /// Party key
    pub u_i: ScalarType,
    /// signing key
    pub x_i: ScalarType,
    /// Commitment to the polynomial coefficients for each `member_id` within the same `group_id`.
    pub vss_com_dict: HashMap<ShardId, Vec<PointType>>,
    /// `(group_id, member_id)` of current shard.
    pub id: ShardId,
    /// Minimum numof shards required for signing/recovery.
    pub th: u16,
    /// Auxiliary data for the shard.
    pub aux: Option<Vec<u8>>,
}

impl<ScalarType, PointType> Shard<ScalarType, PointType>
where
    ScalarType: Clone
        + Default // Zero
        + Add<Output = ScalarType>
        + Mul<Output = ScalarType>
        + Mul<PointType, Output = PointType>,
    PointType: Clone
        + Default // Identity
        + std::ops::Add<PointType, Output = PointType>
        + std::ops::Mul<ScalarType, Output = PointType>,
{
    pub fn pk(&self) -> PointType {
        let mut res = PointType::default();
        for vss_com in self.vss_com_dict.values() {
            res = res + vss_com[0].clone();
        }
        res
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MultiShard<ScalarType, PointType>
where
    ScalarType: Clone
        + Default // Zero
        + Add<Output = ScalarType>
        + Mul<Output = ScalarType>
        + Mul<PointType, Output = PointType>,
    PointType: Clone
        + Default // Identity
        + std::ops::Add<Output = PointType>
        + std::ops::Mul<ScalarType, Output = PointType>,
{
    pub shards: HashMap<ShardId, Shard<ScalarType, PointType>>,
    pub aux: Option<Vec<u8>>,
}

impl<ScalarType, PointType> MultiShard<ScalarType, PointType>
where
    ScalarType: Clone
        + Default // Zero
        + Add<Output = ScalarType>
        + Mul<Output = ScalarType>
        + Mul<PointType, Output = PointType>,
    PointType: Clone
        + Default // Identity
        + std::ops::Add<PointType, Output = PointType>
        + std::ops::Mul<ScalarType, Output = PointType>,
{
    pub fn pk(&self) -> PointType {
        let mut res = PointType::default();
        for shard in self.shards.values() {
            res = res + shard.pk();
        }
        res
    }
}
