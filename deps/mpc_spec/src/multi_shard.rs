use std::{
    collections::{HashMap, HashSet},
    ops::{Add, Mul},
};

use libexception::*;
use serde::{Deserialize, Serialize};

use crate::MpcAddr;

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
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
    pub ui_pergroup: HashMap<u16, ScalarType>,
    pub xi_pergroup: HashMap<u16, ScalarType>,
    pub vss_com_grid: HashMap<u16, HashMap<MpcAddr, Vec<PointType>>>, // (group, member(poly), coef)

    pub ids: HashSet<MpcAddr>,
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
    pub fn th(&self, gid: u16) -> Outcome<usize> {
        let vss_com_dict = self
            .vss_com_grid
            .get(&gid)
            .ifnone("NoSuchGroup", gid.to_string())?;

        let vss_com = vss_com_dict
            .values()
            .next()
            .ifnone("EmptyVssCom", format!("at group {}", gid.to_string()))?;

        Ok(vss_com.len())
    }

    pub fn pk(&self) -> Result<PointType, &'static str> {
        let mut res = PointType::default();
        for vss_com_dict in self.vss_com_grid.values() {
            for vss_com in vss_com_dict.values() {
                res = res + vss_com[0].clone();
            }
        }
        Ok(res)
    }
}
