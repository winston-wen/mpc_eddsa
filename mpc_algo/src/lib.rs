#![deny(unused_must_use)]
#![allow(non_snake_case, non_upper_case_globals)]

pub use biz_algo::*;
use mpc_sesman::exception; // to properly compile `assert_throw!()` and `throw!()`

mod prelude {
    // to enable `.catch()?` and `.ifnone()?`
    pub use mpc_sesman::exception::{Outcome, TraitStdOptionToOutcome, TraitStdResultToOutcome};
    pub use mpc_sesman::{assert_throw, throw};
}
mod aes;
mod biz_algo;
mod party_i;
