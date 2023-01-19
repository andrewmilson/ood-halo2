#![feature(let_chains)]

use std::marker::PhantomData;

use constraints::AlgebraicExpression;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig},
    AssignedValue,
};
use halo2_proofs::{circuit::Chip, halo2curves::FieldExt, plonk::Column, plonk::Instance};

#[macro_use]
mod macros;
mod air;
mod constraints;
mod ood;

pub struct Proof<F: FieldExt> {
    execution_trace_ood_evals: Vec<AssignedValue<F>>,
}

#[derive(Clone, Debug)]
pub struct ProofConfig<F: FieldExt> {
    instance: Column<Instance>,
    main_chip: FlexGateConfig<F>,
    range_chip: RangeConfig<F>,
}

pub struct VerifyStarkChip {/* TODO */}

impl<F: FieldExt> Chip<F> for VerifyStarkChip {
    type Config = ProofConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        todo!()
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
