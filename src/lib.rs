#![feature(let_chains)]

use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::gates::range::RangeConfig;
use halo2_base::AssignedValue;
use halo2_proofs::circuit::Chip;
use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::Instance;

mod air;
// mod constraints;
mod ood;
mod utils;

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
    use crate::air::Air;
    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use halo2_proofs::halo2curves::pasta::Fp;
    use ministark::constraintv2::AlgebraicItem;
    use ministark::constraintv2::Constraint;
    use num_traits::Pow;

    struct FibAir {}

    impl Air for FibAir {
        type F = Fp;

        fn constraints(&self) -> Vec<Constraint<Fp>> {
            use AlgebraicItem::*;

            let n = self.trace_len();
            let one = Constant(Fp::from(1));
            let claimed_nth_fib_num = Hint(0);

            // Domain we use to interpolate execution trace
            let exp = (<Fp as PrimeField>::S - n.ilog2()) as u64;
            let x_generator = Fp::root_of_unity().pow(&[0, 0, 0, exp]);
            let first_trace_x = Constant(x_generator.pow(&[0, 0, 0, 0]));
            let second_trace_x = Constant(x_generator.pow(&[0, 0, 0, 1]));
            let last_trace_x = Constant(x_generator.pow(&[0, 0, 0, n as u64]));

            // NOTE: x^n - 1 = (x - ⍵_n^0)(x - ⍵_n^1)(x - ⍵_n^2)...(x - ⍵_n^(n-1))
            let vanish_all_rows = X.pow(n) - &one;
            let vanish_first_row = X - first_trace_x;
            let vanish_second_row = X - second_trace_x;
            let vanish_last_row = X - last_trace_x;

            vec![
                // 1. first row must equal 1
                (Trace(0, 0) - &one) / &vanish_first_row,
                // 2. second row must equal 1
                (Trace(0, 0) - &one) / &vanish_second_row,
                // 3. remainig rows must equal the sum of their two preceding rows
                (Trace(0, 0) - Trace(0, -1) - Trace(0, -2))
                    * &vanish_first_row
                    * &vanish_second_row
                    / vanish_all_rows,
                // 4. last row must equal the the prover's claimed `n`th fibonacci number
                (Trace(0, 0) - claimed_nth_fib_num) / vanish_last_row,
            ]
            .into_iter()
            .map(Constraint::new)
            .collect()
        }

        fn trace_len(&self) -> usize {
            todo!()
        }
    }

    #[test]
    fn it_works() {
        let n = 2usize.pow(16);
        let fib_air = FibAir {};
    }
}
