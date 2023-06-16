use crate::air::Air;
use crate::utils::HybridCell;
use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::AssignedValue;
use halo2_base::Context;
use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::plonk::Error;
use ministark::constraintv2::AlgebraicItem;
use num_traits::Pow;
use std::cell::RefCell;
use std::collections::BTreeMap;

// TODO: error handling
// STARK out of domain (OOD) constraint evaluation
pub fn ood_constraint_eval<F: FieldExt>(
    ctx: &mut Context<'_, F>,
    chip: &FlexGateConfig<F>,
    composition_coefficients: &[(AssignedValue<F>, AssignedValue<F>)],
    challenges: &[AssignedValue<F>],
    hints: &[AssignedValue<F>],
    execution_trace_ood_evals: Vec<AssignedValue<F>>,
    air: impl Air<F = F>,
    x: AssignedValue<F>,
) -> Result<AssignedValue<F>, Error> {
    let ctx = RefCell::new(ctx);
    let x = HybridCell::from_val(chip, &ctx, x.clone());
    let trace_degree = air.trace_len() - 1;
    let composition_degree = air.composition_degree();
    let trace_ood_eval_map = air
        .trace_arguments()
        .into_iter()
        .zip(execution_trace_ood_evals)
        .collect::<BTreeMap<(usize, isize), AssignedValue<F>>>();

    // TODO: Improve performance. Combine constraints into one and call
    // `constraint.reuse_shared_nodes();`. Currently need to use traverse_mut
    let mut partial_results = Vec::new();
    for (i, constraint) in air.constraints().into_iter().enumerate() {
        let (numerator, denominator) = constraint.degree(trace_degree);
        let evaluation_degree = numerator - denominator;
        assert!(evaluation_degree <= composition_degree);
        let degree_adjustment = composition_degree - evaluation_degree;

        // evaluate the constraint and lay corresponding circuitry
        use AlgebraicItem::*;
        let res = constraint.eval(
            // map the constraint symbols to their corresponding assigned values
            &mut |leaf| match leaf {
                Constant(a) => HybridCell::from_constant(chip, &ctx, *a),
                Challenge(i) => HybridCell::from_ref(chip, &ctx, &challenges[*i]),
                Hint(i) => HybridCell::from_ref(chip, &ctx, &hints[*i]),
                &Trace(i, j) => HybridCell::from_ref(chip, &ctx, &trace_ood_eval_map[&(i, j)]),
                X => x.clone(),
            },
        );

        let alpha = HybridCell::from_ref(chip, &ctx, &composition_coefficients[i].0);
        let beta = HybridCell::from_ref(chip, &ctx, &composition_coefficients[i].1);
        partial_results.push(res * (alpha * x.clone().pow(degree_adjustment) + beta));
    }

    // sum all partial results together
    let mut partial_results = partial_results.into_iter();
    let expr = partial_results.next().unwrap();
    Ok(partial_results.fold(expr, |a, b| a + b).value().unwrap())
}
