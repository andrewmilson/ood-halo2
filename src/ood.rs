use crate::{air::Air, constraints::AlgebraicExpression};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context, QuantumCell,
};
use halo2_proofs::{halo2curves::FieldExt, plonk::Error};
use std::{collections::BTreeMap, marker::PhantomData, ops::Deref};


pub fn ood_constraint_eval<F: FieldExt>(
    ctx: &mut Context<'_, F>,
    main_chip: &FlexGateConfig<F>,
    composition_coefficients: &[(AssignedValue<F>, AssignedValue<F>)],
    challenges: &[AssignedValue<F>],
    hints: &[AssignedValue<F>],
    execution_trace_ood_evals: Vec<AssignedValue<F>>,
    air: impl Air<F = F>,
    x: AssignedValue<F>,
) -> Result<AssignedValue<F>, Error> {
    let trace_degree = air.trace_len() - 1;
    let composition_degree = air.composition_degree();
    let trace_ood_eval_map = air
        .trace_arguments()
        .into_iter()
        .zip(execution_trace_ood_evals)
        .collect::<BTreeMap<(usize, isize), AssignedValue<F>>>();

    let mut partial_results = Vec::new();
    for (i, constraint) in air.constraints().iter().enumerate() {
        let (numerator_degree, denominator_degree) = constraint.degree(trace_degree);
        let evaluation_degree = numerator_degree - denominator_degree;
        assert!(evaluation_degree <= composition_degree);
        let degree_adjustment = composition_degree - evaluation_degree;

        use AlgebraicExpression::*;
        let AssignedValue(eval_result) = constraint.map(&mut |node| match node {
            X => AssignedValue(x.clone()),
            Constant(c) => todo!(),
            Challenge(i) => AssignedValue(challenges[i].clone()),
            Hint(i) => AssignedValue(hints[i].clone()),
            Trace(i, j) => AssignedValue(trace_ood_eval_map.get(&(i, j)).unwrap().clone()),
            AssignedValue(v) => AssignedValue(v),
            // TODO: can use reuse_shared_nodes optimization
            Add(a, b) => {
                let a = a.borrow();
                let b = b.borrow();

                let (a, b) = match (a.deref(), b.deref()) {
                    (Constant(c), AssignedValue(av)) | (AssignedValue(av), Constant(c)) => {
                        (QuantumCell::Constant(*c), QuantumCell::Existing(av))
                    },
                    (AssignedValue(a), AssignedValue(b)) => {
                        (QuantumCell::Existing(a), QuantumCell::Existing(b))
                    },
                    (Constant(a), Constant(b)) => {
                        (QuantumCell::Constant(*a), QuantumCell::Constant(*b))
                    },
                    _ => panic!()
                };

                match (a, b) {
                    (QuantumCell::Constant(a), QuantumCell::Constant(b)) => {
                        Constant(a + b)
                    },
                    (a, b) => {
                        // TODO: figure out error handling here
                        AssignedValue(main_chip.add(ctx, &a, &b).unwrap())
                    }
                }
            },
            Neg(v) => {
                let v = v.borrow();
                match v.deref() {
                    // TODO: error handing
                    AssignedValue(v) => AssignedValue(main_chip.neg(ctx, &QuantumCell::Existing(v)).unwrap()),
                    Constant(c) => Constant(-*c),
                    _ => panic!()
                }
            },
            Mul(a, b) => {
                let a = a.borrow();
                let b = b.borrow();
                
                let (a, b) = match (a.deref(), b.deref()) {
                    (Constant(c), AssignedValue(av)) | (AssignedValue(av), Constant(c)) => {
                        (QuantumCell::Constant(*c), QuantumCell::Existing(av))
                    },
                    (AssignedValue(a), AssignedValue(b)) => {
                        (QuantumCell::Existing(a), QuantumCell::Existing(b))
                    },
                    (Constant(a), Constant(b)) => {
                        (QuantumCell::Constant(*a), QuantumCell::Constant(*b))
                    },
                    _ => panic!()
                };

                match (a, b) {
                    (QuantumCell::Constant(a), QuantumCell::Constant(b)) => {
                        Constant(a * b)
                    },
                    (a, b) => {
                        // TODO: figure out error handling here
                        AssignedValue(main_chip.mul(ctx, &a, &b).unwrap())
                    }
                }
            },
            Exp(v, e) => {
                let v = v.borrow();
                match v.deref() {
                    Constant(c) => Constant(c.pow(&[0, 0, 0, e as u64])),
                    // TODO: error handing
                    AssignedValue(v) => {
                        let mut res = main_chip.pow(ctx, &QuantumCell::Existing(v), e.unsigned_abs()).unwrap();

                        if e < 0 {
                            res = main_chip.invert(ctx, &QuantumCell::Existing(&res)).unwrap();
                        }

                        AssignedValue(res)
                    },
                    _ => panic!()
                }
            },
        }) else {
            panic!()
        };

        let x = QuantumCell::Existing(&x);
        let eval_result = QuantumCell::Existing(&eval_result);
        let alpha = QuantumCell::Existing(&composition_coefficients[i].0);
        let beta = QuantumCell::Existing(&composition_coefficients[i].1);

        // calculate `eval_result * (alpha * x^degree_adjustment + beta)`
        let adjusted_x = main_chip.pow(ctx, &x, degree_adjustment)?;
        let scaled_x = main_chip.mul(ctx, &alpha, &QuantumCell::Existing(&adjusted_x))?;
        let coeff = main_chip.add(ctx, &QuantumCell::Existing(&scaled_x), &beta)?;
        let result = main_chip.mul(ctx, &eval_result, &QuantumCell::Existing(&coeff))?;

        partial_results.push(result);
    }

    // sum all partial results together
    let mut partial_results = partial_results.into_iter();
    let expr = partial_results.next().unwrap();
    let result = partial_results.fold(expr, |a, b| {
        let a = QuantumCell::Existing(&a);
        let b = QuantumCell::Existing(&b);
        main_chip.add(ctx, &a, &b).unwrap()
    });

    Ok(result)
}