use halo2_proofs::halo2curves::FieldExt;
use ministark::constraintv2::Constraint;
use std::collections::BTreeSet;

pub trait Air {
    type F: FieldExt;

    fn constraints(&self) -> Vec<Constraint<Self::F>>;

    fn trace_len(&self) -> usize;

    fn composition_degree(&self) -> usize {
        let trace_len = self.trace_len();
        let ce_domain_size = trace_len * self.ce_blowup_factor();
        ce_domain_size - 1
    }

    /// Constraint evaluation blowup factor
    /// Must be a power of two.
    fn ce_blowup_factor(&self) -> usize {
        let trace_degree = self.trace_len() - 1;
        let ret = self
            .constraints()
            .iter()
            .map(|constraint| {
                let (numerator_degree, denominator_degree) = constraint.degree(trace_degree);
                numerator_degree - denominator_degree
            })
            .max()
            // TODO: ceil_power_of_two might not be correct here. check the math
            .map_or(0, |degree| degree.next_power_of_two() / trace_degree)
            .next_power_of_two();
        ret
    }

    fn trace_arguments(&self) -> BTreeSet<(usize, isize)> {
        self.constraints()
            .iter()
            .map(Constraint::trace_arguments)
            .fold(BTreeSet::new(), |a, b| &a | &b)
    }
}
